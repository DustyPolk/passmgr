//! `grant`: create, inspect and revoke agent grants.
//!
//! `create` is deliberately a *client* of `pmd`: it derives the vault key
//! once, proves that key's presence for the exact request, lets the daemon
//! accept the grant, and only then writes it to the vault with the same key.
//! The daemon never sees the vault or the raw token, and the raw token is
//! written once to a new 0600 file rather than to stdout.
//!
//! `list` and `show` read the vault locally after the master password, like
//! the other read commands, and print metadata only: ids, labels, scope,
//! allowlisted commands, use counts and timestamps. A grant's token hash and
//! its raw token have no accessor on this path, so neither can be printed by
//! accident. `revoke` is the opposite: it needs no password and no terminal,
//! because taking access away is always allowed, and it asks the daemon (the
//! only process that can write without a prompt) to set `revoked_at` and
//! re-encrypt the vault with the key it already holds.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use passmgr::Error;
use passmgr::agent;
use passmgr::crypto;
use passmgr::grant::{
    Capabilities, Grant, GrantRequest, GrantSpec, GrantToken, MAX_GRANT_LIFETIME_SECS, Scope,
    escape_hidden, is_program_runner,
};
use passmgr::protocol::{
    GrantCreateRequest, GrantRevokeRequest, ProveRequest, Request, Response, ResponseError,
};
use passmgr::text::escape_path;
use passmgr::timestamp;
use passmgr::token::SessionToken;
use passmgr::{client, session, socket, vault};

use super::args::{
    GrantCommand, GrantCreateOptions, GrantListOptions, GrantRevokeOptions, GrantShowOptions,
};
use super::commands::{prompt_master, unlock, warn_insecure, write_json};
use super::grant_summary::{describe_expires_at, preview_scope, print_approval_prompt};
use super::stdout_write;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Parse `--expires`: a positive whole number of minutes, hours or days.
///
/// Only the three documented units are accepted, so a typo cannot silently
/// become seconds. The maximum is the same 30 days `Grant::create` enforces.
pub(crate) fn parse_expiry(text: &str) -> Result<Duration, String> {
    let digits = text
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .count();
    let (number, unit) = text.split_at(digits);
    if number.is_empty() {
        return Err(format!(
            "invalid --expires '{text}' (expected a duration such as 30m, 1h or 7d)"
        ));
    }
    let value = number
        .parse::<u64>()
        .map_err(|_| format!("invalid --expires '{text}' (the number is too large)"))?;
    let seconds_per_unit = match unit {
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => {
            return Err(format!(
                "invalid --expires '{text}' (use minutes 'm', hours 'h' or days 'd')"
            ));
        }
    };
    let seconds = value
        .checked_mul(seconds_per_unit)
        .ok_or_else(|| format!("invalid --expires '{text}' (the duration is too large)"))?;
    if seconds == 0 {
        return Err("--expires must be at least 1m".to_owned());
    }
    if seconds > MAX_GRANT_LIFETIME_SECS {
        return Err("--expires may be at most 30d".to_owned());
    }
    Ok(Duration::from_secs(seconds))
}

pub(crate) fn command_grant(
    command: GrantCommand,
    agent_mode: bool,
    path: &Path,
) -> Result<(), Error> {
    match command {
        GrantCommand::Create(options) => command_grant_create(options, agent_mode, path),
        GrantCommand::List(options) => command_grant_list(options, path),
        GrantCommand::Show(options) => command_grant_show(options, path),
        GrantCommand::Revoke(options) => command_grant_revoke(options, agent_mode, path),
    }
}

#[cfg(not(unix))]
pub(crate) fn command_grant_create(
    _options: GrantCreateOptions,
    _agent_mode: bool,
    _path: &Path,
) -> Result<(), Error> {
    Err(Error::Daemon(
        "grant create requires the unlock daemon, which is supported on Unix systems only".into(),
    ))
}

#[cfg(not(unix))]
pub(crate) fn command_grant_revoke(
    _options: GrantRevokeOptions,
    _agent_mode: bool,
    _path: &Path,
) -> Result<(), Error> {
    Err(Error::Daemon(
        "grant revoke requires the unlock daemon, which is supported on Unix systems only".into(),
    ))
}

/// `passmgr grant create`: prove the master password and store a new grant.
#[cfg(unix)]
pub(crate) fn command_grant_create(
    options: GrantCreateOptions,
    agent_mode: bool,
    vault_path: &Path,
) -> Result<(), Error> {
    let commands = resolve_commands(&options.commands)?;
    if !options.allow_interpreter && commands.iter().any(|command| is_program_runner(command)) {
        // Do not echo the path: it may have come from an agent suggestion and
        // this line is read by a human's terminal.
        return Err(Error::Refused(
            "refusing to allow a shell, interpreter or program runner in a grant; \
             re-run with --allow-interpreter if every command it can run is trusted"
                .to_owned(),
        ));
    }

    // Creating a grant is a human act. Checked before the approval summary,
    // the password prompt or any file is created: a refusal must cost nothing.
    agent::check_human(agent_mode)
        .map_err(|refusal| Error::Refused(refusal.message_for("create a grant")))?;
    warn_insecure(vault_path)?;

    // Build the exact request first, then resolve and show the human what
    // approving it would mean (TODO R.26, R.41). Everything here is metadata
    // the agent supplied or the vault already stores; no credential value is
    // involved.
    let now = unix_now()?;
    let token = GrantToken::generate()?;
    let scope = Scope::new(options.references, options.tags, None)?;
    let request = GrantRequest::new(
        GrantSpec {
            label: options.label,
            scope,
            commands,
            capabilities: Capabilities::RUN,
            expires_at: now + options.expires.as_secs(),
            max_uses: options.max_uses,
        },
        token.hash(),
    )?;
    request.check_approvable(now)?;

    // An existing `--out` is still refused before the password prompt; the
    // authoritative `O_EXCL` create happens after the human says yes.
    TokenFile::check_available(&options.out)?;

    // The names a human needs to recognize the scope live only in the
    // encrypted vault, so approval now starts with the master password
    // (TODO R.41). A refused request still writes nothing, and the y/N still
    // comes before any daemon contact and before the token file exists.
    let container = vault::read_container(vault_path)?;
    let master = prompt_master(false)?;
    // Derive and authenticate once. The same key proves the approval and
    // writes the grant, so the vault is never decrypted a second time.
    let key = crypto::unlock_key(&container, &master)?;
    drop(master);
    drop(container);

    let grant = request.clone().create_grant(now)?;

    // Resolve the human-readable names and check the vault limits before the
    // human decides. The vault is dropped before the prompt, so decrypted
    // credentials are not kept in memory while a human reads; reopening it is
    // a bare AES decrypt, not another Argon2 derivation.
    let preview = {
        let current = vault::Vault::open_with_key(vault_path, &key)?;
        // The daemon cannot check vault limits (it never opens the vault), so
        // a vault that cannot hold another grant must fail *before* the
        // human's approval is spent (TODO R.22). The check applies the same
        // dead-grant prune the write below does, so "still full" here means
        // full of grants that are actually alive (TODO R.42).
        current.check_grant_writable(&grant, now)?;
        // An unknown ref is refused here, before the summary and before any
        // socket contact: a grant that names nothing must not be approvable.
        preview_scope(request.scope(), &current)?
    };

    // Nothing below this line runs unless the human typed an explicit yes: a
    // `n` must leave no token file and must not contact the daemon.
    print_approval_prompt(&request, now, &preview);
    if !passmgr::terminal::prompt_yes_no("Approve this grant? [y/N] ")? {
        return Err(Error::InvalidInput(
            "grant creation cancelled; nothing was written".to_owned(),
        ));
    }

    let paths = socket::RuntimePaths::resolve();
    let session_token = load_session(&paths)?;

    // Created only after the human said yes; the guard removes the file if
    // anything later fails.
    let mut out = TokenFile::create(&options.out)?;

    let digest = request.digest();
    let nonce = client::challenge(&paths, &session_token)?;
    let proof = passmgr::presence::Proof::compute(&key, &nonce, &digest)
        .map_err(|error| Error::Daemon(format!("could not compute the approval proof: {error}")))?;
    client::prove(
        &paths,
        &session_token,
        &ProveRequest {
            nonce,
            digest,
            proof,
        },
    )?;

    let response = client::request(
        &paths,
        &session_token,
        &Request::GrantCreate(GrantCreateRequest::from_grant_request(&request)),
    )?;
    match response {
        Response::GrantApproved => {}
        Response::Error(error) => {
            return Err(Error::Daemon(format!(
                "the unlock daemon refused the grant ({})",
                error.code()
            )));
        }
        _ => {
            return Err(Error::Daemon(
                "the unlock daemon returned an unexpected response to grant_create".to_owned(),
            ));
        }
    }

    // A failed write here spends the approval but changes nothing; the error
    // says so and a retry asks for a new approval. The vault is opened under
    // the write lock *after* the approval, so a run that recorded a use while
    // the human was deciding cannot make an approved creation fail (TODO
    // R.39); the pre-check above was on a lock-free read and is repeated on
    // this fresh state.
    let mut vault = vault::Vault::open_with_key_for_update(vault_path, &key)?;
    // Drop grants that died more than the retention window ago, in the same
    // write that adds the new one, so a vault that reached `MAX_GRANTS` over
    // its lifetime is usable again (TODO R.42). Reusing `now` from the top of
    // the command is conservative: a grant that dies while the human is
    // deciding is kept, never dropped early.
    vault.prune_dead_grants(now);
    vault.check_grant_writable(&grant, now)?;
    vault.add_grant(grant)?;
    vault.save_with_key(&key)?;

    out.write_token(&token)?;
    out.commit();
    eprintln!("{}", grant_created_message(request.label(), &options.out));
    Ok(())
}

/// The success line for a written grant.
fn grant_created_message(label: &str, out: &Path) -> String {
    format!(
        "Grant '{}' created; token written to '{}'.",
        escape_hidden(label),
        display_path(out)
    )
}

/// Render an argv-supplied path for a human.
///
/// `--out` comes from argv and may have been suggested by an agent, so a raw
/// escape sequence in it would act on the human's terminal (an OSC 52 payload
/// writes the clipboard). [`escape_hidden`] writes every control character as
/// a visible `\u{..}` escape. A path that is not UTF-8 is shown with lossy
/// replacement, exactly as `Path::display` would.
fn display_path(path: &Path) -> String {
    escape_hidden(&path.to_string_lossy())
}

/// The one message for an `--out` that already names something, whether the
/// cheap pre-check or the authoritative `O_EXCL` create found it.
#[cfg(unix)]
fn existing_token_error(path: &Path) -> Error {
    Error::InvalidInput(format!(
        "refusing to overwrite the existing token file '{}'",
        display_path(path)
    ))
}

/// `passmgr grant list [--json]`: metadata for every stored grant.
pub(crate) fn command_grant_list(
    options: GrantListOptions,
    vault_path: &Path,
) -> Result<(), Error> {
    let (vault, _master) = unlock(vault_path)?;
    let now = unix_now()?;
    let grants: Vec<&Grant> = vault.grants().iter().collect();

    if options.json {
        let grants: Vec<_> = grants
            .iter()
            .map(|grant| grant_metadata(grant, now))
            .collect();
        return write_json(&serde_json::json!({ "grants": grants }));
    }
    if grants.is_empty() {
        eprintln!("No grants stored.");
        return Ok(());
    }

    use std::fmt::Write as _;

    let mut output = String::from("Stored Grants:\n");
    for grant in grants {
        writeln!(
            output,
            "- {} ({}) [{}]",
            grant.id(),
            grant.label(),
            grant.status(now).name()
        )
        .expect("writing to a String cannot fail");
        writeln!(
            output,
            "  scope: {}; commands: {}; {}",
            describe_scope(grant.scope()),
            grant.commands().len(),
            describe_uses(grant)
        )
        .expect("writing to a String cannot fail");
        writeln!(output, "  {}", describe_expiry(grant, now))
            .expect("writing to a String cannot fail");
    }
    stdout_write(format_args!("{output}"))
}

/// `passmgr grant show <id> [--json]`: metadata for one grant.
pub(crate) fn command_grant_show(
    options: GrantShowOptions,
    vault_path: &Path,
) -> Result<(), Error> {
    let (vault, _master) = unlock(vault_path)?;
    let now = unix_now()?;
    let grant = vault
        .grant(options.id)
        .ok_or(Error::GrantNotFound(options.id))?;

    if options.json {
        return write_json(&grant_metadata(grant, now));
    }

    use std::fmt::Write as _;

    let mut output = format!("Grant {} ({})\n", grant.id(), grant.label());
    writeln!(output, "  status: {}", grant.status(now).name())
        .expect("writing to a String cannot fail");
    writeln!(output, "  scope: {}", describe_scope(grant.scope()))
        .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  commands: {}",
        grant
            .commands()
            .iter()
            .map(|command| escape_path(command))
            .collect::<Vec<_>>()
            .join(", ")
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  capabilities: {}",
        grant.capabilities().names().join(", ")
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  created: {}",
        timestamp::format_utc(grant.created_unix())
    )
    .expect("writing to a String cannot fail");
    writeln!(output, "  {}", describe_expiry(grant, now)).expect("writing to a String cannot fail");
    writeln!(output, "  {}", describe_uses(grant)).expect("writing to a String cannot fail");
    if let Some(last_used) = grant.last_used_unix() {
        writeln!(output, "  last used: {}", timestamp::format_utc(last_used))
            .expect("writing to a String cannot fail");
    }
    if let Some(revoked_at) = grant.revoked_at_unix() {
        writeln!(output, "  revoked: {}", timestamp::format_utc(revoked_at))
            .expect("writing to a String cannot fail");
    }
    stdout_write(format_args!("{output}"))
}

/// `passmgr grant revoke <id>|--all [--json]`.
///
/// No password, no TTY requirement and no `check_human`: revocation only
/// removes access, so an agent may perform it for the human who granted it.
/// It goes through the daemon because the daemon already holds the key and can
/// write the vault without a prompt; the CLI never sends a secret either way.
#[cfg(unix)]
pub(crate) fn command_grant_revoke(
    options: GrantRevokeOptions,
    _agent_mode: bool,
    _vault_path: &Path,
) -> Result<(), Error> {
    let paths = socket::RuntimePaths::resolve();
    let session_token = load_session(&paths)?;

    let request = match (options.id, options.all) {
        (Some(id), false) => GrantRevokeRequest::Id(id),
        (None, true) => GrantRevokeRequest::All,
        // `parse_grant_revoke` rejects both and neither; keep the command a
        // total function without guessing at intent.
        _ => {
            return Err(Error::InvalidInput(
                "grant revoke needs exactly one grant id or --all".to_owned(),
            ));
        }
    };
    let response = client::request(&paths, &session_token, &Request::GrantRevoke(request))?;
    let revoked = match response {
        Response::GrantRevoked { revoked } => revoked,
        Response::Error(ResponseError::NotFound) => {
            return Err(match options.id {
                // An id the daemon does not know is a not-found (exit 3).
                Some(id) => Error::GrantNotFound(id),
                // `--all` carries no id, so a `not_found` answer cannot name
                // one. Never `expect` here: any same-user process can replace
                // the socket and answer whatever it likes (TODO R.27).
                None => Error::Daemon(format!(
                    "the unlock daemon refused the revocation ({})",
                    ResponseError::NotFound.code()
                )),
            });
        }
        Response::Error(error) => {
            return Err(Error::Daemon(format!(
                "the unlock daemon refused the revocation ({})",
                error.code()
            )));
        }
        _ => {
            return Err(Error::Daemon(
                "the unlock daemon returned an unexpected response to grant_revoke".to_owned(),
            ));
        }
    };

    if options.json {
        return write_json(&serde_json::json!({ "revoked": revoked }));
    }
    match (options.id, revoked) {
        (Some(id), 0) => eprintln!("Grant '{id}' is already revoked; nothing changed."),
        (Some(id), _) => eprintln!("Revoked grant '{id}'."),
        (None, 0) => eprintln!("No active grants to revoke."),
        (None, count) => eprintln!("Revoked {count} grant(s)."),
    }
    Ok(())
}

fn describe_scope(scope: &Scope) -> String {
    let mut parts = Vec::new();
    if !scope.refs().is_empty() {
        let refs: Vec<String> = scope.refs().iter().map(|id| id.to_ref()).collect();
        parts.push(format!("refs: {}", refs.join(", ")));
    }
    if !scope.tags().is_empty() {
        parts.push(format!("tags: {}", scope.tags().join(", ")));
    }
    if let Some(fields) = scope.fields() {
        parts.push(format!("fields: {}", fields.join(", ")));
    }
    parts.join("; ")
}

fn describe_uses(grant: &Grant) -> String {
    match (grant.uses(), grant.max_uses(), grant.uses_left()) {
        (uses, Some(max), Some(left)) => format!("uses: {uses} of {max} ({left} left)"),
        (uses, Some(max), None) => format!("uses: {uses} of {max}"),
        (uses, None, _) => format!("uses: {uses} (unlimited)"),
    }
}

fn describe_expiry(grant: &Grant, now: u64) -> String {
    describe_expires_at(grant.expires_at_unix(), now)
}

/// The JSON form of a grant: references and metadata only.
///
/// There is no `token`, `token_hash` or label-derived secret here. The id is
/// public (it names the grant in `grant list`), and the allowlisted command
/// paths are the ones the human approved.
fn grant_metadata(grant: &Grant, now: u64) -> serde_json::Value {
    serde_json::json!({
        "id": grant.id().to_hex(),
        "label": grant.label(),
        "refs": grant.scope().refs().iter().map(|id| id.to_ref()).collect::<Vec<_>>(),
        "tags": grant.scope().tags(),
        "fields": grant.scope().fields(),
        "commands": grant.commands().iter().map(|command| command.display().to_string()).collect::<Vec<_>>(),
        "capabilities": grant.capabilities().names(),
        "created": timestamp::to_json(grant.created_unix()),
        "expires_at": timestamp::to_json(grant.expires_at_unix()),
        "max_uses": grant.max_uses(),
        "uses": grant.uses(),
        "uses_left": grant.uses_left(),
        "revoked_at": grant.revoked_at_unix().map(timestamp::to_json),
        "last_used": grant.last_used_unix().map(timestamp::to_json),
        "status": grant.status(now).name(),
    })
}

/// Resolve every `--command` through the caller's PATH and canonicalize it.
///
/// Errors never echo the argument: a grant command may be suggested by an
/// agent, and this text goes to a human's terminal. The index is enough to
/// identify which one failed.
fn resolve_commands(given: &[String]) -> Result<Vec<PathBuf>, Error> {
    let cwd = std::env::current_dir()?;
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let mut commands = Vec::with_capacity(given.len());
    for (index, program) in given.iter().enumerate() {
        let number = index + 1;
        let found = super::run::resolve_program(program, &cwd, &path_var).map_err(|_| {
            Error::InvalidInput(format!(
                "cannot resolve grant command #{number}: \
                 use an absolute path or put it on PATH"
            ))
        })?;
        let canonical = std::fs::canonicalize(&found)
            .map_err(|_| Error::InvalidInput(format!("cannot resolve grant command #{number}")))?;
        let metadata = std::fs::metadata(&canonical)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(Error::InvalidInput(format!(
                "grant command #{number} is not an executable file"
            )));
        }
        commands.push(canonical);
    }
    Ok(commands)
}

fn load_session(paths: &socket::RuntimePaths) -> Result<SessionToken, Error> {
    match session::load(paths) {
        Ok(token) => Ok(token),
        Err(error) => {
            // Distinguish "nothing is running" from "a daemon is running but
            // this client cannot authenticate".
            match socket::connect_at(paths) {
                Ok(_) => Err(Error::Daemon(format!(
                    "cannot authenticate to the unlock daemon: {error}; \
                     run 'passmgr lock' and 'passmgr unlock' again"
                ))),
                Err(socket::SocketError::NotRunning) => Err(Error::Daemon(
                    "no passmgr daemon is running; start one with 'passmgr unlock'".to_owned(),
                )),
                Err(error) => Err(Error::Daemon(error.to_string())),
            }
        }
    }
}

fn unix_now() -> Result<u64, Error> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::InvalidInput("the system clock is before the Unix epoch".to_owned()))?
        .as_secs();
    if seconds > passmgr::store::MAX_TIMESTAMP_UNIX {
        return Err(Error::InvalidInput(
            "the system clock is beyond the supported timestamp range".to_owned(),
        ));
    }
    Ok(seconds)
}

/// A token file that exists only if the grant was written.
///
/// Created with `O_CREAT | O_EXCL | O_NOFOLLOW` at 0600 so it can neither
/// overwrite a file nor follow a symlink. If any later step fails, `Drop`
/// removes the empty file: a grant that was not stored must not leave a token
/// behind that authorizes nothing.
#[cfg(unix)]
struct TokenFile {
    file: File,
    path: PathBuf,
    committed: bool,
}

#[cfg(unix)]
impl TokenFile {
    /// Refuse an `--out` that already names something, without creating it.
    ///
    /// `create` is still the authority (`O_EXCL`); this only makes the common
    /// refusal cheap and, since TODO R.41 moved the password prompt ahead of
    /// the summary, keeps it ahead of the password too.
    fn check_available(path: &Path) -> Result<(), Error> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Err(existing_token_error(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::Io(error)),
        }
    }

    fn create(path: &Path) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    existing_token_error(path)
                } else {
                    Error::Io(error)
                }
            })?;
        // `mode` is filtered by the umask, so ask for 0600 explicitly. A
        // token file readable by anyone else would hand out the grant.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            committed: false,
        })
    }

    fn write_token(&mut self, token: &GrantToken) -> Result<(), Error> {
        let hex = token.to_hex();
        self.file.write_all(hex.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.sync_all()?;
        Ok(())
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

#[cfg(unix)]
impl Drop for TokenFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests;
