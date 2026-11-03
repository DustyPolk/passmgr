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
use std::io::{IsTerminal, Write};
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
use passmgr::timestamp;
use passmgr::token::SessionToken;
use passmgr::{client, session, socket, vault};

use super::args::{
    GrantCommand, GrantCreateOptions, GrantListOptions, GrantRevokeOptions, GrantShowOptions,
};
use super::commands::{prompt_master, unlock, warn_insecure, write_json};
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

    // Build the exact request first, then show the human what approving it
    // would mean (TODO R.26). Everything here is metadata the agent supplied
    // or the vault already stores; no credential value is involved.
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

    // Nothing below this line runs unless the human typed an explicit yes: a
    // `n` must leave no token file and must not contact the daemon.
    print_approval_prompt(&request, now);
    if !passmgr::terminal::prompt_yes_no("Approve this grant? [y/N] ")? {
        return Err(Error::InvalidInput(
            "grant creation cancelled; nothing was written".to_owned(),
        ));
    }

    let paths = socket::RuntimePaths::resolve();
    let session_token = load_session(&paths)?;

    // Created after the human said yes and before the password prompt, so an
    // existing `--out` fails without asking for the password; the guard
    // removes the file if anything later fails.
    let mut out = TokenFile::create(&options.out)?;

    let container = vault::read_container(vault_path)?;
    let master = prompt_master(false)?;
    // Derive and authenticate once. The same key proves the approval and
    // writes the grant, so the vault is never decrypted a second time.
    let key = crypto::unlock_key(&container, &master)?;
    drop(master);
    drop(container);

    let grant = request.clone().create_grant(now)?;

    let mut vault = vault::Vault::open_with_key(vault_path, &key)?;
    // The daemon cannot check vault limits (it never opens the vault), so a
    // vault that cannot hold another grant must fail *before* the human's
    // approval is spent (TODO R.22).
    vault.check_grant_writable(&grant)?;

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
    // says so and a retry asks for a new approval.
    vault.lock_for_update()?;
    vault.add_grant(grant)?;
    vault.save_with_key(&key)?;

    out.write_token(&token)?;
    out.commit();
    eprintln!(
        "Grant '{}' created; token written to '{}'.",
        request.label(),
        options.out.display()
    );
    Ok(())
}

/// Show the human the request they are about to approve, on stderr.
///
/// Only metadata goes to the terminal: label, scope, commands, capabilities,
/// expiry and use limit. The strings are untrusted (an agent suggested the
/// label and paths), so each is escaped and none can drive the terminal.
/// Every program runner that `--allow-interpreter` let through gets its own
/// warning, because allowing one is allowing whatever it can start (TODO
/// R.25).
fn print_approval_prompt(request: &GrantRequest, now: u64) {
    eprint!("{}", describe_request(request, now));
    let color = std::io::stderr().is_terminal();
    for warning in runner_warnings(request) {
        eprintln!("{}", render_warning(&warning, color));
    }
}

/// The request in the form the human reads before approving it.
fn describe_request(request: &GrantRequest, now: u64) -> String {
    use std::fmt::Write as _;

    let mut output = String::from("Grant request:\n");
    writeln!(output, "  label: {}", escape_hidden(request.label()))
        .expect("writing to a String cannot fail");
    writeln!(output, "  scope: {}", describe_scope(request.scope()))
        .expect("writing to a String cannot fail");
    writeln!(output, "  commands:").expect("writing to a String cannot fail");
    for command in request.commands() {
        writeln!(output, "    {}", escape_hidden(command))
            .expect("writing to a String cannot fail");
    }
    writeln!(
        output,
        "  capabilities: {}",
        request.capabilities().names().join(", ")
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  {}",
        describe_expires_at(request.expires_at(), now)
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  max uses: {}",
        request
            .max_uses()
            .map(|uses| uses.to_string())
            .unwrap_or_else(|| "unlimited".to_owned())
    )
    .expect("writing to a String cannot fail");
    output
}

/// A warning line for every command that can run another program.
fn runner_warnings(request: &GrantRequest) -> Vec<String> {
    request
        .commands()
        .iter()
        .filter(|command| is_program_runner(Path::new(command)))
        .map(|command| {
            format!(
                "WARNING: '{}' is a shell, interpreter or program runner: \
                 it can run any command with the credentials this grant covers",
                escape_hidden(command)
            )
        })
        .collect()
}

/// Bold red when the human's terminal can show it, plain text otherwise: a
/// piped summary or a captured log must not gain escape sequences.
fn render_warning(text: &str, color: bool) -> String {
    if color {
        format!("\x1b[1;31m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
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
            grant_status(grant, now)
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
    writeln!(output, "  status: {}", grant_status(grant, now))
        .expect("writing to a String cannot fail");
    writeln!(output, "  scope: {}", describe_scope(grant.scope()))
        .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  commands: {}",
        grant
            .commands()
            .iter()
            .map(|command| command.display().to_string())
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
            return Err(Error::GrantNotFound(
                options.id.expect("not_found implies an id"),
            ));
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

/// The human-readable status: revoked wins over expiry, which wins over
/// exhaustion, so a revoked grant never shows as merely expired.
fn grant_status(grant: &Grant, now: u64) -> &'static str {
    if grant.is_revoked() {
        "revoked"
    } else if now >= grant.expires_at_unix() {
        "expired"
    } else if grant.uses_left() == Some(0) {
        "exhausted"
    } else {
        "active"
    }
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

fn describe_expires_at(expires_at: u64, now: u64) -> String {
    if expires_at <= now {
        format!("expired: {}", timestamp::format_utc(expires_at))
    } else {
        format!(
            "expires: {} (in {})",
            timestamp::format_utc(expires_at),
            humanize_seconds(expires_at - now)
        )
    }
}

/// A coarse, never-negative duration such as `7d 3h`, `59m` or `12s`.
fn humanize_seconds(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
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
        "status": grant_status(grant, now),
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
    fn create(path: &Path) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::InvalidInput(format!(
                        "refusing to overwrite the existing token file '{}'",
                        path.display()
                    ))
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
mod tests {
    use super::*;

    #[test]
    fn expiry_accepts_the_documented_units() {
        assert_eq!(parse_expiry("30m").unwrap(), Duration::from_secs(1_800));
        assert_eq!(parse_expiry("1h").unwrap(), Duration::from_secs(3_600));
        assert_eq!(parse_expiry("7d").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_expiry("30d").unwrap(), Duration::from_secs(2_592_000));
    }

    #[test]
    fn expiry_refuses_unknown_or_unbounded_values() {
        for text in [
            "",
            "0m",
            "0",
            "1s",
            "1h30m",
            "d",
            "1.5h",
            "-1h",
            "31d",
            "999999999999d",
        ] {
            assert!(parse_expiry(text).is_err(), "{text:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_token_file_is_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        std::fs::write(&path, b"keep me").unwrap();
        assert!(TokenFile::create(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
    }

    fn sample_request(now: u64, commands: &[&str]) -> GrantRequest {
        GrantRequest::new(
            GrantSpec {
                label: "deploy prod".into(),
                scope: Scope::new(
                    vec![
                        passmgr::store::EntryId::from_hex("00112233445566778899aabbccddeeff")
                            .expect("entry id"),
                    ],
                    vec!["prod".into()],
                    None,
                )
                .expect("scope"),
                commands: commands.iter().map(PathBuf::from).collect(),
                capabilities: Capabilities::RUN,
                expires_at: now + 3_600,
                max_uses: Some(2),
            },
            passmgr::grant::TokenHash::of(b"approval-canary-token"),
        )
        .expect("request")
    }

    /// The human approves exactly what the summary shows: the label, scope,
    /// commands, capabilities, expiry and use limit. No secret exists at this
    /// point, and the request's token hash has no accessor here.
    #[test]
    fn the_approval_summary_names_every_value_being_approved() {
        let now = 1_700_000_000;
        let summary = describe_request(&sample_request(now, &["/usr/bin/gh"]), now);
        assert!(summary.starts_with("Grant request:\n"), "{summary}");
        assert!(summary.contains("  label: deploy prod"), "{summary}");
        assert!(
            summary.contains("refs: pm://00112233445566778899aabbccddeeff"),
            "{summary}"
        );
        assert!(summary.contains("tags: prod"), "{summary}");
        assert!(
            summary.contains("  commands:\n    /usr/bin/gh\n"),
            "{summary}"
        );
        assert!(summary.contains("  capabilities: run"), "{summary}");
        assert!(
            summary.contains("expires: 2023-11-14T23:13:20Z (in 1h 0m)"),
            "{summary}"
        );
        assert!(summary.contains("  max uses: 2"), "{summary}");
        assert!(!summary.contains("approval-canary-token"), "{summary}");
    }

    #[test]
    fn only_program_runners_produce_a_warning() {
        let now = 1_700_000_000;
        let warnings = runner_warnings(&sample_request(now, &["/usr/bin/gh"]));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with("WARNING: '/usr/bin/gh'"),
            "{warnings:?}"
        );
        assert!(warnings[0].contains("can run any command"), "{warnings:?}");

        assert!(runner_warnings(&sample_request(now, &["/usr/bin/true", "/bin/echo"])).is_empty());
    }

    #[test]
    fn a_warning_is_only_coloured_for_a_terminal() {
        assert_eq!(render_warning("WARNING", false), "WARNING");
        assert_eq!(render_warning("WARNING", true), "\x1b[1;31mWARNING\x1b[0m");
    }

    fn sample_grant(now: u64) -> Grant {
        Grant::create(
            GrantSpec {
                label: "deploy prod".into(),
                scope: Scope::new(
                    vec![
                        passmgr::store::EntryId::from_hex("00112233445566778899aabbccddeeff")
                            .expect("entry id"),
                    ],
                    vec!["prod".into()],
                    Some(vec!["password".into()]),
                )
                .expect("scope"),
                commands: vec![PathBuf::from("/usr/bin/gh")],
                capabilities: Capabilities::RUN,
                expires_at: now + 3_600,
                max_uses: Some(2),
            },
            passmgr::grant::TokenHash::of(b"metadata-canary-token"),
            now,
        )
        .expect("grant")
    }

    /// The JSON form of a grant is the whole agent-facing surface of `grant
    /// list`/`show`; it must carry no token and no hash, not even an encoded
    /// form of one.
    #[test]
    fn grant_metadata_never_carries_a_token_or_its_hash() {
        let now = 1_700_000_000;
        let grant = sample_grant(now);
        let value = grant_metadata(&grant, now);
        let text = value.to_string();
        let hash_hex = grant.token_hash().to_hex();

        assert!(!text.contains(&hash_hex), "{text}");
        assert!(!text.contains("metadata-canary-token"), "{text}");
        assert!(!text.contains("token"), "no field may name a token: {text}");
        assert_eq!(value["id"], serde_json::json!(grant.id().to_hex()));
        assert_eq!(value["label"], serde_json::json!("deploy prod"));
        assert_eq!(
            value["refs"],
            serde_json::json!(["pm://00112233445566778899aabbccddeeff"])
        );
        assert_eq!(value["tags"], serde_json::json!(["prod"]));
        assert_eq!(value["fields"], serde_json::json!(["password"]));
        assert_eq!(value["commands"], serde_json::json!(["/usr/bin/gh"]));
        assert_eq!(value["capabilities"], serde_json::json!(["run"]));
        assert_eq!(value["max_uses"], serde_json::json!(2));
        assert_eq!(value["uses"], serde_json::json!(0));
        assert_eq!(value["uses_left"], serde_json::json!(2));
        assert_eq!(value["revoked_at"], serde_json::Value::Null);
        assert_eq!(value["status"], serde_json::json!("active"));
    }

    #[test]
    fn grant_status_puts_revoked_before_expired_and_exhausted() {
        let now = 1_700_000_000;
        let active = sample_grant(now);
        assert_eq!(grant_status(&active, now), "active");

        let mut expired = sample_grant(now);
        assert_eq!(grant_status(&expired, now + 3_600), "expired");

        let mut exhausted = sample_grant(now);
        exhausted.mark_used(now).expect("first use");
        exhausted.mark_used(now).expect("second use");
        assert_eq!(grant_status(&exhausted, now), "exhausted");

        // Revoking an expired grant still reads as revoked, not expired.
        expired.revoke(now + 10).expect("revoke");
        assert_eq!(grant_status(&expired, now + 3_600), "revoked");
    }

    #[test]
    fn humanized_durations_are_coarse_and_never_negative() {
        assert_eq!(humanize_seconds(7 * 86_400 + 3 * 3_600), "7d 3h");
        assert_eq!(humanize_seconds(3_600 + 120), "1h 2m");
        assert_eq!(humanize_seconds(59 * 60), "59m");
        assert_eq!(humanize_seconds(12), "12s");
        assert_eq!(humanize_seconds(0), "0s");
    }

    #[test]
    fn uses_and_scope_descriptions_name_metadata_only() {
        let now = 1_700_000_000;
        let grant = sample_grant(now);
        assert_eq!(describe_uses(&grant), "uses: 0 of 2 (2 left)");
        assert_eq!(
            describe_scope(grant.scope()),
            "refs: pm://00112233445566778899aabbccddeeff; tags: prod; fields: password"
        );
        assert!(describe_expiry(&grant, now).contains("expires: "));
        assert!(describe_expiry(&grant, now).contains("(in 1h 0m)"));
        assert!(describe_expiry(&grant, now + 3_600).starts_with("expired: "));
    }

    #[cfg(unix)]
    #[test]
    fn a_new_token_file_is_0600_and_removed_when_uncommitted() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        {
            let mut file = TokenFile::create(&path).unwrap();
            file.write_token(&GrantToken::generate().unwrap()).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(!path.exists(), "an uncommitted token file must be removed");
    }
}
