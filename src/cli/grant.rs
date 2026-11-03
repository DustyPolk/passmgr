//! `grant create`: the human-authorized path from a fresh token to a stored
//! grant.
//!
//! The command is deliberately a *client* of `pmd`: it derives the vault key
//! once, proves that key's presence for the exact request, lets the daemon
//! accept the grant, and only then writes it to the vault with the same key.
//! The daemon never sees the vault or the raw token, and the raw token is
//! written once to a new 0600 file rather than to stdout.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use passmgr::Error;
use passmgr::agent;
use passmgr::crypto;
use passmgr::grant::{
    Capabilities, GrantRequest, GrantSpec, GrantToken, MAX_GRANT_LIFETIME_SECS, Scope,
    is_interpreter,
};
use passmgr::protocol::{GrantCreateRequest, ProveRequest, Request, Response};
use passmgr::token::SessionToken;
use passmgr::{client, session, socket, vault};

use super::args::{GrantCommand, GrantCreateOptions};
use super::commands::{prompt_master, warn_insecure};

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

/// `passmgr grant create`: prove the master password and store a new grant.
#[cfg(unix)]
pub(crate) fn command_grant_create(
    options: GrantCreateOptions,
    agent_mode: bool,
    vault_path: &Path,
) -> Result<(), Error> {
    let commands = resolve_commands(&options.commands)?;
    if !options.allow_interpreter && commands.iter().any(|command| is_interpreter(command)) {
        // Do not echo the path: it may have come from an agent suggestion and
        // this line is read by a human's terminal.
        return Err(Error::Refused(
            "refusing to allow a shell, interpreter or program runner in a grant; \
             re-run with --allow-interpreter if every command it can run is trusted"
                .to_owned(),
        ));
    }

    // Creating a grant is a human act. Checked before the password prompt or
    // any file is created: a refusal must cost neither.
    agent::check_human(agent_mode)
        .map_err(|refusal| Error::Refused(refusal.message_for("create a grant")))?;
    warn_insecure(vault_path)?;

    let paths = socket::RuntimePaths::resolve();
    let session_token = load_session(&paths)?;

    // Created before the prompt so an existing `--out` fails without asking
    // for the password, and removed by the guard if anything later fails.
    let mut out = TokenFile::create(&options.out)?;

    let container = vault::read_container(vault_path)?;
    let master = prompt_master(false)?;
    // Derive and authenticate once. The same key proves the approval and
    // writes the grant, so the vault is never decrypted a second time.
    let key = crypto::unlock_key(&container, &master)?;
    drop(master);
    drop(container);

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
