//! `unlock` and `lock`, the commands that drive the unlock daemon.

use std::path::Path;

use passmgr::Error;
use passmgr::agent;
use passmgr::vault;

use super::commands::{prompt_master, warn_insecure};
use super::stdout_write;

#[cfg(not(unix))]
pub(crate) const DAEMON_UNSUPPORTED: &str = "the unlock daemon is supported on Unix systems only";

/// `passmgr unlock`: derive the key at a human terminal and start `pmd`.
#[cfg(unix)]
pub(crate) fn command_unlock(
    agent_mode: bool,
    path: &Path,
    idle_timeout: Option<std::time::Duration>,
) -> Result<(), Error> {
    use passmgr::token::SessionToken;

    let idle_timeout = idle_timeout.unwrap_or(passmgr::daemon::DEFAULT_IDLE_TIMEOUT);
    // Starting the daemon is where a session begins, so it must be the
    // human's decision. Checked before any prompt: a refusal must not cost a
    // master-password prompt, and no environment variable can override it.
    agent::check_human(agent_mode)
        .map_err(|refusal| Error::Refused(refusal.message_for("start the unlock daemon")))?;
    warn_insecure(path)?;

    let runtime = passmgr::socket::RuntimePaths::resolve();
    match passmgr::socket::connect_at(&runtime) {
        Ok(_) => {
            return Err(Error::Daemon(
                "an unlock daemon is already running; run 'passmgr lock' first".to_owned(),
            ));
        }
        Err(passmgr::socket::SocketError::NotRunning) => {}
        Err(error) => return Err(Error::Daemon(error.to_string())),
    }

    let container = vault::read_container(path)?;
    let master = prompt_master(false)?;
    // Derive and authenticate in one step. A wrong password fails here, in
    // this short-lived process, before any daemon exists to hold a key.
    let key = passmgr::crypto::unlock_key(&container, &master)?;
    drop(master);
    drop(container);

    // A stale file from a previous session would make clients send a token
    // this daemon does not know; clear it before creating the new one.
    if let Err(error) = passmgr::session::remove(&runtime) {
        return Err(Error::Daemon(format!(
            "could not clear the previous session token: {error}"
        )));
    }
    let token = SessionToken::generate()
        .map_err(|error| Error::Daemon(format!("could not create a session token: {error}")))?;
    passmgr::session::store(&runtime, &token).map_err(|error| {
        Error::Daemon(format!("could not write the session token file: {error}"))
    })?;

    let spawned = passmgr::client::spawn_daemon(path, &runtime, &key, &token, idle_timeout);
    drop(key);
    let pid = match spawned {
        Ok(pid) => pid,
        Err(error) => {
            // No daemon means the token authorizes nothing; do not leave it
            // behind for the next unlock to mistake for a live session.
            let _ = passmgr::session::remove(&runtime);
            return Err(error);
        }
    };
    stdout_write(format_args!(
        "Vault unlocked. The unlock daemon is running (pid {pid}).\n\
         It stops after {idle_timeout:?} without activity.\n\
         Run 'passmgr lock' to stop it now.\n"
    ))
}

/// `passmgr lock`: ask the daemon to wipe its key and stop.
#[cfg(unix)]
pub(crate) fn command_lock() -> Result<(), Error> {
    let runtime = passmgr::socket::RuntimePaths::resolve();
    passmgr::client::lock(&runtime)?;
    stdout_write(format_args!(
        "The unlock daemon has wiped its key and stopped.\n"
    ))
}

#[cfg(not(unix))]
pub(crate) fn command_unlock(
    _agent_mode: bool,
    _path: &Path,
    _idle_timeout: Option<std::time::Duration>,
) -> Result<(), Error> {
    Err(Error::Daemon(DAEMON_UNSUPPORTED.to_owned()))
}

#[cfg(not(unix))]
pub(crate) fn command_lock() -> Result<(), Error> {
    Err(Error::Daemon(DAEMON_UNSUPPORTED.to_owned()))
}
