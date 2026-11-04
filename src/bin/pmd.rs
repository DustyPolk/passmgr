//! `pmd`: the passmgr unlock daemon.
//!
//! Started by `passmgr unlock` (TODO 2.4b). It reads the 32-byte vault key and
//! the 32-byte session token from stdin, verifies the key against the vault,
//! then serves the daemon protocol (`passmgr::protocol`) on a Unix socket until
//! `lock`, a signal or the idle timeout. Requests must carry the session
//! token. It never prints key material and never returns a secret value.

#[cfg(not(unix))]
fn main() {
    eprintln!("pmd: the unlock daemon is supported on Unix systems only");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    if let Err(err) = run() {
        eprintln!("pmd: {err}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn run() -> Result<(), passmgr::daemon::DaemonError> {
    use std::io::{self, Write};
    use std::path::PathBuf;

    use passmgr::daemon;
    use passmgr::socket::RuntimePaths;

    let mut vault: Option<PathBuf> = None;
    let mut runtime_dir: Option<PathBuf> = None;
    let mut idle_timeout = daemon::DEFAULT_IDLE_TIMEOUT;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--vault") => {
                vault = Some(PathBuf::from(next_value(&mut args, "--vault")?));
            }
            Some("--runtime-dir") => {
                runtime_dir = Some(PathBuf::from(next_value(&mut args, "--runtime-dir")?));
            }
            Some("--idle-timeout") => {
                let value = next_value(&mut args, "--idle-timeout")?;
                idle_timeout = parse_idle_timeout_argument(&value)?;
            }
            Some("--help" | "-h") => {
                let mut stdout = io::stdout().lock();
                writeln!(
                    stdout,
                    "pmd: the passmgr unlock daemon\n\n\
                     Usage: pmd --vault PATH [--runtime-dir DIR] [--idle-timeout SECS]\n\n\
                     Reads a 32-byte vault key and a 32-byte session token from stdin,\n\
                     verifies the key, then serves daemon requests on DIR/pmd.sock.\n\
                     Every request must carry the session token. Started by\n\
                     `passmgr unlock`; stop it with `passmgr lock` or SIGTERM.\n\n\
                     --idle-timeout SECS  Stop and wipe the key after SECS without a\n\
                                          successfully handled request (default: {}).",
                    daemon::DEFAULT_IDLE_TIMEOUT.as_secs()
                )
                .map_err(daemon::DaemonError::Io)?;
                return Ok(());
            }
            _ => {
                return Err(daemon::DaemonError::Usage(format!(
                    "unexpected argument {:?}",
                    arg.to_string_lossy()
                )));
            }
        }
    }

    let vault = vault.ok_or_else(|| daemon::DaemonError::Usage("missing --vault PATH".into()))?;
    let paths = match runtime_dir {
        Some(dir) => RuntimePaths::at(dir),
        None => RuntimePaths::resolve(),
    };

    // Read the key and session token before touching the filesystem: no
    // socket appears for a caller that cannot even hand over both.
    let mut stdin = io::stdin().lock();
    let handover = daemon::read_handover(&mut stdin)?;
    drop(stdin);

    daemon::run(&vault, paths.dir(), handover, idle_timeout)
}

#[cfg(unix)]
fn parse_idle_timeout_argument(
    value: &std::ffi::OsStr,
) -> Result<std::time::Duration, passmgr::daemon::DaemonError> {
    let text = value.to_str().ok_or_else(|| {
        passmgr::daemon::DaemonError::Usage("--idle-timeout value must be valid UTF-8".into())
    })?;
    passmgr::daemon::parse_idle_timeout(text).map_err(passmgr::daemon::DaemonError::Usage)
}

#[cfg(unix)]
fn next_value(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    flag: &str,
) -> Result<std::ffi::OsString, passmgr::daemon::DaemonError> {
    args.next()
        .ok_or_else(|| passmgr::daemon::DaemonError::Usage(format!("{flag} requires a value")))
}
