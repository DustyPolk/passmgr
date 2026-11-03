//! Vault write locking and atomic container replacement.
//!
//! Splitting this out of `src/vault.rs` keeps the vault lifecycle readable and
//! puts every "how does a writer serialize with another writer" decision in
//! one reviewable place. The public paths (`vault::lock_path`,
//! `vault::LOCK_SUFFIX`) are re-exported from `src/vault.rs`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Suffix of the sidecar file whose `flock` serializes vault writers.
pub const LOCK_SUFFIX: &str = ".lock";

/// How long a writer waits for another writer before giving up.
///
/// Writers are short-lived CLI commands, so a healthy lock is released in
/// milliseconds. A longer wait would only hide a stuck process, and an
/// unattended caller must not hang forever.
const WRITE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_LOCK_RETRY: Duration = Duration::from_millis(10);

/// The sidecar lock path for `vault`: `<vault>.lock` in the same directory.
///
/// The lock file is never unlinked: removing it while it is held would let a
/// second writer lock a fresh inode and break mutual exclusion.
pub fn lock_path(vault: &Path) -> PathBuf {
    let mut path = vault.as_os_str().to_os_string();
    path.push(LOCK_SUFFIX);
    PathBuf::from(path)
}

/// Take the exclusive write lock for `vault`, creating the sidecar 0600 file
/// if needed.
pub(super) fn acquire_write_lock(vault: &Path) -> Result<File> {
    acquire_write_lock_with_timeout(vault, WRITE_LOCK_TIMEOUT)
}

#[cfg(unix)]
pub(super) fn acquire_write_lock_with_timeout(vault: &Path, timeout: Duration) -> Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = lock_path(vault);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        // Never follow a symlink planted at the lock path, and never leak the
        // descriptor into a child process.
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|err| with_path(&path, err))?;

    let metadata = file.metadata().map_err(|err| with_path(&path, err))?;
    if !metadata.is_file() {
        return Err(Error::MalformedVault(format!(
            "lock '{}' is not a regular file",
            path.display()
        )));
    }
    // An old lock file could carry a wider mode; narrow it before use.
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|err| with_path(&path, err))?;

    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `as_raw_fd` returns a valid descriptor owned by `file`,
        // which outlives each call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(file);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::WouldBlock {
            return Err(with_path(&path, err));
        }
        if Instant::now() >= deadline {
            return Err(Error::VaultBusy(vault.to_path_buf()));
        }
        thread::sleep(WRITE_LOCK_RETRY);
    }
}

#[cfg(not(unix))]
pub(super) fn acquire_write_lock_with_timeout(vault: &Path, _timeout: Duration) -> Result<File> {
    let _ = vault;
    Err(Error::UnsupportedFormat(
        "vault write locking requires a Unix system".to_owned(),
    ))
}

pub(super) fn write_container(path: &Path, container: &[u8]) -> Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };

    let mut temp = tempfile::Builder::new()
        .prefix(".passmgr-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|err| with_path(path, err))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| with_path(path, err))?;
    }

    temp.write_all(container)
        .map_err(|err| with_path(path, err))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| with_path(path, err))?;
    temp.persist(path)
        .map_err(|err| with_path(path, err.error))?;

    // Best effort: make the rename durable across a crash. Some filesystems do
    // not support fsync on directories, so failure is ignored.
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

pub(super) fn with_path(path: &Path, err: io::Error) -> Error {
    Error::Io(io::Error::new(
        err.kind(),
        format!("{}: {err}", path.display()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use crate::vault::Vault;

    #[test]
    fn write_lock_is_exclusive_private_and_released_on_drop() {
        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.dat");
        let master = "master";

        let first = Vault::open_for_add(&vault_path, master).unwrap();
        let lock_path = lock_path(&vault_path);
        assert_eq!(lock_path, directory.path().join("vault.dat.lock"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the lock file must not be readable by others");
        }

        // A second writer cannot take the lock while the first is alive. The
        // short timeout keeps the test fast; production waits 30 s.
        let started = Instant::now();
        assert!(matches!(
            acquire_write_lock_with_timeout(&vault_path, Duration::from_millis(100)),
            Err(Error::VaultBusy(_))
        ));
        assert!(started.elapsed() >= Duration::from_millis(100));

        // Dropping the first vault releases the kernel lock.
        drop(first);
        let second = Vault::open_for_add(&vault_path, master);
        assert!(second.is_ok(), "the lock must be released on drop");
    }

    #[cfg(unix)]
    #[test]
    fn write_lock_refuses_a_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.dat");
        let target = directory.path().join("target");
        fs::write(&target, b"do not touch").unwrap();
        symlink(&target, lock_path(&vault_path)).unwrap();

        assert!(matches!(
            Vault::open_for_add(&vault_path, "master"),
            Err(Error::Io(_))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"do not touch");
    }
}
