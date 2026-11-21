//! Vault write locking and atomic container replacement.
//!
//! Splitting this out of `src/vault.rs` keeps the vault lifecycle readable and
//! puts every "how does a writer serialize with another writer" decision in
//! one reviewable place. The public paths (`vault::lock_path`,
//! `vault::LOCK_SUFFIX`) are re-exported from `src/vault.rs`.

use std::fs::{self, File};
use std::io;
#[cfg(not(unix))]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};
#[cfg(unix)]
use crate::fs_secure::{
    self, FlockKind, FsError, InsecureKind, ModePolicy, OpenMode, OpenRegularOptions, OwnerPolicy,
    PRIVATE_FILE_MODE,
};
use crate::text::escape_path;

/// Suffix of the sidecar file whose `flock` serializes vault writers.
pub const LOCK_SUFFIX: &str = ".lock";

/// How long a writer waits for another writer before giving up.
///
/// Writers are short-lived CLI commands, so a healthy lock is released in
/// milliseconds. A longer wait would only hide a stuck process, and an
/// unattended caller must not hang forever.
const WRITE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(unix)]
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
    use std::os::unix::fs::PermissionsExt;

    let path = lock_path(vault);
    let (file, _) = fs_secure::open_regular_file(
        &path,
        OpenRegularOptions {
            access: OpenMode::CreateReadWrite,
            owner: OwnerPolicy::CurrentUser,
            mode: ModePolicy::Any,
        },
    )
    .map_err(|err| map_fs_error(vault, err))?;

    // An old lock file could carry a wider mode; narrow it before use.
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|err| with_path(&path, err))?;

    fs_secure::lock_file_with_timeout(
        &file,
        &path,
        FlockKind::Exclusive,
        timeout,
        WRITE_LOCK_RETRY,
    )
    .map_err(|err| map_fs_error(vault, err))?;
    Ok(file)
}

#[cfg(not(unix))]
pub(super) fn acquire_write_lock_with_timeout(vault: &Path, _timeout: Duration) -> Result<File> {
    let _ = vault;
    Err(Error::UnsupportedFormat(
        "vault write locking requires a Unix system".to_owned(),
    ))
}

#[cfg(unix)]
pub(super) fn write_container(path: &Path, container: &[u8]) -> Result<()> {
    fs_secure::atomic_write_private(path, container, ".passmgr-", ".tmp")
        .map_err(|err| map_fs_error(path, err))
}

#[cfg(unix)]
fn map_fs_error(vault: &Path, err: FsError) -> Error {
    match err {
        FsError::Insecure {
            path,
            kind: InsecureKind::NotRegularFile,
        } => Error::MalformedVault(format!(
            "lock '{}' is not a regular file",
            escape_path(&path)
        )),
        FsError::Insecure {
            path,
            kind: InsecureKind::Symlink,
        } => with_path(&path, io::Error::from_raw_os_error(libc::ELOOP)),
        FsError::Insecure { path, kind } => with_path(
            &path,
            io::Error::new(io::ErrorKind::PermissionDenied, kind.to_string()),
        ),
        FsError::NotFound { path, source } | FsError::Io { path, source } => {
            with_path(&path, source)
        }
        FsError::Busy { .. } => Error::VaultBusy(vault.to_path_buf()),
    }
}

#[cfg(not(unix))]
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
        format!("'{}': {err}", escape_path(path)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
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

    #[cfg(unix)]
    #[test]
    fn write_lock_refuses_a_fifo_without_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.dat");
        let fifo = lock_path(&vault_path);
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        assert!(made.unwrap().success(), "mkfifo");

        let (sender, receiver) = std::sync::mpsc::channel();
        let path_for_thread = vault_path.clone();
        thread::spawn(move || {
            let _ = sender.send(
                acquire_write_lock_with_timeout(&path_for_thread, Duration::from_millis(100))
                    .map(drop),
            );
        });
        let result = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("opening a FIFO lock file must not block");
        assert!(
            matches!(result, Err(Error::MalformedVault(_))),
            "{result:?}"
        );
        assert!(fifo.exists(), "the FIFO is not removed");
    }
}
