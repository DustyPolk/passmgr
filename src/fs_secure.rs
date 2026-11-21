//! Private Unix filesystem primitives: safe regular-file open, private 0700
//! directory checks/creation, timed non-blocking `flock`, and atomic 0600 file
//! replacement.
//!
//! Every security-sensitive Unix filesystem sequence in `passmgr` lives here so
//! open flags (`O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`), descriptor-level `fstat`
//! checks, no-repair permission enforcement, timed advisory locking, and atomic
//! writes are audited once instead of drifting across callers.

use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::text::escape_path;

/// The only permission mode used when creating private files (session, audit,
/// lock files, and atomic writes).
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;

/// The permission mode used when creating private directories (runtime and
/// audit state directories).
pub(crate) const PRIVATE_DIR_MODE: u32 = 0o700;

/// Return the effective user ID of the current process.
pub(crate) fn current_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// How [`open_regular_file`] opens the file descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenMode {
    /// Open an existing file read-only (`O_RDONLY`).
    ReadOnly,
    /// Open for reading and writing, creating with [`PRIVATE_FILE_MODE`]
    /// (`0o600`) if missing, without truncating (`O_RDWR | O_CREAT`).
    CreateReadWrite,
    /// Open for reading and appending, creating with [`PRIVATE_FILE_MODE`]
    /// (`0o600`) if missing, without truncating (`O_RDWR | O_APPEND | O_CREAT`).
    CreateReadAppend,
}

/// Permission policy enforced on a private file or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModePolicy {
    /// Do not enforce permission bits.
    Any,
    /// Require exact Unix permission bits (`mode & 0o777 == expected`).
    Exact(u32),
    /// Require no group or world permission bits (`mode & 0o077 == 0`).
    NoGroupWorld,
}

/// Ownership policy enforced on an opened file descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerPolicy {
    /// Require ownership by the current effective user (`geteuid()`).
    CurrentUser,
    /// Do not enforce ownership.
    Any,
}

/// Options for [`open_regular_file`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OpenRegularOptions {
    pub access: OpenMode,
    pub owner: OwnerPolicy,
    pub mode: ModePolicy,
}

/// Advisory lock mode for [`lock_file_with_timeout`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlockKind {
    /// Shared (reader) lock (`LOCK_SH`).
    Shared,
    /// Exclusive (writer) lock (`LOCK_EX`).
    Exclusive,
}

/// Why a private path failed a security check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InsecureKind {
    /// The path is a symbolic link (`ELOOP` on `O_NOFOLLOW` or symlink `lstat`).
    Symlink,
    /// The path is not a regular file (FIFO, directory, socket, device).
    NotRegularFile,
    /// The path exists but is not a real directory.
    NotADirectory,
    /// The file or directory is owned by a different user.
    WrongOwner { expected_uid: u32, actual_uid: u32 },
    /// The file or directory permissions violate the required [`ModePolicy`].
    Permissions { mode: u32, expected: ModePolicy },
}

impl fmt::Display for InsecureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Symlink => f.write_str("symbolic link"),
            Self::NotRegularFile => f.write_str("not a regular file"),
            Self::NotADirectory => f.write_str("not a real directory"),
            Self::WrongOwner {
                expected_uid,
                actual_uid,
            } => write!(f, "owned by uid {actual_uid}, not {expected_uid}"),
            Self::Permissions { mode, expected } => match expected {
                ModePolicy::Exact(want) => {
                    write!(f, "permissions {mode:04o}, expected {want:04o}")
                }
                ModePolicy::NoGroupWorld => {
                    write!(f, "permissions {mode:04o}, expected no group/world bits")
                }
                ModePolicy::Any => write!(f, "permissions {mode:04o}"),
            },
        }
    }
}

/// Why a private filesystem operation failed.
#[derive(Debug)]
pub(crate) enum FsError {
    /// The target path does not exist.
    NotFound { path: PathBuf, source: io::Error },
    /// The path exists (or resolved to a symlink) and failed a security check.
    Insecure { path: PathBuf, kind: InsecureKind },
    /// An advisory `flock` remained contended until the timeout elapsed.
    Busy { path: PathBuf },
    /// Underlying OS or I/O error.
    Io { path: PathBuf, source: io::Error },
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { path, source } => {
                write!(f, "'{}': {source}", escape_path(path))
            }
            Self::Insecure { path, kind } => {
                write!(f, "refusing '{}': {kind}", escape_path(path))
            }
            Self::Busy { path } => {
                write!(f, "'{}' is locked by another process", escape_path(path))
            }
            Self::Io { path, source } => {
                write!(f, "cannot access '{}': {source}", escape_path(path))
            }
        }
    }
}

impl std::error::Error for FsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotFound { source, .. } | Self::Io { source, .. } => Some(source),
            Self::Insecure { .. } | Self::Busy { .. } => None,
        }
    }
}

/// Open a regular file with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and validate
/// file type, ownership, and permissions on the opened descriptor (`fstat`).
///
/// Permissions on existing files are never repaired.
pub(crate) fn open_regular_file(
    path: &Path,
    options: OpenRegularOptions,
) -> Result<(File, fs::Metadata), FsError> {
    open_regular_file_for_uid(path, options, current_uid())
}

fn open_regular_file_for_uid(
    path: &Path,
    options: OpenRegularOptions,
    expected_uid: u32,
) -> Result<(File, fs::Metadata), FsError> {
    let mut open = OpenOptions::new();
    open.read(true);
    match options.access {
        OpenMode::ReadOnly => {}
        OpenMode::CreateReadWrite => {
            open.write(true)
                .create(true)
                .truncate(false)
                .mode(PRIVATE_FILE_MODE);
        }
        OpenMode::CreateReadAppend => {
            open.append(true)
                .create(true)
                .truncate(false)
                .mode(PRIVATE_FILE_MODE);
        }
    }
    // Never follow a symlink at the final component, never block on a FIFO
    // before `fstat` refuses it, and never leak descriptors to child processes.
    open.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);

    let file = loop {
        match open.open(path) {
            Ok(file) => break file,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
                return Err(FsError::Insecure {
                    path: path.to_path_buf(),
                    kind: InsecureKind::Symlink,
                });
            }
            Err(err) if err.raw_os_error() == Some(libc::EISDIR) => {
                return Err(FsError::Insecure {
                    path: path.to_path_buf(),
                    kind: InsecureKind::NotRegularFile,
                });
            }
            Err(err) => return Err(classify_io(path, err)),
        }
    };

    // Inspect the opened descriptor (`fstat`), never the path, so a racing swap
    // cannot slip past type, owner, or mode validation.
    let metadata = file.metadata().map_err(|err| classify_io(path, err))?;
    if !metadata.is_file() {
        return Err(FsError::Insecure {
            path: path.to_path_buf(),
            kind: InsecureKind::NotRegularFile,
        });
    }
    if options.owner == OwnerPolicy::CurrentUser && metadata.uid() != expected_uid {
        return Err(FsError::Insecure {
            path: path.to_path_buf(),
            kind: InsecureKind::WrongOwner {
                expected_uid,
                actual_uid: metadata.uid(),
            },
        });
    }
    check_mode(path, metadata.mode() & 0o777, options.mode)?;
    Ok((file, metadata))
}

/// Validate a private directory without creating it or changing its permissions.
///
/// Returns `Ok(true)` when `path` exists and is a real (non-symlink) directory
/// owned by the current user satisfying `mode`, `Ok(false)` when `path` does
/// not exist, and `Err(FsError::Insecure { .. })` when it is a symlink,
/// non-directory, foreign-owned, or has forbidden permissions.
pub(crate) fn validate_private_dir(path: &Path, mode: ModePolicy) -> Result<bool, FsError> {
    validate_private_dir_for_uid(path, mode, current_uid())
}

fn validate_private_dir_for_uid(
    path: &Path,
    mode: ModePolicy,
    expected_uid: u32,
) -> Result<bool, FsError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(classify_io(path, err)),
    };
    if metadata.file_type().is_symlink() {
        return Err(FsError::Insecure {
            path: path.to_path_buf(),
            kind: InsecureKind::Symlink,
        });
    }
    if !metadata.is_dir() {
        return Err(FsError::Insecure {
            path: path.to_path_buf(),
            kind: InsecureKind::NotADirectory,
        });
    }
    if metadata.uid() != expected_uid {
        return Err(FsError::Insecure {
            path: path.to_path_buf(),
            kind: InsecureKind::WrongOwner {
                expected_uid,
                actual_uid: metadata.uid(),
            },
        });
    }
    check_mode(path, metadata.mode() & 0o777, mode)?;
    Ok(true)
}

/// Ensure `path` exists as a real private `0700` directory owned by the current
/// user satisfying `mode`, never repairing permissions on an existing directory.
///
/// When `recursive` is `false`, parent directories are never created. When
/// `recursive` is `true`, missing parents are created with mode `0o700` and
/// `path` is re-validated after creation.
pub(crate) fn ensure_private_dir(
    path: &Path,
    recursive: bool,
    mode: ModePolicy,
) -> Result<(), FsError> {
    if validate_private_dir(path, mode)? {
        return Ok(());
    }
    match DirBuilder::new()
        .recursive(recursive)
        .mode(PRIVATE_DIR_MODE)
        .create(path)
    {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(classify_io(path, err)),
    }
    // Re-validate rather than trusting the umask or a racing creator.
    if !validate_private_dir(path, mode)? {
        return Err(FsError::NotFound {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::NotFound,
                "directory disappeared after creation",
            ),
        });
    }
    Ok(())
}

/// Acquire a non-blocking shared or exclusive `flock` on `file`, retrying at
/// `retry_interval` until `timeout` elapses.
///
/// The lock is released when `file` (and any duplicates of its open file
/// description) is closed. Never unlinks `path`.
pub(crate) fn lock_file_with_timeout(
    file: &File,
    path: &Path,
    kind: FlockKind,
    timeout: Duration,
    retry_interval: Duration,
) -> Result<(), FsError> {
    let operation = match kind {
        FlockKind::Shared => libc::LOCK_SH,
        FlockKind::Exclusive => libc::LOCK_EX,
    };
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `as_raw_fd` returns a valid descriptor owned by `file`,
        // which outlives each call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if err.kind() != io::ErrorKind::WouldBlock {
            return Err(FsError::Io {
                path: path.to_path_buf(),
                source: err,
            });
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(FsError::Busy {
                path: path.to_path_buf(),
            });
        }
        let pause = retry_interval.min(deadline.saturating_duration_since(now));
        if pause.is_zero() {
            thread::yield_now();
        } else {
            thread::sleep(pause);
        }
    }
}

/// Atomically write `contents` to `path` as a private `0600` file.
///
/// Creates a temporary file in `path`'s parent directory with mode `0o600`,
/// writes `contents`, calls `sync_all()` on the temporary file, atomically
/// renames (`persist`) it onto `path`, and performs a best-effort `sync_all()`
/// on the parent directory. Any error before `persist` cleans up the temporary
/// file automatically.
pub(crate) fn atomic_write_private(
    path: &Path,
    contents: &[u8],
    temp_prefix: &str,
    temp_suffix: &str,
) -> Result<(), FsError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };

    let mut temp = tempfile::Builder::new()
        .prefix(temp_prefix)
        .suffix(temp_suffix)
        .permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .tempfile_in(parent)
        .map_err(|err| classify_io(path, err))?;

    // Guarantee exact 0600 on the fresh temporary descriptor regardless of
    // process umask before any bytes are written or persisted.
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|err| classify_io(path, err))?;

    temp.write_all(contents)
        .and_then(|()| temp.as_file().sync_all())
        .map_err(|err| classify_io(path, err))?;
    temp.persist(path)
        .map_err(|err| classify_io(path, err.error))?;

    // Best effort: make the directory entry durable across a crash. Some
    // filesystems do not support fsync on directories, so failure is ignored.
    if let Ok(directory) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(parent)
    {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn check_mode(path: &Path, actual: u32, policy: ModePolicy) -> Result<(), FsError> {
    let ok = match policy {
        ModePolicy::Any => true,
        ModePolicy::Exact(expected) => actual == expected,
        ModePolicy::NoGroupWorld => actual & 0o077 == 0,
    };
    if ok {
        Ok(())
    } else {
        Err(FsError::Insecure {
            path: path.to_path_buf(),
            kind: InsecureKind::Permissions {
                mode: actual,
                expected: policy,
            },
        })
    }
}

fn classify_io(path: &Path, source: io::Error) -> FsError {
    if source.kind() == io::ErrorKind::NotFound {
        FsError::NotFound {
            path: path.to_path_buf(),
            source,
        }
    } else {
        FsError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

#[cfg(test)]
mod tests;
