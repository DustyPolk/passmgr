//! Where the unlock daemon's socket lives, and how it is created safely.
//!
//! The daemon (`pmd`, TODO 2.4) holds the vault key. Clients reach it over a
//! Unix socket, so the socket's location and permissions are part of the
//! security boundary:
//!
//! ```text
//! $XDG_RUNTIME_DIR/passmgr/          mode 0700, owned by the user
//! $XDG_RUNTIME_DIR/passmgr/pmd.sock  mode 0600, a socket
//! $XDG_RUNTIME_DIR/passmgr/pmd.lock  mode 0600, flock() target
//! ```
//!
//! `XDG_RUNTIME_DIR` is a per-user, per-boot private directory. When it is
//! unset (common on macOS) the fallback is `<temp_dir>/passmgr-<uid>`, still
//! checked to be a real 0700 directory owned by the current user. The fallback
//! keeps the uid in the name so two users sharing a temp directory cannot
//! collide; the ownership and mode checks below then fail closed on anything
//! pre-created by somebody else.
//!
//! # Single instance
//!
//! `pmd.lock` is held with a non-blocking `flock(LOCK_EX)` for the whole life
//! of [`DaemonSocket`]. A second daemon fails immediately with
//! [`SocketError::AlreadyRunning`] instead of racing on the socket path. The
//! lock is advisory but that is enough: both contenders are our own code.
//!
//! # Stale sockets
//!
//! A crashed daemon leaves the socket file behind. [`DaemonSocket::bind_at`]
//! never unlinks a socket blindly: it first connects to it. A successful
//! connection means a live daemon (refuse), `ECONNREFUSED` means nobody is
//! listening (unlink and rebind), and anything else is reported as an error.
//! Only a real socket owned by the current user is ever removed; symlinks and
//! regular files are refused untouched.
//!
//! The socket is chmodded to 0600 *after* `bind` because the bind creates it
//! with the process umask. The 0700 directory already keeps other users out,
//! so that brief window is not reachable from outside the account; the chmod
//! is belt and braces (and covers a directory that is later widened).
//!
//! # Peer credentials
//!
//! File permissions and the 0700 directory are the first line of defence, but
//! the daemon does not rely on them alone. Every accepted connection has its
//! peer's uid read from the kernel *before* a single request byte is read:
//! `SO_PEERCRED` on Linux and `getpeereid` on macOS. A peer whose uid is not
//! the daemon's own uid is disconnected with [`SocketError::PeerRejected`].
//! Use [`DaemonSocket::accept_peer`] rather than [`DaemonSocket::listener`],
//! so the check cannot be forgotten.
//!
//! The credentials are the ones the kernel recorded when the peer called
//! `connect(2)`; they cannot be chosen or forged by the connecting process.
//! Note what this check does **not** do: every process running as the same
//! user passes it. It separates users, not agents from their owner. Requests
//! from the owner are authorized separately by the session token (TODO 2.5)
//! and grants (TODO 3.1). On Linux the reported pid is informational only and
//! is never used for authorization (pids are reused).

use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::fs_secure::{
    self, FlockKind, FsError, ModePolicy, OpenMode, OpenRegularOptions, OwnerPolicy, current_uid,
};
use crate::text::escape_path;

/// Subdirectory of `XDG_RUNTIME_DIR` that holds the socket, lock and session
/// token. Created with mode 0700.
pub const RUNTIME_SUBDIR: &str = "passmgr";
/// Name of the daemon's Unix socket inside the runtime directory.
pub const SOCKET_FILE: &str = "pmd.sock";
/// Name of the single-instance lock file inside the runtime directory.
pub const LOCK_FILE: &str = "pmd.lock";
/// Name of the session token file inside the runtime directory.
pub const SESSION_FILE: &str = "session";
/// Mode of the runtime directory.
pub const DIR_MODE: u32 = 0o700;
/// Mode of the socket and the lock file.
pub const FILE_MODE: u32 = 0o600;

/// Largest `sun_path` that Linux accepts: 108 bytes including the trailing
/// NUL, so 107 bytes of path. macOS allows 104. We use the smaller limit so a
/// path that works on Linux also works on macOS.
const MAX_SOCKET_PATH_BYTES: usize = 104;

/// Why the socket could not be set up or reached.
///
/// Messages contain paths and modes only; there are no secrets anywhere near
/// this module.
#[derive(Debug)]
pub enum SocketError {
    /// Filesystem or socket syscall failure, with the path that caused it.
    Io { path: PathBuf, source: io::Error },
    /// A path the daemon relies on is not a real directory/socket, is owned
    /// by another user, or has permissions other than 0700/0600.
    InsecurePath { path: PathBuf, detail: String },
    /// The socket path would not fit in `sun_path`.
    PathTooLong { path: PathBuf, bytes: usize },
    /// Another daemon holds the instance lock, or is still answering on the
    /// socket.
    AlreadyRunning,
    /// Something that is not a socket (or is a symlink) occupies the socket
    /// path. It is left alone.
    NotASocket(PathBuf),
    /// No daemon is listening (socket missing, or connection refused).
    NotRunning,
    /// The kernel says the connection comes from a different user than the
    /// one that owns the daemon. The connection is dropped unread.
    PeerRejected { expected: u32, actual: u32 },
    /// Asking the kernel for the peer's credentials failed.
    PeerCheckFailed(io::Error),
    /// This platform has no peer-credential implementation compiled in. The
    /// daemon fails closed rather than accepting an unchecked peer.
    PeerCheckUnsupported,
}

impl SocketError {
    fn io(path: &Path, err: io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source: err,
        }
    }
}

impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "'{}': {source}", escape_path(path)),
            Self::InsecurePath { path, detail } => {
                write!(f, "refusing to use '{}': {detail}", escape_path(path))
            }
            Self::PathTooLong { path, bytes } => write!(
                f,
                "socket path '{}' is {bytes} bytes; the limit is {MAX_SOCKET_PATH_BYTES}",
                escape_path(path)
            ),
            Self::AlreadyRunning => f.write_str("another passmgr daemon is already running"),
            Self::NotASocket(path) => write!(
                f,
                "'{}' exists but is not a socket; refusing to remove it",
                escape_path(path)
            ),
            Self::NotRunning => f.write_str("no passmgr daemon is running (try 'passmgr unlock')"),
            Self::PeerRejected { expected, actual } => write!(
                f,
                "refusing connection from uid {actual}; the daemon is owned by uid {expected}"
            ),
            Self::PeerCheckUnsupported => {
                f.write_str("this platform does not support peer credential checks")
            }
            Self::PeerCheckFailed(source) => {
                write!(f, "could not read the peer's credentials: {source}")
            }
        }
    }
}

/// The kernel-reported identity of the process at the other end of a Unix
/// socket, captured when it connected.
///
/// `pid` is `Some` on Linux and `None` on macOS. It is informational: never
/// authorize on it, because process ids are reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    uid: u32,
    gid: u32,
    pid: Option<i32>,
}

impl PeerCredentials {
    /// The peer's user id.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The peer's group id.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// The peer's process id, where the platform reports one.
    pub fn pid(&self) -> Option<i32> {
        self.pid
    }

    /// Accept only `expected_uid`; every other user is rejected.
    pub fn verify(&self, expected_uid: u32) -> Result<(), SocketError> {
        if self.uid == expected_uid {
            Ok(())
        } else {
            Err(SocketError::PeerRejected {
                expected: expected_uid,
                actual: self.uid,
            })
        }
    }
}

/// Read the peer credentials of an accepted connection.
///
/// This issues one `getsockopt(SO_PEERCRED)` / `getpeereid` call and reads no
/// bytes from the stream.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn credentials_from_fd(fd: RawFd) -> io::Result<PeerCredentials> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is borrowed from a live `UnixStream`, the buffer points at
    // a live `ucred`, and `len` describes its size exactly.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned an unexpected SO_PEERCRED size",
        ));
    }
    Ok(PeerCredentials {
        uid: cred.uid,
        gid: cred.gid,
        pid: Some(cred.pid),
    })
}

/// Read the peer credentials of an accepted connection (macOS `getpeereid`).
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn credentials_from_fd(fd: RawFd) -> io::Result<PeerCredentials> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is borrowed from a live `UnixStream` and both out-pointers
    // refer to live locals. `getpeereid` writes both on success.
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials {
        uid,
        gid,
        pid: None,
    })
}

/// Platforms without a compiled-in credential check fail closed.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn credentials_from_fd(_fd: RawFd) -> io::Result<PeerCredentials> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credential checks are not implemented on this platform",
    ))
}

impl std::error::Error for SocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::PeerCheckFailed(source) => Some(source),
            _ => None,
        }
    }
}

/// Paths used by the daemon, all inside one 0700 directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePaths {
    dir: PathBuf,
}

impl RuntimePaths {
    /// Resolve the runtime directory from the environment.
    pub fn resolve() -> Self {
        Self::at(default_dir(env::var_os("XDG_RUNTIME_DIR").as_deref()))
    }

    /// Use an explicit runtime directory. Used by tests and by
    /// `RuntimePaths::resolve`.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The 0700 directory that holds the socket, lock and session token.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `$dir/pmd.sock`.
    pub fn socket(&self) -> PathBuf {
        self.dir.join(SOCKET_FILE)
    }

    /// `$dir/pmd.lock`.
    pub fn lock(&self) -> PathBuf {
        self.dir.join(LOCK_FILE)
    }

    /// The session token file clients use to authorize requests.
    pub fn session(&self) -> PathBuf {
        self.dir.join(SESSION_FILE)
    }

    /// Create the directory if needed, then require that it is a real 0700
    /// directory owned by the current user. Anything else is refused rather
    /// than repaired, so a pre-created directory cannot be taken over.
    pub(crate) fn ensure_dir(&self) -> Result<(), SocketError> {
        fs_secure::ensure_private_dir(&self.dir, false, ModePolicy::Exact(DIR_MODE))
            .map_err(map_fs_error)
    }
}

/// The default runtime directory: `$XDG_RUNTIME_DIR/passmgr`, or
/// `<temp_dir>/passmgr-<uid>` when `XDG_RUNTIME_DIR` is unset or empty.
///
/// Split out from [`RuntimePaths::resolve`] so the choice is testable without
/// mutating the process environment.
pub fn default_dir(xdg_runtime_dir: Option<&OsStr>) -> PathBuf {
    match xdg_runtime_dir.filter(|value| !value.is_empty()) {
        Some(base) => Path::new(base).join(RUNTIME_SUBDIR),
        None => env::temp_dir().join(format!("{RUNTIME_SUBDIR}-{}", current_uid())),
    }
}

/// The bound daemon socket plus the single-instance lock that keeps it unique.
///
/// Dropping this removes the socket file (if it is still the one we bound) and
/// releases the lock. The lock file itself is left in place: unlinking a lock
/// file while holding it would let a second daemon lock a fresh inode.
#[derive(Debug)]
pub struct DaemonSocket {
    paths: RuntimePaths,
    listener: UnixListener,
    /// Held for the lifetime of the daemon; closed on drop, which releases
    /// the `flock`.
    _lock: File,
    /// Inode of the socket we created, so `Drop` cannot remove a socket that
    /// somebody else bound in the meantime.
    socket_inode: u64,
}

impl DaemonSocket {
    /// Bind the daemon socket at the environment-derived path.
    pub fn bind() -> Result<Self, SocketError> {
        Self::bind_at(RuntimePaths::resolve())
    }

    /// Bind the daemon socket at an explicit runtime directory.
    ///
    /// Order matters: the directory is validated, the instance lock is taken,
    /// and only then is a stale socket removed and a new one bound. Holding
    /// the lock first means two simultaneous starts cannot both decide the
    /// socket is stale.
    pub fn bind_at(paths: RuntimePaths) -> Result<Self, SocketError> {
        let socket_path = paths.socket();
        let bytes = socket_path.as_os_str().as_bytes().len();
        if bytes > MAX_SOCKET_PATH_BYTES {
            return Err(SocketError::PathTooLong {
                path: socket_path,
                bytes,
            });
        }

        paths.ensure_dir()?;
        let lock = acquire_lock(&paths.lock())?;
        clear_stale_socket(&socket_path)?;

        let listener =
            UnixListener::bind(&socket_path).map_err(|err| SocketError::io(&socket_path, err))?;

        let socket_inode = match set_socket_permissions(&socket_path) {
            Ok(inode) => inode,
            Err(err) => {
                // Do not leave a socket behind that nobody is listening on.
                drop(listener);
                let _ = fs::remove_file(&socket_path);
                return Err(err);
            }
        };

        Ok(Self {
            paths,
            listener,
            _lock: lock,
            socket_inode,
        })
    }

    /// The listening socket; the daemon accepts connections from here.
    ///
    /// Prefer [`Self::accept_peer`], which performs the peer-uid check. This
    /// accessor exists for tests and for code that has already validated its
    /// peer another way.
    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// Accept one connection and verify the peer's uid.
    ///
    /// The uid is read from the kernel and compared with this process's
    /// effective uid before any request bytes are read. A mismatch yields
    /// [`SocketError::PeerRejected`] and the connection is dropped. The
    /// returned stream is the only handle the daemon should read from.
    pub fn accept_peer(&self) -> Result<(UnixStream, PeerCredentials), SocketError> {
        self.accept_peer_expecting(current_uid())
    }

    /// `accept_peer` with an explicit owner uid. Split out so tests can force
    /// the check to fail without needing a second user account.
    fn accept_peer_expecting(
        &self,
        expected_uid: u32,
    ) -> Result<(UnixStream, PeerCredentials), SocketError> {
        let (stream, _addr) = self
            .listener
            .accept()
            .map_err(|err| SocketError::io(&self.paths.socket(), err))?;

        let peer = match peer_credentials(&stream) {
            Ok(peer) => peer,
            Err(err) => {
                drop(stream);
                return Err(err);
            }
        };
        if let Err(err) = peer.verify(expected_uid) {
            drop(stream);
            return Err(err);
        }
        Ok((stream, peer))
    }

    /// The paths this socket was bound at.
    pub fn paths(&self) -> &RuntimePaths {
        &self.paths
    }
}

impl Drop for DaemonSocket {
    fn drop(&mut self) {
        let path = self.paths.socket();
        let still_ours = fs::symlink_metadata(&path)
            .map(|meta| meta.ino() == self.socket_inode && meta.file_type().is_socket())
            .unwrap_or(false);
        if still_ours {
            let _ = fs::remove_file(path);
        }
    }
}

/// Connect to the daemon at the environment-derived path.
pub fn connect() -> Result<UnixStream, SocketError> {
    connect_at(&RuntimePaths::resolve())
}

/// Read the peer credentials of `stream` (an accepted connection).
pub fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, SocketError> {
    credentials_from_fd(stream.as_raw_fd()).map_err(|err| {
        if err.kind() == io::ErrorKind::Unsupported {
            SocketError::PeerCheckUnsupported
        } else {
            SocketError::PeerCheckFailed(err)
        }
    })
}

/// Connect to the daemon at an explicit runtime directory.
pub fn connect_at(paths: &RuntimePaths) -> Result<UnixStream, SocketError> {
    let path = paths.socket();
    match UnixStream::connect(&path) {
        Ok(stream) => Ok(stream),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Err(SocketError::NotRunning)
        }
        Err(err) => Err(SocketError::io(&path, err)),
    }
}

/// How long to keep retrying a lock that looks held.
///
/// `flock` is released when the last descriptor for the file closes, but a
/// close performed on another thread can be deferred to that thread's task
/// work. For a few milliseconds afterwards the lock still looks held even
/// though its owner has gone. Waiting that window out avoids reporting a
/// `AlreadyRunning` for a daemon that is already exiting; a live daemon holds
/// the lock for its whole lifetime, so it still wins.
const LOCK_ACQUIRE_TIMEOUT: Duration = Duration::from_millis(250);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(5);

/// Take a non-blocking exclusive `flock` on `path`.
///
/// The lock is released when the returned `File` is dropped (or the process
/// exits). A lock that stays held for [`LOCK_ACQUIRE_TIMEOUT`] maps to
/// [`SocketError::AlreadyRunning`]. The lock file is never unlinked while held.
fn acquire_lock(path: &Path) -> Result<File, SocketError> {
    let (file, _metadata) = fs_secure::open_regular_file(
        path,
        OpenRegularOptions {
            access: OpenMode::CreateReadWrite { mode: FILE_MODE },
            owner: OwnerPolicy::CurrentUser,
            mode: ModePolicy::Exact(FILE_MODE),
        },
    )
    .map_err(map_fs_error)?;

    fs_secure::lock_file_with_timeout(
        &file,
        path,
        FlockKind::Exclusive,
        LOCK_ACQUIRE_TIMEOUT,
        LOCK_RETRY_INTERVAL,
    )
    .map_err(map_fs_error)?;
    Ok(file)
}

fn map_fs_error(error: FsError) -> SocketError {
    match error {
        FsError::NotFound { path, source } | FsError::Io { path, source } => {
            SocketError::Io { path, source }
        }
        FsError::Insecure { path, kind } => SocketError::InsecurePath {
            path,
            detail: kind.to_string(),
        },
        FsError::Busy { .. } => SocketError::AlreadyRunning,
    }
}

/// Remove a socket left behind by a crashed daemon, but only after proving
/// that nobody is listening on it.
fn clear_stale_socket(path: &Path) -> Result<(), SocketError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(SocketError::io(path, err)),
    };

    if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
        return Err(SocketError::NotASocket(path.to_path_buf()));
    }
    if meta.uid() != current_uid() {
        return Err(SocketError::InsecurePath {
            path: path.to_path_buf(),
            detail: format!("socket owned by uid {}, not {}", meta.uid(), current_uid()),
        });
    }

    // A connection succeeding means a live daemon: never steal its socket.
    match UnixStream::connect(path) {
        Ok(_) => Err(SocketError::AlreadyRunning),
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
            fs::remove_file(path).map_err(|err| SocketError::io(path, err))
        }
        // Lost a race with a daemon that cleaned up after itself: nothing to do.
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(SocketError::io(path, err)),
    }
}

/// Restrict the freshly bound socket to the owner and return its inode.
fn set_socket_permissions(path: &Path) -> Result<u64, SocketError> {
    fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))
        .map_err(|err| SocketError::io(path, err))?;
    let meta = fs::symlink_metadata(path).map_err(|err| SocketError::io(path, err))?;
    Ok(meta.ino())
}

#[cfg(test)]
mod tests;
