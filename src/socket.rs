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
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// Subdirectory of `XDG_RUNTIME_DIR` that holds the socket, lock and session
/// token. Created with mode 0700.
pub const RUNTIME_SUBDIR: &str = "passmgr";
/// Name of the daemon's Unix socket inside the runtime directory.
pub const SOCKET_FILE: &str = "pmd.sock";
/// Name of the single-instance lock file inside the runtime directory.
pub const LOCK_FILE: &str = "pmd.lock";
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
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::InsecurePath { path, detail } => {
                write!(f, "refusing to use '{}': {detail}", path.display())
            }
            Self::PathTooLong { path, bytes } => write!(
                f,
                "socket path '{}' is {bytes} bytes; the limit is {MAX_SOCKET_PATH_BYTES}",
                path.display()
            ),
            Self::AlreadyRunning => f.write_str("another passmgr daemon is already running"),
            Self::NotASocket(path) => write!(
                f,
                "'{}' exists but is not a socket; refusing to remove it",
                path.display()
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

    /// Create the directory if needed, then require that it is a real 0700
    /// directory owned by the current user. Anything else is refused rather
    /// than repaired, so a pre-created directory cannot be taken over.
    fn ensure_dir(&self) -> Result<(), SocketError> {
        match fs::create_dir(&self.dir) {
            Ok(()) => {
                fs::set_permissions(&self.dir, fs::Permissions::from_mode(DIR_MODE))
                    .map_err(|err| SocketError::io(&self.dir, err))?;
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(SocketError::io(&self.dir, err)),
        }

        // symlink_metadata: never follow a symlink planted at the path.
        let meta =
            fs::symlink_metadata(&self.dir).map_err(|err| SocketError::io(&self.dir, err))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(SocketError::InsecurePath {
                path: self.dir.clone(),
                detail: "not a real directory".to_owned(),
            });
        }
        if meta.uid() != current_uid() {
            return Err(SocketError::InsecurePath {
                path: self.dir.clone(),
                detail: format!("owned by uid {}, not {}", meta.uid(), current_uid()),
            });
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != DIR_MODE {
            return Err(SocketError::InsecurePath {
                path: self.dir.clone(),
                detail: format!("mode is {mode:04o}, expected {DIR_MODE:04o}"),
            });
        }
        Ok(())
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

/// Take a non-blocking exclusive `flock` on `path`.
///
/// The lock is released when the returned `File` is dropped (or the process
/// exits). A second daemon gets `EWOULDBLOCK`, which maps to
/// [`SocketError::AlreadyRunning`].
fn acquire_lock(path: &Path) -> Result<File, SocketError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(FILE_MODE)
        .open(path)
        .map_err(|err| SocketError::io(path, err))?;

    // An old lock file could have been created with a wider mode; narrow it.
    file.set_permissions(fs::Permissions::from_mode(FILE_MODE))
        .map_err(|err| SocketError::io(path, err))?;

    // SAFETY: `as_raw_fd` returns a valid descriptor owned by `file`, which
    // outlives the call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Err(SocketError::AlreadyRunning);
        }
        return Err(SocketError::io(path, err));
    }
    Ok(file)
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

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn paths_in(temp: &tempfile::TempDir) -> RuntimePaths {
        // The parent stands in for $XDG_RUNTIME_DIR, which must already exist.
        let base = temp.path().join("run");
        fs::create_dir_all(&base).unwrap();
        RuntimePaths::at(base.join(RUNTIME_SUBDIR))
    }

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn default_dir_prefers_xdg_runtime_dir() {
        let dir = default_dir(Some(OsStr::new("/run/user/1234")));
        assert_eq!(dir, Path::new("/run/user/1234/passmgr"));
    }

    #[test]
    fn default_dir_falls_back_to_per_user_temp_dir() {
        let dir = default_dir(None);
        assert_eq!(dir.parent(), Some(env::temp_dir().as_path()));
        assert_eq!(
            dir.file_name().unwrap().to_string_lossy(),
            format!("passmgr-{}", current_uid())
        );

        // An empty XDG_RUNTIME_DIR is treated as unset.
        assert_eq!(default_dir(Some(OsStr::new(""))), dir);
    }

    #[test]
    fn bind_creates_private_dir_socket_and_lock() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        let daemon = DaemonSocket::bind_at(paths.clone()).unwrap();

        assert_eq!(mode_of(paths.dir()), 0o700, "runtime dir must be 0700");
        assert_eq!(mode_of(&paths.socket()), 0o600, "socket must be 0600");
        assert_eq!(mode_of(&paths.lock()), 0o600, "lock file must be 0600");
        assert!(
            fs::symlink_metadata(paths.socket())
                .unwrap()
                .file_type()
                .is_socket()
        );
        assert_eq!(daemon.paths(), &paths);

        // A client can reach the listener and exchange bytes.
        let mut client = connect_at(&paths).unwrap();
        let mut server = daemon.listener().accept().unwrap().0;
        client.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn an_existing_0700_directory_is_reused() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        fs::create_dir_all(paths.dir()).unwrap();
        fs::set_permissions(paths.dir(), fs::Permissions::from_mode(0o700)).unwrap();

        let _daemon = DaemonSocket::bind_at(paths.clone()).unwrap();
        assert_eq!(mode_of(paths.dir()), 0o700);
    }

    #[test]
    fn second_daemon_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        let first = DaemonSocket::bind_at(paths.clone()).unwrap();

        let second = DaemonSocket::bind_at(paths.clone());
        assert!(matches!(second, Err(SocketError::AlreadyRunning)));

        // The first daemon still owns a working socket.
        assert!(connect_at(&paths).is_ok());
        drop(first);
    }

    #[test]
    fn stale_socket_is_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        fs::create_dir_all(paths.dir()).unwrap();
        fs::set_permissions(paths.dir(), fs::Permissions::from_mode(0o700)).unwrap();

        // Bind and drop a bare listener: the file stays, nobody listens.
        let stale = UnixListener::bind(paths.socket()).unwrap();
        drop(stale);
        assert!(paths.socket().exists(), "test needs a stale socket file");

        let daemon = DaemonSocket::bind_at(paths.clone()).unwrap();
        assert!(connect_at(&paths).is_ok());
        drop(daemon);
    }

    #[test]
    fn live_socket_without_a_lock_is_not_stolen() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        fs::create_dir_all(paths.dir()).unwrap();
        fs::set_permissions(paths.dir(), fs::Permissions::from_mode(0o700)).unwrap();

        // A live listener but no lock file, as if the lock were removed.
        let live = UnixListener::bind(paths.socket()).unwrap();

        let attempt = DaemonSocket::bind_at(paths.clone());
        assert!(matches!(attempt, Err(SocketError::AlreadyRunning)));
        assert!(
            paths.socket().exists(),
            "a live socket must not be unlinked"
        );

        // The original listener is untouched and still accepts.
        assert!(connect_at(&paths).is_ok());
        let _ = live.accept().unwrap();
    }

    #[test]
    fn non_socket_at_the_path_is_left_alone() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        fs::create_dir_all(paths.dir()).unwrap();
        fs::set_permissions(paths.dir(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(paths.socket(), b"do not delete me").unwrap();

        let attempt = DaemonSocket::bind_at(paths.clone());
        assert!(matches!(attempt, Err(SocketError::NotASocket(_))));
        assert_eq!(fs::read(paths.socket()).unwrap(), b"do not delete me");
    }

    #[test]
    fn symlinked_runtime_dir_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let attempt = DaemonSocket::bind_at(RuntimePaths::at(&link));
        assert!(matches!(attempt, Err(SocketError::InsecurePath { .. })));
        assert!(!real.join(SOCKET_FILE).exists());
    }

    #[test]
    fn group_readable_runtime_dir_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        fs::create_dir_all(paths.dir()).unwrap();
        fs::set_permissions(paths.dir(), fs::Permissions::from_mode(0o750)).unwrap();

        let attempt = DaemonSocket::bind_at(paths.clone());
        match attempt {
            Err(SocketError::InsecurePath { detail, .. }) => {
                assert!(
                    detail.contains("0750"),
                    "detail should name the mode: {detail}"
                );
            }
            other => panic!("expected InsecurePath, got {other:?}"),
        }
        assert!(!paths.socket().exists());
    }

    #[test]
    fn overlong_socket_path_is_rejected_before_any_io() {
        let temp = tempfile::tempdir().unwrap();
        let long = temp.path().join("x".repeat(120));
        let attempt = DaemonSocket::bind_at(RuntimePaths::at(&long));
        match attempt {
            Err(SocketError::PathTooLong { bytes, .. }) => {
                assert!(bytes > MAX_SOCKET_PATH_BYTES);
            }
            other => panic!("expected PathTooLong, got {other:?}"),
        }
        assert!(!long.exists(), "no directory should be created");
    }

    #[test]
    fn dropping_the_daemon_removes_the_socket_and_releases_the_lock() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        let daemon = DaemonSocket::bind_at(paths.clone()).unwrap();
        assert!(paths.socket().exists());

        drop(daemon);
        assert!(
            !paths.socket().exists(),
            "clean shutdown removes the socket"
        );
        assert!(paths.lock().exists(), "the lock file stays behind");

        // The lock is released, so a new daemon can start.
        let _again = DaemonSocket::bind_at(paths.clone()).unwrap();
    }

    #[test]
    fn connect_without_a_daemon_reports_not_running() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        assert!(matches!(connect_at(&paths), Err(SocketError::NotRunning)));

        // A stale socket file is also "not running", not an I/O failure.
        fs::create_dir_all(paths.dir()).unwrap();
        fs::set_permissions(paths.dir(), fs::Permissions::from_mode(0o700)).unwrap();
        drop(UnixListener::bind(paths.socket()).unwrap());
        assert!(matches!(connect_at(&paths), Err(SocketError::NotRunning)));
    }

    #[test]
    fn socket_path_is_short_enough_for_the_platform() {
        // Guard the constant itself: the default Linux limit is 108 bytes
        // including the NUL and macOS is 104.
        assert_eq!(MAX_SOCKET_PATH_BYTES, 104);
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        let bytes = paths.socket().as_os_str().as_bytes().len();
        assert!(bytes <= MAX_SOCKET_PATH_BYTES);
    }

    #[test]
    fn lock_is_released_when_the_process_that_held_it_dies() {
        // flock is released by the kernel on process exit. Simulate the
        // "holder dies" side with a fork-free proxy: a second File handle in
        // this process conflicts while the first is open (flock is per open
        // file description), and succeeds once it is dropped.
        let temp = tempfile::tempdir().unwrap();
        let lock_path = temp.path().join("pmd.lock");
        let held = acquire_lock(&lock_path).unwrap();
        assert!(matches!(
            acquire_lock(&lock_path),
            Err(SocketError::AlreadyRunning)
        ));
        drop(held);
        assert!(acquire_lock(&lock_path).is_ok());
    }

    fn current_gid() -> u32 {
        // SAFETY: getegid has no preconditions and cannot fail.
        unsafe { libc::getegid() }
    }

    #[test]
    fn peer_credentials_report_the_current_user() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        let daemon = DaemonSocket::bind_at(paths.clone()).unwrap();

        let _client = connect_at(&paths).unwrap();
        let (stream, peer) = daemon.accept_peer().unwrap();
        assert_eq!(peer.uid(), current_uid());
        assert_eq!(peer.gid(), current_gid());
        peer.verify(current_uid()).unwrap();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(peer.pid(), Some(std::process::id() as i32));
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        assert_eq!(peer.pid(), None, "getpeereid does not report a pid");

        // The free function and the accept helper agree.
        assert_eq!(peer_credentials(&stream).unwrap(), peer);

        // A check of our own uid passed, so normal traffic still works.
        drop(stream);
        let _client2 = connect_at(&paths).unwrap();
        let _ = daemon.accept_peer().unwrap();
    }

    #[test]
    fn accept_peer_rejects_a_foreign_uid_and_closes_the_connection() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths_in(&temp);
        let daemon = DaemonSocket::bind_at(paths.clone()).unwrap();

        // The client connects and writes a request-shaped message. The daemon
        // must reject before reading any of it.
        let mut client = connect_at(&paths).unwrap();
        client.write_all(b"{\"version\":1}").unwrap();

        let foreign_uid = current_uid().wrapping_add(1);
        match daemon.accept_peer_expecting(foreign_uid) {
            Err(SocketError::PeerRejected { expected, actual }) => {
                assert_eq!(expected, foreign_uid);
                assert_eq!(actual, current_uid());
            }
            other => panic!("expected PeerRejected, got {other:?}"),
        }

        // The rejected stream was dropped without a reply: the client sees
        // end-of-stream (or a reset), never a response.
        let mut buf = [0u8; 1];
        match client.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => panic!("rejected peer must not receive a reply, got {n} bytes"),
            Err(err) => assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ),
                "unexpected error after rejection: {err}"
            ),
        }
    }

    #[test]
    fn verify_rejects_a_different_uid_with_a_clear_message() {
        let peer = PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(42),
        };
        assert!(peer.verify(1000).is_ok());

        let err = peer.verify(1001).unwrap_err();
        assert!(matches!(
            err,
            SocketError::PeerRejected {
                expected: 1001,
                actual: 1000
            }
        ));
        let message = err.to_string();
        assert!(message.contains("uid 1000"), "message: {message}");
        assert!(message.contains("uid 1001"), "message: {message}");
    }
}
