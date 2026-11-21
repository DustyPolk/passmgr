use super::*;
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::sync::mpsc;
use std::thread;

#[cfg(target_os = "linux")]
use crate::test_poll::{current_tid, wait_for_thread_to_sleep};

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
    symlink(&real, &link).unwrap();

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
fn symlinked_lock_file_is_refused_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_in(&temp);
    fs::create_dir_all(paths.dir()).unwrap();
    fs::set_permissions(paths.dir(), fs::Permissions::from_mode(0o700)).unwrap();

    let target = temp.path().join("target");
    fs::write(&target, b"do not touch").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    symlink(&target, paths.lock()).unwrap();

    let attempt = DaemonSocket::bind_at(paths.clone());
    assert!(
        matches!(attempt, Err(SocketError::InsecurePath { .. })),
        "expected InsecurePath, got {attempt:?}"
    );
    assert_eq!(fs::read(&target).unwrap(), b"do not touch");
    assert_eq!(
        mode_of(&target),
        0o644,
        "symlink target permissions must never be modified"
    );
    assert!(
        fs::symlink_metadata(paths.lock())
            .unwrap()
            .file_type()
            .is_symlink(),
        "symlink at lock path must remain untouched"
    );
    assert!(!paths.socket().exists());

    // A dangling symlink at the lock path must also be refused without
    // creating its target.
    fs::remove_file(paths.lock()).unwrap();
    let dangling_target = temp.path().join("never-created");
    symlink(&dangling_target, paths.lock()).unwrap();
    let attempt = DaemonSocket::bind_at(paths.clone());
    assert!(
        matches!(attempt, Err(SocketError::InsecurePath { .. })),
        "expected InsecurePath, got {attempt:?}"
    );
    assert!(
        !dangling_target.exists(),
        "dangling symlink target must not be created"
    );
}

#[test]
fn lock_file_refuses_fifo_and_symlink_and_narrows_loose_regular_file() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_in(&temp);
    fs::create_dir_all(paths.dir()).unwrap();
    fs::set_permissions(paths.dir(), fs::Permissions::from_mode(0o700)).unwrap();

    // (a) A FIFO at the lock path is refused without blocking.
    let status = std::process::Command::new("mkfifo")
        .arg(paths.lock())
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo failed");

    let (tx, rx) = mpsc::channel();
    let fifo_paths = paths.clone();
    thread::spawn(move || {
        let _ = tx.send(DaemonSocket::bind_at(fifo_paths));
    });
    let attempt = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("opening a FIFO at the lock path must not block");
    assert!(
        matches!(attempt, Err(SocketError::InsecurePath { .. })),
        "expected InsecurePath, got {attempt:?}"
    );
    assert!(paths.lock().exists(), "FIFO at lock path must remain");
    assert!(!paths.socket().exists());

    // (b) A symlink at the lock path is refused untouched (never chmodded).
    fs::remove_file(paths.lock()).unwrap();
    let target = temp.path().join("loose-target");
    fs::write(&target, b"keep-me").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    symlink(&target, paths.lock()).unwrap();

    let attempt = DaemonSocket::bind_at(paths.clone());
    assert!(
        matches!(attempt, Err(SocketError::InsecurePath { .. })),
        "expected InsecurePath, got {attempt:?}"
    );
    assert_eq!(
        mode_of(&target),
        0o644,
        "symlink target must never be chmodded"
    );
    assert!(
        fs::symlink_metadata(paths.lock())
            .unwrap()
            .file_type()
            .is_symlink(),
        "symlink at lock path must remain untouched"
    );
    assert!(!paths.socket().exists());

    // (c) An existing regular lock file with loose mode (0644) is narrowed to
    // 0600 on the verified descriptor rather than refused.
    fs::remove_file(paths.lock()).unwrap();
    fs::write(paths.lock(), b"").unwrap();
    fs::set_permissions(paths.lock(), fs::Permissions::from_mode(0o644)).unwrap();

    let daemon = DaemonSocket::bind_at(paths.clone()).expect("loose regular lock file is narrowed");
    assert_eq!(
        mode_of(&paths.lock()),
        0o600,
        "verified regular lock file permissions must be narrowed to 0600"
    );
    assert!(paths.socket().exists());
    drop(daemon);
}

#[test]
fn socket_error_display_escapes_hidden_characters_in_paths() {
    let hostile = PathBuf::from("/tmp/evil\u{1b}[2K\u{7}\u{202e}pmd.sock");
    let errors = [
        SocketError::Io {
            path: hostile.clone(),
            source: io::Error::other("disk error"),
        },
        SocketError::InsecurePath {
            path: hostile.clone(),
            detail: "symbolic link".into(),
        },
        SocketError::PathTooLong {
            path: hostile.clone(),
            bytes: 120,
        },
        SocketError::NotASocket(hostile),
    ];

    for error in &errors {
        let rendered = error.to_string();
        assert!(rendered.contains(r"\u{1b}"), "{rendered:?}");
        assert!(rendered.contains(r"\u{7}"), "{rendered:?}");
        assert!(rendered.contains(r"\u{202e}"), "{rendered:?}");
        assert!(
            !rendered.contains('\u{1b}')
                && !rendered.contains('\u{7}')
                && !rendered.contains('\u{202e}'),
            "{rendered:?}"
        );
    }
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

#[test]
#[cfg(target_os = "linux")]
fn a_lock_released_while_the_caller_waits_is_acquired() {
    // A daemon that has just exited may take a few milliseconds to release
    // its `flock` (the descriptor can be closed on another thread, which
    // defers the final fput). Acquiring must wait that window out rather
    // than report a daemon that is no longer there.
    let temp = tempfile::tempdir().unwrap();
    let lock_path = temp.path().join("pmd.lock");
    let held = acquire_lock(&lock_path).unwrap();

    let (tid_tx, tid_rx) = mpsc::channel();
    let contender_path = lock_path.clone();
    let contender = thread::spawn(move || {
        tid_tx.send(current_tid()).unwrap();
        acquire_lock(&contender_path)
    });

    // The pause between flock retries is the contender's only sleep, so
    // seeing it there proves its first attempt was refused and it is waiting.
    // If it gives up before the release below, the join reports the failure.
    wait_for_thread_to_sleep(
        tid_rx.recv().unwrap(),
        LOCK_ACQUIRE_TIMEOUT,
        "the contender never waited between lock retries",
    );
    drop(held);
    assert!(
        contender.join().unwrap().is_ok(),
        "a lock released while the caller waits must be acquired"
    );
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
