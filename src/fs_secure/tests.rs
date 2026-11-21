use std::error::Error as _;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::*;

fn write_with_mode(path: &Path, contents: &[u8], mode: u32) {
    fs::write(path, contents).expect("write test file");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod test file");
}

#[test]
fn open_regular_file_reads_valid_0600_file_and_reports_not_found() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("absent");
    let err = open_regular_file(
        &missing,
        OpenRegularOptions {
            access: OpenMode::ReadOnly,
            owner: OwnerPolicy::CurrentUser,
            mode: ModePolicy::Exact(PRIVATE_FILE_MODE),
        },
    )
    .expect_err("missing file must fail");
    assert!(matches!(err, FsError::NotFound { .. }), "{err:?}");

    let path = dir.path().join("secret");
    write_with_mode(&path, b"payload", 0o600);
    let (mut file, meta) = open_regular_file(
        &path,
        OpenRegularOptions {
            access: OpenMode::ReadOnly,
            owner: OwnerPolicy::CurrentUser,
            mode: ModePolicy::Exact(PRIVATE_FILE_MODE),
        },
    )
    .expect("open 0600 file");
    assert!(meta.is_file());
    assert_eq!(meta.mode() & 0o777, 0o600);
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("read");
    assert_eq!(buf, b"payload");
}

#[test]
fn open_regular_file_refuses_symlinks_across_all_open_modes() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("target");
    write_with_mode(&target, b"real", 0o600);
    let link = dir.path().join("link");
    symlink(&target, &link).expect("symlink");

    let dangling_target = dir.path().join("nonexistent");
    let dangling = dir.path().join("dangling");
    symlink(&dangling_target, &dangling).expect("dangling symlink");

    for path in [&link, &dangling] {
        for access in [
            OpenMode::ReadOnly,
            OpenMode::CreateReadWrite,
            OpenMode::CreateReadAppend,
        ] {
            let err = open_regular_file(
                path,
                OpenRegularOptions {
                    access,
                    owner: OwnerPolicy::CurrentUser,
                    mode: ModePolicy::Exact(PRIVATE_FILE_MODE),
                },
            )
            .expect_err("symlink must be refused");
            assert!(
                matches!(
                    err,
                    FsError::Insecure {
                        kind: InsecureKind::Symlink,
                        ..
                    }
                ),
                "{err:?}"
            );
        }
    }
    assert_eq!(fs::read(&target).expect("target untouched"), b"real");
    assert!(!dangling_target.exists(), "dangling target not created");
}

#[test]
fn open_regular_file_refuses_fifo_without_blocking() {
    let dir = TempDir::new().expect("tempdir");
    let fifo = dir.path().join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo failed");

    for access in [
        OpenMode::ReadOnly,
        OpenMode::CreateReadWrite,
        OpenMode::CreateReadAppend,
    ] {
        let fifo_path = fifo.clone();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let result = open_regular_file(
                &fifo_path,
                OpenRegularOptions {
                    access,
                    owner: OwnerPolicy::Any,
                    mode: ModePolicy::Any,
                },
            )
            .map(|_| ());
            let _ = tx.send(result);
        });
        let result = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("opening a FIFO must not block");
        let err = result.expect_err("FIFO must be refused");
        assert!(
            matches!(
                err,
                FsError::Insecure {
                    kind: InsecureKind::NotRegularFile,
                    ..
                }
            ),
            "{err:?}"
        );
    }
    assert!(fifo.exists(), "FIFO must not be removed");
}

#[test]
fn open_regular_file_refuses_directory_across_all_open_modes() {
    let dir = TempDir::new().expect("tempdir");
    let subdir = dir.path().join("subdir");
    fs::create_dir(&subdir).expect("create subdir");

    for access in [
        OpenMode::ReadOnly,
        OpenMode::CreateReadWrite,
        OpenMode::CreateReadAppend,
    ] {
        let err = open_regular_file(
            &subdir,
            OpenRegularOptions {
                access,
                owner: OwnerPolicy::Any,
                mode: ModePolicy::Any,
            },
        )
        .expect_err("directory must be refused");
        assert!(
            matches!(
                err,
                FsError::Insecure {
                    kind: InsecureKind::NotRegularFile,
                    ..
                }
            ),
            "{err:?}"
        );
    }
}

#[test]
fn open_regular_file_enforces_mode_policies_without_repairing() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("token");
    write_with_mode(&path, b"tok", 0o400);

    // 0400 is accepted by NoGroupWorld and Any, refused by Exact(0600).
    assert!(
        open_regular_file(
            &path,
            OpenRegularOptions {
                access: OpenMode::ReadOnly,
                owner: OwnerPolicy::CurrentUser,
                mode: ModePolicy::NoGroupWorld,
            },
        )
        .is_ok()
    );
    let err = open_regular_file(
        &path,
        OpenRegularOptions {
            access: OpenMode::ReadOnly,
            owner: OwnerPolicy::CurrentUser,
            mode: ModePolicy::Exact(0o600),
        },
    )
    .expect_err("0400 must fail Exact(0600)");
    assert!(
        matches!(
            err,
            FsError::Insecure {
                kind: InsecureKind::Permissions {
                    mode: 0o400,
                    expected: ModePolicy::Exact(0o600),
                },
                ..
            }
        ),
        "{err:?}"
    );

    // Loose modes (0640, 0604, 0644) fail both Exact(0600) and NoGroupWorld
    // and are never repaired on disk.
    for loose in [0o640, 0o604, 0o644] {
        fs::set_permissions(&path, fs::Permissions::from_mode(loose)).expect("chmod loose");
        for policy in [ModePolicy::Exact(0o600), ModePolicy::NoGroupWorld] {
            let err = open_regular_file(
                &path,
                OpenRegularOptions {
                    access: OpenMode::CreateReadWrite,
                    owner: OwnerPolicy::CurrentUser,
                    mode: policy,
                },
            )
            .expect_err("loose mode must be refused");
            assert!(
                matches!(
                    err,
                    FsError::Insecure {
                        kind: InsecureKind::Permissions { mode, expected },
                        ..
                    } if mode == loose && expected == policy
                ),
                "{err:?}"
            );
            assert_eq!(
                fs::metadata(&path).expect("stat").mode() & 0o777,
                loose,
                "refused file permissions must never be repaired"
            );
        }
        // ModePolicy::Any still opens loose files (used for vault warn-only path).
        assert!(
            open_regular_file(
                &path,
                OpenRegularOptions {
                    access: OpenMode::ReadOnly,
                    owner: OwnerPolicy::CurrentUser,
                    mode: ModePolicy::Any,
                },
            )
            .is_ok()
        );
    }
}

#[test]
fn open_regular_file_enforces_owner_policy() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("owned");
    write_with_mode(&path, b"data", 0o600);
    let foreign_uid = current_uid().wrapping_add(1);

    let err = open_regular_file_for_uid(
        &path,
        OpenRegularOptions {
            access: OpenMode::ReadOnly,
            owner: OwnerPolicy::CurrentUser,
            mode: ModePolicy::Exact(0o600),
        },
        foreign_uid,
    )
    .expect_err("foreign owner must be refused");
    assert!(
        matches!(
            err,
            FsError::Insecure {
                kind: InsecureKind::WrongOwner {
                    expected_uid,
                    actual_uid,
                },
                ..
            } if expected_uid == foreign_uid && actual_uid == current_uid()
        ),
        "{err:?}"
    );

    assert!(
        open_regular_file_for_uid(
            &path,
            OpenRegularOptions {
                access: OpenMode::ReadOnly,
                owner: OwnerPolicy::Any,
                mode: ModePolicy::Exact(0o600),
            },
            foreign_uid,
        )
        .is_ok()
    );
}

#[test]
fn open_regular_file_creates_missing_file_with_0600_in_write_and_append_modes() {
    let dir = TempDir::new().expect("tempdir");
    for (name, access) in [
        ("rw.lock", OpenMode::CreateReadWrite),
        ("append.jsonl", OpenMode::CreateReadAppend),
    ] {
        let path = dir.path().join(name);
        let (_file, meta) = open_regular_file(
            &path,
            OpenRegularOptions {
                access,
                owner: OwnerPolicy::CurrentUser,
                mode: ModePolicy::Exact(PRIVATE_FILE_MODE),
            },
        )
        .expect("create private file");
        assert!(meta.is_file());
        assert_eq!(meta.mode() & 0o777, PRIVATE_FILE_MODE);
        assert_eq!(meta.uid(), current_uid());
    }
}

#[test]
fn open_regular_file_sets_cloexec_across_all_open_modes() {
    let dir = TempDir::new().expect("tempdir");
    let existing = dir.path().join("existing");
    write_with_mode(&existing, b"data", PRIVATE_FILE_MODE);

    for (path, access) in [
        (existing, OpenMode::ReadOnly),
        (dir.path().join("rw.lock"), OpenMode::CreateReadWrite),
        (dir.path().join("append.jsonl"), OpenMode::CreateReadAppend),
    ] {
        let (file, _) = open_regular_file(
            &path,
            OpenRegularOptions {
                access,
                owner: OwnerPolicy::CurrentUser,
                mode: ModePolicy::Exact(PRIVATE_FILE_MODE),
            },
        )
        .expect("open regular file");
        // SAFETY: `file` owns a live descriptor for the duration of this call.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        assert!(
            flags >= 0,
            "fcntl(F_GETFD) failed: {}",
            io::Error::last_os_error()
        );
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "FD_CLOEXEC must be set for {access:?}"
        );
    }
}

#[test]
fn private_dir_validates_missing_and_creates_non_recursively_or_recursively() {
    let root = TempDir::new().expect("tempdir");

    // Missing directory returns Ok(false) without creating it.
    let runtime = root.path().join("runtime");
    assert!(!validate_private_dir(&runtime, ModePolicy::Exact(PRIVATE_DIR_MODE)).expect("ok"));
    assert!(!runtime.exists());

    // Non-recursive creation refuses when a parent is missing.
    let nested_nonrec = root.path().join("absent-parent").join("runtime");
    let err = ensure_private_dir(&nested_nonrec, false, ModePolicy::Exact(PRIVATE_DIR_MODE))
        .expect_err("non-recursive must not create missing parent");
    assert!(matches!(err, FsError::NotFound { .. }), "{err:?}");
    assert!(!root.path().join("absent-parent").exists());

    // Non-recursive creation creates a 0700 dir when parent exists and is idempotent.
    ensure_private_dir(&runtime, false, ModePolicy::Exact(PRIVATE_DIR_MODE))
        .expect("create runtime dir");
    assert_eq!(
        fs::symlink_metadata(&runtime).expect("lstat").mode() & 0o777,
        PRIVATE_DIR_MODE
    );
    assert!(validate_private_dir(&runtime, ModePolicy::Exact(PRIVATE_DIR_MODE)).expect("ok"));
    ensure_private_dir(&runtime, false, ModePolicy::Exact(PRIVATE_DIR_MODE))
        .expect("idempotent ensure");

    // Recursive creation creates nested 0700 directories and re-validates.
    let nested_rec = root.path().join("state").join("passmgr").join("audit");
    ensure_private_dir(&nested_rec, true, ModePolicy::NoGroupWorld).expect("recursive create");
    assert_eq!(
        fs::symlink_metadata(&nested_rec).expect("lstat").mode() & 0o777,
        PRIVATE_DIR_MODE
    );
    assert_eq!(
        fs::symlink_metadata(root.path().join("state"))
            .expect("parent lstat")
            .mode()
            & 0o777,
        PRIVATE_DIR_MODE
    );
    assert!(validate_private_dir(&nested_rec, ModePolicy::NoGroupWorld).expect("ok"));
}

#[test]
fn private_dir_refuses_symlinks_files_wrong_owner_and_loose_modes_without_repairing() {
    let root = TempDir::new().expect("tempdir");

    // Symlink pointing at a valid 0700 directory is refused.
    let real = root.path().join("real");
    ensure_private_dir(&real, false, ModePolicy::Exact(PRIVATE_DIR_MODE)).expect("real dir");
    let link = root.path().join("link");
    symlink(&real, &link).expect("symlink dir");
    for result in [
        validate_private_dir(&link, ModePolicy::Exact(PRIVATE_DIR_MODE)).map(|_| ()),
        ensure_private_dir(&link, false, ModePolicy::Exact(PRIVATE_DIR_MODE)),
        ensure_private_dir(&link, true, ModePolicy::NoGroupWorld),
    ] {
        let err = result.expect_err("symlink dir must be refused");
        assert!(
            matches!(
                err,
                FsError::Insecure {
                    kind: InsecureKind::Symlink,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    // Regular file at directory path is refused as NotADirectory.
    let file_path = root.path().join("not-a-dir");
    write_with_mode(&file_path, b"x", 0o700);
    let err = ensure_private_dir(&file_path, false, ModePolicy::Exact(PRIVATE_DIR_MODE))
        .expect_err("file at dir path must be refused");
    assert!(
        matches!(
            err,
            FsError::Insecure {
                kind: InsecureKind::NotADirectory,
                ..
            }
        ),
        "{err:?}"
    );

    // Loose modes (0750, 0755) are refused without repairing.
    for loose in [0o750, 0o755] {
        fs::set_permissions(&real, fs::Permissions::from_mode(loose)).expect("chmod loose");
        for (recursive, policy) in [
            (false, ModePolicy::Exact(PRIVATE_DIR_MODE)),
            (true, ModePolicy::NoGroupWorld),
        ] {
            let err = ensure_private_dir(&real, recursive, policy)
                .expect_err("loose dir must be refused");
            assert!(
                matches!(
                    err,
                    FsError::Insecure {
                        kind: InsecureKind::Permissions { mode, expected },
                        ..
                    } if mode == loose && expected == policy
                ),
                "{err:?}"
            );
            assert_eq!(
                fs::symlink_metadata(&real).expect("lstat").mode() & 0o777,
                loose,
                "refused directory permissions must never be repaired"
            );
        }
    }

    // Restore 0700 and verify wrong-owner refusal.
    fs::set_permissions(&real, fs::Permissions::from_mode(PRIVATE_DIR_MODE)).expect("restore 0700");
    let foreign_uid = current_uid().wrapping_add(1);
    let err = validate_private_dir_for_uid(&real, ModePolicy::Exact(PRIVATE_DIR_MODE), foreign_uid)
        .expect_err("foreign owner dir must be refused");
    assert!(
        matches!(
            err,
            FsError::Insecure {
                kind: InsecureKind::WrongOwner {
                    expected_uid,
                    actual_uid,
                },
                ..
            } if expected_uid == foreign_uid && actual_uid == current_uid()
        ),
        "{err:?}"
    );
}

#[test]
fn timed_flock_enforces_shared_exclusive_contention_and_release_on_drop() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("state.lock");
    let open_rw = || {
        open_regular_file(
            &path,
            OpenRegularOptions {
                access: OpenMode::CreateReadWrite,
                owner: OwnerPolicy::CurrentUser,
                mode: ModePolicy::Exact(PRIVATE_FILE_MODE),
            },
        )
        .expect("open lock file")
        .0
    };

    // Shared locks coexist across independent open file descriptions.
    let shared_a = open_rw();
    let shared_b = open_rw();
    lock_file_with_timeout(
        &shared_a,
        &path,
        FlockKind::Shared,
        Duration::from_millis(50),
        Duration::from_millis(5),
    )
    .expect("first shared lock");
    lock_file_with_timeout(
        &shared_b,
        &path,
        FlockKind::Shared,
        Duration::from_millis(50),
        Duration::from_millis(5),
    )
    .expect("second shared lock");

    // An exclusive lock times out with Busy while shared locks are held.
    let waiter = open_rw();
    let started = Instant::now();
    let err = lock_file_with_timeout(
        &waiter,
        &path,
        FlockKind::Exclusive,
        Duration::from_millis(40),
        Duration::from_millis(5),
    )
    .expect_err("exclusive lock must block on shared locks");
    assert!(matches!(err, FsError::Busy { .. }), "{err:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "timeout elapsed too early: {:?}",
        started.elapsed()
    );

    // Dropping both shared locks allows exclusive acquisition.
    drop(shared_a);
    drop(shared_b);
    lock_file_with_timeout(
        &waiter,
        &path,
        FlockKind::Exclusive,
        Duration::from_millis(50),
        Duration::from_millis(5),
    )
    .expect("exclusive lock after shared release");

    // While exclusive is held, both shared and exclusive attempts time out with Busy.
    let contender = open_rw();
    for kind in [FlockKind::Shared, FlockKind::Exclusive] {
        let started = Instant::now();
        let err = lock_file_with_timeout(
            &contender,
            &path,
            kind,
            Duration::from_millis(35),
            Duration::from_millis(5),
        )
        .expect_err("contended lock must return Busy");
        assert!(matches!(err, FsError::Busy { .. }), "{err:?}");
        assert!(started.elapsed() >= Duration::from_millis(35));
    }

    // Confirm immediate Busy while held (zero timeout does not block).
    let err = lock_file_with_timeout(
        &contender,
        &path,
        FlockKind::Exclusive,
        Duration::ZERO,
        Duration::from_millis(5),
    )
    .expect_err("contended lock with zero timeout must return Busy");
    assert!(matches!(err, FsError::Busy { .. }), "{err:?}");

    // Synchronize the waiter thread before releasing `holder` so contention
    // and post-release acquisition are proven without any fixed sleep.
    let holder = waiter;
    let waiter_path = path.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (acquired_tx, acquired_rx) = mpsc::channel();
    let acquirer = thread::spawn(move || {
        let busy = lock_file_with_timeout(
            &contender,
            &waiter_path,
            FlockKind::Exclusive,
            Duration::ZERO,
            Duration::from_millis(5),
        );
        assert!(matches!(busy, Err(FsError::Busy { .. })), "{busy:?}");
        started_tx.send(()).expect("signal waiter ready");
        let acquired = lock_file_with_timeout(
            &contender,
            &waiter_path,
            FlockKind::Exclusive,
            Duration::from_secs(5),
            Duration::from_millis(5),
        );
        acquired_tx.send(acquired).expect("send acquire result");
    });

    started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter thread started");
    assert!(
        matches!(acquired_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "lock must not be acquired while holder is alive"
    );
    drop(holder);
    acquired_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter must finish after holder drops")
        .expect("retry must acquire lock once holder drops");
    acquirer.join().expect("join acquirer");
    assert!(path.exists(), "lock file must stay on disk");
}

#[test]
fn atomic_write_private_creates_replaces_0600_and_leaves_no_temp_files() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("secret.dat");

    atomic_write_private(&target, b"first-version", ".atomic-", ".tmp").expect("first write");
    let first_meta = fs::symlink_metadata(&target).expect("stat first");
    assert!(first_meta.is_file());
    assert_eq!(first_meta.mode() & 0o777, PRIVATE_FILE_MODE);
    assert_eq!(first_meta.uid(), current_uid());
    assert_eq!(fs::read(&target).expect("read first"), b"first-version");

    // Replacing an existing file atomically swaps in a fresh 0600 inode.
    atomic_write_private(&target, b"second-version", ".atomic-", ".tmp").expect("second write");
    let second_meta = fs::symlink_metadata(&target).expect("stat second");
    assert_eq!(second_meta.mode() & 0o777, PRIVATE_FILE_MODE);
    assert_ne!(
        first_meta.ino(),
        second_meta.ino(),
        "atomic rename must replace the inode rather than overwrite in place"
    );
    assert_eq!(fs::read(&target).expect("read second"), b"second-version");

    // Only the target file remains in the directory; zero stray temp files.
    let entries: Vec<_> = fs::read_dir(dir.path())
        .expect("read_dir")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("secret.dat")]);

    // Writing into a missing parent directory fails with NotFound.
    let missing_parent = dir.path().join("no-such-dir").join("secret.dat");
    let err = atomic_write_private(&missing_parent, b"nope", ".atomic-", ".tmp")
        .expect_err("missing parent must fail");
    assert!(matches!(err, FsError::NotFound { .. }), "{err:?}");
}

#[test]
fn fs_error_display_escapes_hidden_and_control_characters_in_paths() {
    let hostile = PathBuf::from("/tmp/evil\u{1b}[2K\u{7}\u{202e}name");
    let samples = [
        FsError::NotFound {
            path: hostile.clone(),
            source: io::Error::new(io::ErrorKind::NotFound, "missing"),
        },
        FsError::Insecure {
            path: hostile.clone(),
            kind: InsecureKind::Permissions {
                mode: 0o644,
                expected: ModePolicy::Exact(0o600),
            },
        },
        FsError::Busy {
            path: hostile.clone(),
        },
        FsError::Io {
            path: hostile,
            source: io::Error::other("disk error"),
        },
    ];

    assert!(samples[0].source().is_some());
    assert!(samples[1].source().is_none());
    assert!(samples[2].source().is_none());
    assert!(samples[3].source().is_some());

    for err in &samples {
        let rendered = err.to_string();
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
    assert!(samples[1].to_string().contains("0644"));
    assert!(samples[1].to_string().contains("0600"));
}
