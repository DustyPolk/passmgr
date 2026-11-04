use super::*;

fn inherited() -> Vec<(OsString, OsString)> {
    inherited_env([
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("HOME"), OsString::from("/tmp")),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("LD_PRELOAD"), OsString::from("/tmp/x.so")),
        (OsString::from("UNRELATED"), OsString::from("value")),
        (
            OsString::from("PASSMGR_RUNNER_TEST_ONLY"),
            OsString::from("leaked-if-inherited"),
        ),
    ])
}

fn secret_env(name: &str, secret: &str) -> Vec<(String, Zeroizing<String>)> {
    vec![(name.to_owned(), Zeroizing::new(secret.to_owned()))]
}

fn collect(
    argv: &[&str],
    env_name: &str,
    secret: &str,
) -> (Vec<RunFrame>, Result<RunFinished, RunError>) {
    collect_with(argv, env_name, secret, Path::new("/"), Limits::NONE)
}

fn collect_with(
    argv: &[&str],
    env_name: &str,
    secret: &str,
    cwd: &Path,
    limits: Limits,
) -> (Vec<RunFrame>, Result<RunFinished, RunError>) {
    let argv: Vec<String> = argv.iter().map(|arg| (*arg).to_string()).collect();
    let env = secret_env(env_name, secret);
    let cancel = AtomicBool::new(false);
    let stop = Stop::on_cancel(&cancel);
    let mut frames = Vec::new();
    let result = execute(
        Path::new(&argv[0]),
        &argv[1..],
        &env,
        &[],
        cwd,
        &inherited(),
        limits,
        &stop,
        |frame| {
            frames.push(frame);
            Ok(())
        },
    );
    (frames, result)
}

fn stdout_bytes(frames: &[RunFrame]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for frame in frames {
        if let RunFrame::Stdout(data) = frame {
            bytes.extend_from_slice(data);
        }
    }
    bytes
}

fn stderr_bytes(frames: &[RunFrame]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for frame in frames {
        if let RunFrame::Stderr(data) = frame {
            bytes.extend_from_slice(data);
        }
    }
    bytes
}

#[test]
fn the_inherited_environment_is_a_small_allowlist() {
    let names: Vec<String> = inherited()
        .into_iter()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["PATH", "HOME", "LC_ALL"]);
}

#[test]
fn loader_and_shell_hook_names_are_denied() {
    for name in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "IFS",
        "PATH",
        "HOME",
        "SHELLOPTS",
        "PS4",
        "GCONV_PATH",
        "GLIBC_TUNABLES",
        "LOCPATH",
    ] {
        assert!(denied_env_name(name), "{name} must be denied");
    }
    for name in ["API_KEY", "GH_TOKEN", "LANG", "TZ", "LC_ALL", "X"] {
        assert!(!denied_env_name(name), "{name} must be allowed");
    }
}

#[test]
fn the_child_sees_the_injected_variable() {
    let secret = "unit-test-secret-1234";
    let (frames, result) = collect(
        &["/bin/sh", "-c", "printf %s \"$PM_TEST\""],
        "PM_TEST",
        secret,
    );
    assert_eq!(result.expect("run").exit, RunExit::Code(0));
    assert_eq!(stdout_bytes(&frames), b"[REDACTED]");
    assert!(frames.iter().all(|frame| match frame {
        RunFrame::Stdout(data) | RunFrame::Stderr(data) =>
            !String::from_utf8_lossy(data).contains(secret),
        _ => true,
    }));
}

#[test]
fn every_secret_is_injected_and_plain_env_is_not_redacted() {
    let secret_env = vec![
        (
            "FIRST".to_owned(),
            Zeroizing::new("first-canary-9f3a".to_owned()),
        ),
        (
            "SECOND".to_owned(),
            Zeroizing::new("second-canary-2b7c".to_owned()),
        ),
    ];
    let plain_env = vec![("PLAIN".to_owned(), "visible".to_owned())];
    let cancel = AtomicBool::new(false);
    let stop = Stop::on_cancel(&cancel);
    let mut frames = Vec::new();
    let result = execute(
        Path::new("/bin/sh"),
        &[
            "-c".to_owned(),
            "printf %s \"$FIRST|$SECOND|$PLAIN\"".to_owned(),
        ],
        &secret_env,
        &plain_env,
        Path::new("/"),
        &inherited(),
        Limits::NONE,
        &stop,
        |frame| {
            frames.push(frame);
            Ok(())
        },
    );
    assert_eq!(result.expect("run").exit, RunExit::Code(0));
    assert_eq!(
        stdout_bytes(&frames),
        b"[REDACTED]|[REDACTED]|visible",
        "both secrets redacted in one pass, the plain value passed through"
    );
}

#[test]
fn the_injected_variable_is_the_only_secret_and_the_env_is_not_inherited() {
    let (frames, result) = collect(
        &[
            "/bin/sh",
            "-c",
            "printf %s \"$PASSMGR_RUNNER_TEST_ONLY|$PM_TEST\"",
        ],
        "PM_TEST",
        "unit-test-secret-5678",
    );
    assert_eq!(result.expect("run").exit, RunExit::Code(0));
    let output = String::from_utf8(stdout_bytes(&frames)).expect("utf8");
    assert_eq!(output, "|[REDACTED]");
}

#[test]
fn a_secret_split_across_pipe_reads_is_redacted() {
    // Larger than READ_CHUNK, so the value cannot arrive in one read.
    let secret = format!("prefix-{}-suffix", "a".repeat(10_000));
    let (frames, result) = collect(
        &["/bin/sh", "-c", "printf %s \"$BIG_SECRET\""],
        "BIG_SECRET",
        &secret,
    );
    assert_eq!(result.expect("run").exit, RunExit::Code(0));
    let output = stdout_bytes(&frames);
    assert_eq!(output, b"[REDACTED]");
    assert!(
        !output
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );
}

#[test]
fn large_output_is_split_into_protocol_sized_frames() {
    let (frames, result) = collect(
        &[
            "/bin/sh",
            "-c",
            "dd if=/dev/zero bs=1024 count=40 2>/dev/null | tr '\\000' x; printf %s \"$PM_TEST\"",
        ],
        "PM_TEST",
        "unit-test-secret-9012",
    );
    assert_eq!(result.expect("run").exit, RunExit::Code(0));
    let stdout: Vec<&Vec<u8>> = frames
        .iter()
        .filter_map(|frame| match frame {
            RunFrame::Stdout(data) => Some(data),
            _ => None,
        })
        .collect();
    assert!(stdout.len() > 1, "expected more than one chunk");
    assert!(
        stdout.iter().all(|chunk| chunk.len() <= MAX_CHUNK_BYTES),
        "every chunk must fit the protocol"
    );
    let total: usize = stdout.iter().map(|chunk| chunk.len()).sum();
    let bytes = stdout_bytes(&frames);
    assert_eq!(total, 40 * 1024 + b"[REDACTED]".len());
    assert_eq!(&bytes[40 * 1024..], b"[REDACTED]");
}

#[test]
fn the_exit_code_is_propagated() {
    let (_frames, result) = collect(&["/bin/sh", "-c", "exit 7"], "PM_TEST", "secret-1234");
    assert_eq!(result.expect("run").exit, RunExit::Code(7));
}

#[test]
fn a_signalled_child_is_not_reported_as_an_exit_code() {
    let (_frames, result) = collect(
        &["/bin/sh", "-c", "kill -TERM $$"],
        "PM_TEST",
        "secret-1234",
    );
    assert_eq!(
        result.expect("run").exit,
        RunExit::Signal(libc::SIGTERM as u8)
    );
}

#[test]
fn a_missing_program_is_a_spawn_error() {
    let (_frames, result) = collect(
        &["/nonexistent/passmgr-runner-test"],
        "PM_TEST",
        "secret-1234",
    );
    assert!(matches!(result, Err(RunError::Spawn(_))));
}

#[test]
fn the_child_starts_in_the_callers_working_directory() {
    // A relative argument must resolve against `cwd`, not against the
    // process's own directory: this is the difference between running the
    // caller's script and an unrelated file in the daemon's cwd.
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("marker.txt"), b"from-the-cwd").expect("write marker");
    let argv = ["/bin/cat".to_string(), "marker.txt".to_string()];
    let cancel = AtomicBool::new(false);
    let stop = Stop::on_cancel(&cancel);
    let mut frames = Vec::new();
    let result = execute(
        Path::new(&argv[0]),
        &argv[1..],
        &secret_env("PM_TEST", "secret-1234"),
        &[],
        dir.path(),
        &inherited(),
        Limits::NONE,
        &stop,
        |frame| {
            frames.push(frame);
            Ok(())
        },
    );
    assert_eq!(result.expect("run").exit, RunExit::Code(0));
    assert_eq!(stdout_bytes(&frames), b"from-the-cwd");
}

#[test]
fn an_invalid_environment_name_is_refused_before_spawning() {
    let cancel = AtomicBool::new(false);
    let stop = Stop::on_cancel(&cancel);
    let argv = ["/bin/true".to_string()];
    let err = execute(
        Path::new(&argv[0]),
        &argv[1..],
        &secret_env("BAD=NAME", "secret-1234"),
        &[],
        Path::new("/"),
        &inherited(),
        Limits::NONE,
        &stop,
        |_| Ok(()),
    )
    .expect_err("invalid env name");
    assert!(matches!(err, RunError::Spawn(_)));
}

#[test]
fn output_errors_and_cancellation_stop_the_child() {
    // One frame first, then stay alive: the failing emit must kill the
    // child instead of waiting for it. The output is longer than the
    // redactor's holdback window, so a frame really is emitted before the
    // child blocks.
    let noisy = [
        "/bin/sh".to_string(),
        "-c".to_string(),
        "printf 0123456789abcdef; sleep 30".to_string(),
    ];
    let quiet = [
        "/bin/sh".to_string(),
        "-c".to_string(),
        "sleep 30".to_string(),
    ];
    let argv = noisy;

    let cancel = AtomicBool::new(false);
    let stop = Stop::on_cancel(&cancel);
    let err = execute(
        Path::new(&argv[0]),
        &argv[1..],
        &secret_env("PM_TEST", "secret-1234"),
        &[],
        Path::new("/"),
        &inherited(),
        Limits::NONE,
        &stop,
        |_| Err(io::Error::new(io::ErrorKind::BrokenPipe, "gone")),
    )
    .expect_err("output failed");
    assert!(matches!(err, RunError::Output(_)));

    let argv = quiet;
    let cancel = AtomicBool::new(true);
    let stop = Stop::on_cancel(&cancel);
    let err = execute(
        Path::new(&argv[0]),
        &argv[1..],
        &secret_env("PM_TEST", "secret-1234"),
        &[],
        Path::new("/"),
        &inherited(),
        Limits::NONE,
        &stop,
        |_| Ok(()),
    )
    .expect_err("cancelled");
    assert!(matches!(err, RunError::Cancelled));
}

#[test]
fn a_vanished_client_stops_a_child_that_keeps_its_pipes_open() {
    // The shape of an agent host whose tool call timed out: it takes one
    // frame and drops the connection. The child keeps both pipes open and
    // would otherwise run (with the secret in its environment) for as long
    // as its own command lasts.
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("child.pid");
    let script = format!(
        "echo $$ > {}; dd if=/dev/zero bs=1024 count=4 2>/dev/null | tr '\\000' x; exec sleep 30",
        pid_file.display()
    );
    let argv = ["/bin/sh".to_string(), "-c".to_string(), script];

    let cancel = AtomicBool::new(false);
    let gone = AtomicBool::new(false);
    let client_gone = || gone.load(Ordering::SeqCst);
    let stop = Stop::new(&cancel, &client_gone);
    let started = std::time::Instant::now();
    let err = execute(
        Path::new(&argv[0]),
        &argv[1..],
        &secret_env("PM_TEST", "secret-1234"),
        &[],
        Path::new("/"),
        &inherited(),
        Limits::NONE,
        &stop,
        |frame| {
            if matches!(frame, RunFrame::Stdout(_)) {
                gone.store(true, Ordering::SeqCst);
            }
            Ok(())
        },
    )
    .expect_err("the client vanished");
    assert!(matches!(err, RunError::Cancelled));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the vanished client was not noticed: {:?}",
        started.elapsed()
    );

    let pid = wait_for_pid_file(&pid_file);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !process_is_gone(pid) {
        assert!(
            std::time::Instant::now() < deadline,
            "the child survived the vanished client"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_vanished_client_stops_a_child_that_closed_its_pipes() {
    // Both pipes reach EOF before the stop, so the run is already in the
    // wait-for-exit loop when the client disappears. That loop polls the
    // same conditions and must not wait for the child.
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("child.pid");
    let script = format!(
        "echo $$ > {}; printf x; exec 1>&- 2>&-; exec sleep 30",
        pid_file.display()
    );
    let argv = ["/bin/sh".to_string(), "-c".to_string(), script];

    let cancel = AtomicBool::new(false);
    let gone = AtomicBool::new(false);
    let client_gone = || gone.load(Ordering::SeqCst);
    let stop = Stop::new(&cancel, &client_gone);
    let started = std::time::Instant::now();
    let err = execute(
        Path::new(&argv[0]),
        &argv[1..],
        &secret_env("PM_TEST", "secret-1234"),
        &[],
        Path::new("/"),
        &inherited(),
        Limits::NONE,
        &stop,
        |frame| {
            if matches!(frame, RunFrame::Stdout(_)) {
                gone.store(true, Ordering::SeqCst);
            }
            Ok(())
        },
    )
    .expect_err("the client vanished");
    assert!(matches!(err, RunError::Cancelled));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the vanished client was not noticed: {:?}",
        started.elapsed()
    );

    let pid = wait_for_pid_file(&pid_file);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !process_is_gone(pid) {
        assert!(
            std::time::Instant::now() < deadline,
            "the child survived the vanished client"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_client_that_is_already_gone_starts_no_child() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("ran");
    let script = format!("touch {}", marker.display());
    let argv = ["/bin/sh".to_string(), "-c".to_string(), script];

    let cancel = AtomicBool::new(false);
    let gone = || true;
    let stop = Stop::new(&cancel, &gone);
    let err = execute(
        Path::new(&argv[0]),
        &argv[1..],
        &secret_env("PM_TEST", "secret-1234"),
        &[],
        Path::new("/"),
        &inherited(),
        Limits::NONE,
        &stop,
        |_| Ok(()),
    )
    .expect_err("the client vanished before the spawn");
    assert!(matches!(err, RunError::Cancelled));
    assert!(!marker.exists(), "a child started for a gone client");
}

fn wait_for_pid_file(path: &Path) -> libc::pid_t {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(pid) = text.trim().parse::<libc::pid_t>() {
                return pid;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the child did not report the grandchild's pid"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A zombie has been killed but waits for init to reap it; that counts as
/// gone. Only Linux exposes `/proc`, and only Linux runs this suite.
fn process_state(pid: libc::pid_t) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The state is the first field after the parenthesised name.
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.trim_start().chars().next())
}

fn process_is_gone(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 only checks for the process's existence.
    if unsafe { libc::kill(pid, 0) } != 0 {
        return true;
    }
    process_state(pid) == Some('Z')
}

#[test]
fn cancellation_kills_a_grandchild_that_holds_the_pipes() {
    // The shell exits immediately but leaves `sleep` behind with both
    // output pipes open, so EOF never arrives. Cancelling must still stop
    // the run: the readers poll a stop flag, and the group kill reaps the
    // process holding the pipes.
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("grandchild.pid");
    let script = format!("sleep 30 & echo $! > {}", pid_file.display());
    let argv = ["/bin/sh".to_string(), "-c".to_string(), script];

    let cancel = Arc::new(AtomicBool::new(false));
    let runner_cancel = Arc::clone(&cancel);
    let runner = std::thread::spawn(move || {
        let stop = Stop::on_cancel(&runner_cancel);
        execute(
            Path::new(&argv[0]),
            &argv[1..],
            &secret_env("PM_TEST", "secret-1234"),
            &[],
            Path::new("/"),
            &inherited(),
            Limits::NONE,
            &stop,
            |_| Ok(()),
        )
    });

    let grandchild = wait_for_pid_file(&pid_file);
    let started = std::time::Instant::now();
    cancel.store(true, Ordering::SeqCst);
    let result = runner.join().expect("runner thread");
    assert!(matches!(result, Err(RunError::Cancelled)));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "cancelling waited on a grandchild: {:?}",
        started.elapsed()
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !process_is_gone(grandchild) {
        assert!(
            std::time::Instant::now() < deadline,
            "the grandchild holding the pipes survived the cancel"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_finished_leader_is_not_reaped_while_a_grandchild_holds_the_pipes() {
    // The leader exits immediately and leaves `sleep` behind holding both
    // output pipes, so the relay must keep waiting for them. It must not
    // reap the leader meanwhile: while the leader is a zombie its pid (and
    // pgid) cannot be recycled, so the later cancel cannot signal an
    // unrelated process group.
    let dir = tempfile::tempdir().expect("tempdir");
    let leader_file = dir.path().join("leader.pid");
    let grandchild_file = dir.path().join("grandchild.pid");
    let script = format!(
        "echo $$ > {}; sleep 30 & echo $! > {}",
        leader_file.display(),
        grandchild_file.display()
    );
    let argv = ["/bin/sh".to_string(), "-c".to_string(), script];

    let cancel = Arc::new(AtomicBool::new(false));
    let runner_cancel = Arc::clone(&cancel);
    let runner = std::thread::spawn(move || {
        let stop = Stop::on_cancel(&runner_cancel);
        execute(
            Path::new(&argv[0]),
            &argv[1..],
            &secret_env("PM_TEST", "secret-1234"),
            &[],
            Path::new("/"),
            &inherited(),
            Limits::NONE,
            &stop,
            |_| Ok(()),
        )
    });

    let leader = wait_for_pid_file(&leader_file);
    let grandchild = wait_for_pid_file(&grandchild_file);

    // Wait for the leader to exit. If it disappears instead of turning
    // into a zombie, something reaped it while the group is still alive.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match process_state(leader) {
            Some('Z') => break,
            Some(_) => {}
            None => panic!("the leader was reaped while its group was still in use"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the leader never became a zombie"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // Give a relay that polls `try_wait` three poll slices to reap it.
    std::thread::sleep(CANCEL_POLL * 3);
    assert_eq!(
        process_state(leader),
        Some('Z'),
        "the relay reaped the group leader while the grandchild held the pipes"
    );

    cancel.store(true, Ordering::SeqCst);
    let result = runner.join().expect("runner thread");
    assert!(matches!(result, Err(RunError::Cancelled)));

    for pid in [leader, grandchild] {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !process_is_gone(pid) {
            assert!(
                std::time::Instant::now() < deadline,
                "process {pid} survived the cancel"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
fn a_background_process_does_not_outlive_a_completed_run() {
    // The shape real tools leave behind: the shell backgrounds a daemon and
    // exits 0. The daemon redirects its stdio, so both pipes reach EOF and
    // the relay finishes normally -- but the daemon inherited the injected
    // value in its environment. Before the fix the run returned, `lock` and
    // `pmd` followed, and the value stayed readable in
    // `/proc/<grandchild>/environ` for as long as the daemon lived.
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("grandchild.pid");
    let script = format!(
        "sleep 60 </dev/null >/dev/null 2>&1 & echo $! > {}",
        pid_file.display()
    );
    let (frames, result) = collect(&["/bin/sh", "-c", &script], "PM_TEST", "secret-1234");
    assert_eq!(result.expect("run").exit, RunExit::Code(0));
    assert!(stdout_bytes(&frames).is_empty());

    let grandchild = wait_for_pid_file(&pid_file);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !process_is_gone(grandchild) {
        assert!(
            std::time::Instant::now() < deadline,
            "a background process outlived the completed run with the secret in its environment"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_run_past_its_deadline_is_terminated_and_flagged() {
    let started = std::time::Instant::now();
    let (frames, result) = collect_with(
        &["/bin/sh", "-c", "sleep 30"],
        "PM_TEST",
        "secret-1234",
        Path::new("/"),
        Limits {
            timeout: Some(Duration::from_secs(1)),
            max_output_bytes: None,
        },
    );
    let finished = result.expect("run");
    assert!(finished.timed_out);
    assert_eq!(finished.exit, RunExit::Signal(libc::SIGTERM as u8));
    assert!(!finished.stdout_truncated);
    assert!(!finished.stderr_truncated);
    assert!(stdout_bytes(&frames).is_empty());
    // A SIGTERM-aware child exits during the grace period; waiting out the
    // full two seconds here would mean `terminate` slept instead of polling.
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "the timeout took {:?}",
        started.elapsed()
    );
}

#[test]
fn a_timeout_kills_the_whole_process_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("grandchild.pid");
    let script = format!("sleep 60 & echo $! > {}; wait", pid_file.display());
    let (_, result) = collect_with(
        &["/bin/sh", "-c", &script],
        "PM_TEST",
        "secret-1234",
        dir.path(),
        Limits {
            timeout: Some(Duration::from_secs(1)),
            max_output_bytes: None,
        },
    );
    assert!(result.expect("run").timed_out);

    let grandchild = wait_for_pid_file(&pid_file);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !process_is_gone(grandchild) {
        assert!(
            std::time::Instant::now() < deadline,
            "grandchild {grandchild} survived the run timeout"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn output_past_the_cap_is_dropped_and_flagged() {
    let (frames, result) = collect_with(
        &["/bin/sh", "-c", r#"printf "%0100d" 0"#],
        "PM_TEST",
        "secret-1234",
        Path::new("/"),
        Limits {
            timeout: None,
            max_output_bytes: Some(16),
        },
    );
    let finished = result.expect("run");
    assert_eq!(finished.exit, RunExit::Code(0));
    assert!(!finished.timed_out);
    assert!(finished.stdout_truncated);
    assert!(!finished.stderr_truncated);
    assert_eq!(stdout_bytes(&frames), vec![b'0'; 16]);
}

#[test]
fn the_output_cap_is_per_stream() {
    let (frames, result) = collect_with(
        &[
            "/bin/sh",
            "-c",
            r#"printf "%0100d" 0; printf "%0100d" 0 >&2"#,
        ],
        "PM_TEST",
        "secret-1234",
        Path::new("/"),
        Limits {
            timeout: None,
            max_output_bytes: Some(10),
        },
    );
    let finished = result.expect("run");
    assert!(finished.stdout_truncated);
    assert!(finished.stderr_truncated);
    assert_eq!(stdout_bytes(&frames), vec![b'0'; 10]);
    assert_eq!(stderr_bytes(&frames), vec![b'0'; 10]);
}

#[test]
fn the_cap_cuts_redacted_output_never_a_secret() {
    // The child repeats the secret, so the relayed stream is a run of
    // markers. The cap is applied after redaction: 40 bytes is exactly four
    // markers, and no fragment of the secret may appear.
    let secret = "canary-cap-4c1f8e2d";
    let (frames, result) = collect_with(
        &[
            "/bin/sh",
            "-c",
            r#"i=0; while [ $i -lt 20 ]; do printf %s "$PM_TEST"; i=$((i+1)); done"#,
        ],
        "PM_TEST",
        secret,
        Path::new("/"),
        Limits {
            timeout: None,
            max_output_bytes: Some(40),
        },
    );
    assert!(result.expect("run").stdout_truncated);
    let output = stdout_bytes(&frames);
    assert_eq!(output, b"[REDACTED]".repeat(4));
    assert!(!output.windows(secret.len()).any(|w| w == secret.as_bytes()));
}

#[test]
fn reaching_the_cap_keeps_draining_the_pipe() {
    // More output than a pipe buffer holds, after the cap is reached. If the
    // reader stopped reading, the child would block or die of SIGPIPE; it
    // must instead drain to EOF and report its own exit status.
    let started = std::time::Instant::now();
    let (frames, result) = collect_with(
        &["/bin/sh", "-c", "head -c 200000 /dev/zero; exit 3"],
        "PM_TEST",
        "secret-1234",
        Path::new("/"),
        Limits {
            timeout: None,
            max_output_bytes: Some(10),
        },
    );
    let finished = result.expect("run");
    assert_eq!(finished.exit, RunExit::Code(3));
    assert!(finished.stdout_truncated);
    assert_eq!(stdout_bytes(&frames).len(), 10);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the capped run stalled: {:?}",
        started.elapsed()
    );
}

#[test]
fn the_redaction_count_and_duration_are_reported() {
    // A unique canary: the count proves redaction ran, and the bytes prove the
    // value itself never left the reader. Every match on both streams counts.
    let canary = "canary-8f3c2a9d-redaction-count";
    let (frames, result) = collect(
        &[
            "/bin/sh",
            "-c",
            "printf '%s\\n' \"$PM_CANARY\"; printf '%s\\n' \"$PM_CANARY\" >&2",
        ],
        "PM_CANARY",
        canary,
    );
    let finished = result.expect("run");
    assert_eq!(finished.exit, RunExit::Code(0));
    assert_eq!(finished.redactions, 2, "one match per stream");
    assert!(
        finished.duration_ms < 60_000,
        "a short run must not report a wild duration: {}",
        finished.duration_ms
    );
    assert_eq!(stdout_bytes(&frames), b"[REDACTED]\n");
    assert_eq!(stderr_bytes(&frames), b"[REDACTED]\n");
    for frame in &frames {
        if let RunFrame::Stdout(data) | RunFrame::Stderr(data) = frame {
            assert!(
                !data.windows(canary.len()).any(|w| w == canary.as_bytes()),
                "the canary reached a frame"
            );
        }
    }
}

#[test]
fn a_run_without_a_match_reports_no_redactions() {
    let (frames, result) = collect(
        &["/bin/sh", "-c", "printf hello"],
        "PM_TEST",
        "unused-canary",
    );
    let finished = result.expect("run");
    assert_eq!(finished.redactions, 0);
    assert_eq!(stdout_bytes(&frames), b"hello");
}
