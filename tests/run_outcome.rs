#![cfg(unix)]

mod run_support;

use run_support::*;

use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Child;
use std::time::Duration;

#[test]
fn run_propagates_the_child_exit_status() {
    let daemon = Daemon::start();
    let output = run(
        &daemon,
        &[
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "/bin/sh",
            "-c",
            "exit 7",
        ],
    );
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(output.stdout.is_empty());
}

#[test]
fn run_says_on_stderr_when_relayed_output_hit_its_cap() {
    let daemon = Daemon::start();
    let output = run(
        &daemon,
        &[
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "/bin/sh",
            "-c",
            "head -c 400000 /dev/zero; head -c 400000 /dev/zero >&2; exit 3",
        ],
    );
    let cap = passmgr::protocol::DEFAULT_RUN_OUTPUT_BYTES as usize;
    assert_eq!(output.status.code(), Some(3), "{:?}", output.status);
    assert_eq!(output.stdout.len(), cap);
    let stderr = stderr_text(&output);
    for stream in ["standard output", "standard error"] {
        let notice = format!("passmgr: {stream} hit the {cap}-byte cap and was truncated");
        assert!(stderr.contains(&notice), "missing {notice:?}");
    }
}

#[test]
fn run_reports_a_signal_as_128_plus_the_signal() {
    let daemon = Daemon::start();
    let output = run(
        &daemon,
        &[
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "/bin/sh",
            "-c",
            "kill -TERM $$",
        ],
    );
    // The daemon keeps "signal 15" distinct from "exit 143" on the wire; the
    // shell-visible rendering is the usual 128 + N.
    assert_eq!(output.status.code(), Some(143), "{output:?}");
}

/// A caller that stops reading (`| head -1`, a host that closed its pipe)
/// must not turn a failing command into a success. `run` cannot relay the
/// child's status any more, so it cancels the run and exits 141; the child is
/// killed instead of being left running with nobody watching (TODO R.47).
#[test]
fn a_closed_output_pipe_cancels_the_run_and_exits_nonzero() {
    let daemon = Daemon::start();
    let flag = daemon.xdg_runtime_dir().join("release");
    let pid_file = daemon.xdg_runtime_dir().join("child.pid");
    // Print, wait to be released by the test, print again and then linger.
    // The second print is what makes the CLI write into a closed pipe; the
    // long sleep proves the daemon cancelled the child (it is killed long
    // before the script could finish). The padding matters: the redactor
    // holds back the last `secret.len() - 1` bytes of *every* chunk, whether
    // or not they match, so a short first line is not relayed until more
    // output follows it.
    let script = r#"echo $$ > "$1"
printf 'ready\n'
printf 'skip-skip-skip-skip-skip-skip-skip-skip-skip\n'
while [ ! -e "$0" ]; do sleep 0.02; done
printf 'more-more-more-more-more-more-more-more\n'
sleep 30"#;
    let environment = env_argument(&daemon, "API_KEY");
    let mut child = command_at(
        daemon.xdg_runtime_dir(),
        &[
            "run",
            "--env",
            &environment,
            "--",
            "/bin/sh",
            "-c",
            script,
            flag.to_str().expect("flag path"),
            pid_file.to_str().expect("pid path"),
        ],
    )
    .env("PASSMGR_GRANT_FILE", &daemon.grant_file)
    .spawn()
    .expect("spawn passmgr run");

    // Read exactly the first line, then close our end of the pipe while the
    // child is still running.
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut first = [0u8; 6];
    stdout.read_exact(&mut first).expect("read the first line");
    assert_eq!(&first, b"ready\n", "the child's first line must be relayed");
    drop(stdout);
    let pid = wait_for_pid(&pid_file);
    fs::write(&flag, b"go").expect("release the child");

    let status = wait_for_exit(&mut child, WAIT);
    assert_eq!(
        status.code(),
        Some(141),
        "a closed pipe must not look like success: {status:?}"
    );
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(
        stderr.contains("pipe closed") && stderr.contains("cancelled"),
        "the exit is explained on stderr: {stderr:?}"
    );
    assert!(!stderr.contains(SECRET), "the canary reached stderr");

    // The daemon noticed the disconnect and killed the child before it
    // reached the end of its 30-second sleep.
    wait_for_process_exit(pid);
}

/// Poll for the pid a test child reported, with a deadline.
fn wait_for_pid(path: &Path) -> libc::pid_t {
    wait_until(WAIT, "the child did not report its pid", || {
        fs::read_to_string(path).ok()?.trim().parse().ok()
    })
}

/// Poll until `pid` no longer exists (the daemon killed and reaped it).
fn wait_for_process_exit(pid: libc::pid_t) {
    wait_for(
        WAIT,
        "the daemon did not kill the child after its output pipe closed",
        || {
            // SAFETY: signal 0 only checks for existence; the pid came from a
            // child of this test's daemon.
            let gone = unsafe { libc::kill(pid, 0) } != 0;
            if gone {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH),
                    "unexpected error probing for the child"
                );
            }
            gone
        },
    );
}

/// Wait for a spawned process to exit, polling with a deadline instead of
/// sleeping for a fixed time.
fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    poll_until(timeout, || child.try_wait().expect("poll the child")).unwrap_or_else(|| {
        let _ = child.kill();
        let _ = child.wait();
        panic!("the process did not exit within {timeout:?}");
    })
}
