//! Concurrency limits for the unlock daemon (`pmd`).
//!
//! Any same-user process can open many connections. The daemon serves at most
//! [`MAX_CONCURRENT_RUNS`] `run` requests at once and answers the rest `busy`
//! before decrypting the vault or spawning a child, so workers, reader
//! threads, children and injected environments stay bounded. `ping` and
//! `lock` must remain responsive while the cap is full.

#![cfg(unix)]

mod support;

use support::*;

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use passmgr::daemon::MAX_CONCURRENT_RUNS;
use passmgr::protocol::{Request, Response, RunFrame, RunRequest};

const REFUSED_REQUESTS: usize = 64;

/// A run whose child records its pid and then sleeps well past the test.
///
/// The pid is the shell's, which `exec` turns into the sleeping process, so a
/// test can prove the daemon killed and reaped every accepted run.
fn sleeping_run(fixture: &Fixture, pid_file: &Path) -> Request {
    fixture.run_request(
        "API_KEY",
        &[
            "/bin/sh",
            "-c",
            r#"echo $$ >> "$1"; exec sleep 60"#,
            "sh",
            pid_file.to_str().expect("pid path"),
        ],
    )
}

fn polite_run(fixture: &Fixture, marker: &Path) -> Request {
    fixture.run_request(
        "API_KEY",
        &[
            "/bin/sh",
            "-c",
            r#"echo ran >> "$1"; exit 0"#,
            "sh",
            marker.to_str().expect("marker path"),
        ],
    )
}

/// Poll until `pid_file` holds at least `count` distinct pids.
fn wait_for_pids(path: &Path, count: usize) -> HashSet<libc::pid_t> {
    let deadline = Instant::now() + WAIT;
    loop {
        let mut pids = HashSet::new();
        if let Ok(text) = fs::read_to_string(path) {
            for line in text.lines() {
                if let Ok(pid) = line.trim().parse::<libc::pid_t>() {
                    pids.insert(pid);
                }
            }
        }
        if pids.len() >= count {
            return pids;
        }
        assert!(
            Instant::now() < deadline,
            "only {} of {count} runs reported a pid",
            pids.len()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Poll until `pid` no longer exists (the daemon reaped it).
fn wait_for_process_exit(pid: libc::pid_t) {
    let deadline = Instant::now() + WAIT;
    loop {
        // SAFETY: signal 0 only checks for existence; the pid came from a
        // child of this test's daemon.
        if unsafe { libc::kill(pid, 0) } != 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH),
                "unexpected error probing for the child"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon did not kill and reap an injected child"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn spawn_runs(
    socket: &Path,
    token: &passmgr::token::SessionToken,
    requests: Vec<Request>,
) -> Vec<JoinHandle<(Vec<RunFrame>, Vec<u8>)>> {
    requests
        .into_iter()
        .map(|ask| {
            let socket = socket.to_path_buf();
            let token = token.clone();
            std::thread::spawn(move || read_run(&socket, &token, &ask))
        })
        .collect()
}

fn join_requests(handles: Vec<JoinHandle<(Vec<RunFrame>, Vec<u8>)>>) -> Vec<Vec<RunFrame>> {
    handles
        .into_iter()
        .map(|handle| handle.join().expect("run thread").0)
        .collect()
}

/// Fill the cap with long-running children, then send 64 more `run` requests.
/// Every extra request must be refused with the stable `busy` error without
/// spawning anything, while `ping` and `lock` keep working. Locking then
/// removes the socket and reaps every accepted child.
#[test]
fn runs_past_the_cap_are_refused_busy_and_do_not_block_ping_or_lock() {
    let fixture = Fixture::new();
    // A short idle timeout proves the in-flight runs suspend it (R.7) even
    // with a full cap.
    let mut child = fixture.start_with(&["--idle-timeout", "3"]);
    let socket = fixture.socket();
    let pid_file = fixture.temp_path("pids");
    let marker = fixture.temp_path("refused-ran");

    // Saturate the cap.
    let accepted_requests = (0..MAX_CONCURRENT_RUNS)
        .map(|_| sleeping_run(&fixture, &pid_file))
        .collect();
    let accepted = spawn_runs(&socket, &fixture.token, accepted_requests);
    let pids = wait_for_pids(&pid_file, MAX_CONCURRENT_RUNS);
    assert_eq!(pids.len(), MAX_CONCURRENT_RUNS);
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "the idle timeout stopped the daemon while the cap was full"
    );

    // A burst well beyond the cap must be fully refused, quickly.
    let refused_requests = (0..REFUSED_REQUESTS)
        .map(|_| polite_run(&fixture, &marker))
        .collect();
    let started = Instant::now();
    let refused = join_requests(spawn_runs(&socket, &fixture.token, refused_requests));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "refusing over-cap runs took {:?}",
        started.elapsed()
    );
    for frames in &refused {
        assert_eq!(frames.len(), 1, "one terminal frame: {frames:?}");
        assert_eq!(
            frames[0],
            RunFrame::Error(passmgr::protocol::ResponseError::Busy),
            "an over-cap run must be refused with the stable busy error"
        );
    }
    assert!(
        !marker.exists(),
        "a refused run must be refused before anything is spawned"
    );
    assert_eq!(
        fs::read_to_string(&pid_file)
            .expect("pid file")
            .lines()
            .count(),
        MAX_CONCURRENT_RUNS,
        "no run beyond the cap may start"
    );

    // The accept loop is still responsive with every worker busy.
    assert_eq!(
        request(&socket, &fixture.token, &Request::Ping),
        Response::Pong
    );
    let locked = Instant::now();
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(
        locked.elapsed() < Duration::from_secs(2),
        "lock had to wait for busy workers"
    );
    assert!(!socket.exists(), "lock removes the socket");

    assert!(wait_for_exit(&mut child, WAIT).success());
    for frames in join_requests(accepted) {
        assert!(
            frames.is_empty(),
            "a cancelled run emits no terminal frame: {frames:?}"
        );
    }
    for pid in pids {
        wait_for_process_exit(pid);
    }
}

/// How many times the revocation race is replayed. A lost race used to show up
/// within a handful of tries, so 20 leaves a wide margin.
const REVOCATION_TRIALS: usize = 20;

/// A revocation must not fail because an agent is busy using the vault
/// (TODO R.39). Every `run` records its use, which rewrites the vault; the
/// daemon used to read the vault before taking the write lock, so one lost
/// race answered `internal` — on the kill switch, exactly when it was needed.
#[test]
fn revocation_succeeds_while_runs_record_their_use() {
    use passmgr::grant::{Capabilities, Grant, GrantSpec, GrantToken, Scope};
    use passmgr::protocol::GrantRevokeRequest;
    use passmgr::vault::Vault;

    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let program = fs::canonicalize("/bin/true").expect("canonical /bin/true");
    let entry = Vault::open_with_key(&fixture.vault, fixture.key.as_slice())
        .expect("open vault")
        .list()
        .first()
        .expect("the fixture has one credential")
        .id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();

    for trial in 0..REVOCATION_TRIALS {
        let grant_token = GrantToken::generate().expect("grant token");
        let grant_id = {
            let mut vault = Vault::open_with_key_for_update(&fixture.vault, fixture.key.as_slice())
                .expect("lock vault");
            let grant = Grant::create(
                GrantSpec {
                    label: format!("revocation race {trial}"),
                    scope: Scope::new(vec![entry], Vec::new(), None).expect("scope"),
                    commands: vec![program.clone()],
                    capabilities: Capabilities::RUN,
                    expires_at: now + 3_600,
                    max_uses: None,
                },
                grant_token.hash(),
                now,
            )
            .expect("grant");
            let id = grant.id();
            vault.add_grant(grant).expect("add grant");
            vault
                .save_with_key(fixture.key.as_slice())
                .expect("save grant");
            id
        };

        // Several runs record their use concurrently with the revocation, so
        // the two writers really do meet at the vault lock.
        let requests: Vec<Request> = (0..8)
            .map(|_| {
                Request::Run(RunRequest {
                    limits: Default::default(),
                    env: vec![passmgr::protocol::EnvBinding {
                        name: "API_KEY".into(),
                        reference: fixture.reference.clone(),
                    }],
                    plain_env: Vec::new(),
                    command: vec![program.to_str().expect("program path is UTF-8").to_owned()],
                    cwd: "/".into(),
                    grant: grant_token.clone(),
                })
            })
            .collect();
        let runs = spawn_runs(&socket, &fixture.token, requests);

        assert_eq!(
            request(
                &socket,
                &fixture.token,
                &Request::GrantRevoke(GrantRevokeRequest::Id(grant_id)),
            ),
            Response::GrantRevoked { revoked: 1 },
            "trial {trial}: a concurrent run must not refuse the revocation"
        );

        for frames in join_requests(runs) {
            // A run that lost the race to the revocation is denied, which is
            // the point of revoking; it must never be an internal error.
            assert!(
                frames.iter().all(|frame| !matches!(
                    frame,
                    RunFrame::Error(passmgr::protocol::ResponseError::Internal)
                )),
                "trial {trial}: a concurrent run failed internally: {frames:?}"
            );
        }

        let vault =
            Vault::open_with_key(&fixture.vault, fixture.key.as_slice()).expect("reopen vault");
        assert!(
            vault.grant(grant_id).expect("grant").is_revoked(),
            "trial {trial}: the revocation must be on disk"
        );
    }

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}
