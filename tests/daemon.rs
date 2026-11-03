//! End-to-end tests for the unlock daemon (`pmd`).
//!
//! Each test runs a real `pmd` against a disposable runtime directory and a
//! vault created with deliberately cheap Argon2 parameters (this file is not
//! testing the KDF). The vault secret is generated here and must never appear
//! in daemon output, arguments, environment or socket traffic.
//!
//! The fixture and helpers live in `support/`; the shutdown and cancellation
//! tests are in `daemon_shutdown.rs` so neither file grows past ~1,000 lines.

#![cfg(unix)]

mod support;

use support::*;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use passmgr::crypto::KEY_LEN;
use passmgr::presence::{ChallengeNonce, Proof, RequestDigest};
use passmgr::protocol::{
    self, MAX_CHUNK_BYTES, ProveRequest, Request, Response, ResponseError, RunExit, RunFrame,
    RunRequest,
};
use passmgr::token::SessionToken;
#[test]
fn ping_then_lock_wipes_the_key_and_removes_the_socket() {
    let fixture = Fixture::new();
    let mut child = fixture.start();

    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Ping),
        Response::Pong
    );
    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Lock),
        Response::Locked
    );

    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status: {status:?}");
    assert!(
        !fixture.socket().exists(),
        "a clean shutdown must remove the socket"
    );
}

#[test]
fn sigterm_and_sigint_shut_down_cleanly() {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        let fixture = Fixture::new();
        let mut child = fixture.start();
        let pid = child.id() as libc::pid_t;
        // SAFETY: the pid belongs to a live child of this process.
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0, "kill failed");

        let status = wait_for_exit(&mut child, WAIT);
        assert!(status.success(), "signal {signal} exit status: {status:?}");
        assert!(!fixture.socket().exists());
    }
}

#[test]
fn malformed_oversized_and_unknown_requests_are_rejected_without_a_crash() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();

    // An empty connection.
    assert_eq!(
        raw_request(&socket, b""),
        Response::Error(ResponseError::BadRequest)
    );

    // A length prefix far above the 64 KiB cap.
    assert_eq!(
        raw_request(&socket, &u32::MAX.to_be_bytes()),
        Response::Error(ResponseError::BadRequest)
    );

    // Truncated JSON.
    assert_eq!(
        raw_request(&socket, &[0, 0, 0, 5, b'{']),
        Response::Error(ResponseError::BadRequest)
    );

    // Unknown request type.
    let token = fixture.token.to_hex();
    let body = format!(
        r#"{{"version":3,"token":"{}","request":{{"type":"steal"}}}}"#,
        token.as_str()
    );
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    assert_eq!(
        raw_request(&socket, &frame),
        Response::Error(ResponseError::BadRequest)
    );

    // A well-formed frame whose token is not 64 lowercase hex characters.
    let body = br#"{"version":3,"token":"nope","request":{"type":"ping"}}"#;
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    assert_eq!(
        raw_request(&socket, &frame),
        Response::Error(ResponseError::BadRequest)
    );

    // `run` for an unknown reference answers with a terminal run frame and
    // leaves the daemon healthy.
    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &Request::Run(RunRequest {
            env: "API_KEY".into(),
            reference: "pm://00112233445566778899aabbccddeeff".into(),
            command: vec!["/bin/true".into()],
            cwd: "/".into(),
        }),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::NotFound)]);

    // Still alive and serving the owner.
    assert_eq!(
        request(&socket, &fixture.token, &Request::Ping),
        Response::Pong
    );
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn idle_timeout_wipes_the_key_and_stops_the_daemon() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "1"]);
    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Ping),
        Response::Pong
    );

    // No `lock`, no signal: the daemon must stop on its own.
    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status: {status:?}");
    assert!(
        !fixture.socket().exists(),
        "an idle shutdown must remove the socket"
    );
}

#[test]
fn successful_requests_refresh_the_idle_timeout() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "2"]);
    let socket = fixture.socket();

    // Keep pinging for longer than the timeout. Every answered request resets
    // the clock, so the daemon must still be alive at the end.
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        assert_eq!(
            request(&socket, &fixture.token, &Request::Ping),
            Response::Pong
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "activity before the deadline must keep the daemon alive"
    );

    // Now go quiet: it must expire.
    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status: {status:?}");
    assert!(!fixture.socket().exists());
}

#[test]
fn malformed_requests_do_not_refresh_the_idle_timeout() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "2"]);
    let socket = fixture.socket();

    // Send rejected requests for longer than the timeout. They are answered
    // (with `bad_request`) but are not activity, so the daemon must still
    // expire on schedule.
    let started = Instant::now();
    let deadline = started + Duration::from_secs(4);
    let mut rejected = 0;
    while Instant::now() < deadline {
        let Ok(mut stream) = UnixStream::connect(&socket) else {
            break;
        };
        stream.set_read_timeout(Some(WAIT)).expect("read timeout");
        let sent = stream
            .write_all(b"not a frame")
            .and_then(|()| stream.shutdown(std::net::Shutdown::Write));
        let mut bytes = Vec::new();
        if sent.is_err() || stream.read_to_end(&mut bytes).is_err() {
            // The daemon expired between our connect and the request.
            break;
        }
        match protocol::decode_response(&bytes) {
            Ok(Response::Error(ResponseError::BadRequest)) => rejected += 1,
            _ => break,
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(rejected >= 2, "expected repeated rejected requests");

    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status: {status:?}");
    assert!(!fixture.socket().exists());
    // Rejected traffic must not have extended the key's lifetime: if it had,
    // the loop above would have kept the daemon alive past its deadline and
    // the exit would only come seconds later.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "rejected requests extended the idle timeout (stopped after {:?})",
        started.elapsed()
    );
}

/// Rejections must not count as activity, or a client with the wrong token
/// could keep the vault key in memory indefinitely.
#[test]
fn unauthorized_requests_do_not_refresh_the_idle_timeout() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "2"]);
    let socket = fixture.socket();
    let wrong = SessionToken::generate().expect("wrong token");

    let started = Instant::now();
    let deadline = started + Duration::from_secs(4);
    let mut rejected = 0;
    while Instant::now() < deadline {
        match try_request(&socket, &wrong, &Request::Ping) {
            Ok(Response::Error(ResponseError::Unauthorized)) => rejected += 1,
            // The daemon expired between our connect and the request.
            _ => break,
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(rejected >= 2, "expected repeated unauthorized requests");

    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status: {status:?}");
    assert!(!fixture.socket().exists());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "unauthorized requests extended the idle timeout (stopped after {:?})",
        started.elapsed()
    );
}

#[test]
fn a_wrong_key_never_creates_a_socket() {
    let fixture = Fixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_pmd"));
    command
        .arg("--vault")
        .arg(&fixture.vault)
        .arg("--runtime-dir")
        .arg(&fixture.runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn pmd");
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin.write_all(&[0u8; KEY_LEN]).expect("send wrong key");
    drop(stdin);

    let status = wait_for_exit(&mut child, WAIT);
    assert!(!status.success(), "a wrong key must not start the daemon");
    assert!(
        !fixture.socket().exists(),
        "a rejected key must not leave a socket behind"
    );
}

#[test]
fn a_second_daemon_is_refused_and_the_first_keeps_serving() {
    let fixture = Fixture::new();
    let mut first = fixture.start();

    let mut second = fixture.spawn();
    let status = wait_for_exit(&mut second, WAIT);
    assert!(!status.success(), "the second daemon must fail to start");

    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Ping),
        Response::Pong
    );
    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut first, WAIT).success());
}

#[test]
fn the_secret_never_reaches_output_arguments_environment_or_the_socket() {
    let fixture = Fixture::new();
    let child = fixture.start();
    let socket = fixture.socket();

    // Responses carry status only.
    let mut traffic = Vec::new();
    for request in [
        Request::Ping,
        Request::Run(RunRequest {
            env: "API_KEY".into(),
            reference: "pm://00112233445566778899aabbccddeeff".into(),
            command: vec!["/bin/sh".into(), "-c".into(), "true".into()],
            cwd: "/".into(),
        }),
    ] {
        let mut stream = UnixStream::connect(&socket).expect("connect");
        stream.set_read_timeout(Some(WAIT)).expect("read timeout");
        stream
            .write_all(&protocol::encode(&fixture.token, &request).expect("encode"))
            .expect("write");
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).expect("read");
        traffic.extend_from_slice(&bytes);
        assert!(!String::from_utf8_lossy(&bytes).contains(SECRET));
    }

    // On Linux the daemon cleared PR_SET_DUMPABLE, so its cmdline/environ are
    // not readable by same-uid processes. If they are readable, they must
    // still not contain the secret.
    if let Ok(cmdline) = fs::read(format!("/proc/{}/cmdline", child.id())) {
        assert!(!String::from_utf8_lossy(&cmdline).contains(SECRET));
    }
    if let Ok(environ) = fs::read(format!("/proc/{}/environ", child.id())) {
        assert!(!String::from_utf8_lossy(&environ).contains(SECRET));
    }
    assert!(!String::from_utf8_lossy(&traffic).contains(SECRET));

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
}

/// A client that cannot present the session token is rejected, and rejection
/// is not activity: the daemon keeps serving the owner.
#[test]
fn a_wrong_token_is_rejected_and_the_owner_is_served() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let wrong = SessionToken::generate().expect("wrong token");

    assert_eq!(
        request(&socket, &wrong, &Request::Ping),
        Response::Error(ResponseError::Unauthorized)
    );
    assert_eq!(
        request(&socket, &wrong, &Request::Lock),
        Response::Error(ResponseError::Unauthorized)
    );
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "an unauthorized `lock` must not stop the daemon"
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Ping),
        Response::Pong
    );
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

/// The token is a credential: it must not be echoed, logged or put in argv.
#[test]
fn the_session_token_never_reaches_socket_traffic_or_daemon_output() {
    let fixture = Fixture::new();
    let child = fixture.start();
    let socket = fixture.socket();
    let token_hex = fixture.token.to_hex();

    // An unauthorized request gets a status-only answer.
    let wrong = SessionToken::generate().expect("wrong token");
    let wrong_hex = wrong.to_hex();
    let body = format!(
        r#"{{"version":3,"token":"{}","request":{{"type":"ping"}}}}"#,
        wrong_hex.as_str()
    );
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    let mut stream = UnixStream::connect(&socket).expect("connect");
    stream.set_read_timeout(Some(WAIT)).expect("read timeout");
    stream.write_all(&frame).expect("write");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).expect("read");
    assert_eq!(
        protocol::decode_response(&bytes).expect("decode"),
        Response::Error(ResponseError::Unauthorized)
    );
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains(wrong_hex.as_str()));
    assert!(!text.contains(token_hex.as_str()));

    // The token reaches the daemon over stdin, not argv.
    if let Ok(cmdline) = fs::read(format!("/proc/{}/cmdline", child.id())) {
        let cmdline = String::from_utf8_lossy(&cmdline);
        assert!(!cmdline.contains(token_hex.as_str()));
        assert!(!cmdline.contains(SECRET));
    }

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        assert!(!text.contains(token_hex.as_str()));
        assert!(!text.contains(SECRET));
    }
}

/// Ask for a challenge nonce, failing loudly on anything else.
fn challenge(socket: &Path, token: &SessionToken) -> ChallengeNonce {
    match request(socket, token, &Request::Challenge) {
        Response::Challenge(nonce) => nonce,
        other => panic!("expected a challenge, got {other:?}"),
    }
}

fn present(socket: &Path, token: &SessionToken, proof: ProveRequest) -> Response {
    request(socket, token, &Request::Prove(proof))
}

/// A correct proof is accepted, and only once: the daemon spends the nonce.
/// The MAC itself must never reach the daemon's own output.
#[test]
fn a_presence_proof_is_accepted_once_and_stays_out_of_daemon_output() {
    let fixture = Fixture::new();
    let child = fixture.start();
    let socket = fixture.socket();
    let digest = RequestDigest::new([0x42; 32]);

    let nonce = challenge(&socket, &fixture.token);
    let proof = Proof::compute(fixture.key.as_slice(), &nonce, &digest).expect("compute proof");
    let proof_hex = proof.to_hex();
    let proven = ProveRequest {
        nonce,
        digest,
        proof: proof.clone(),
    };
    assert_eq!(
        present(&socket, &fixture.token, proven.clone()),
        Response::Proven
    );

    // Replaying the identical proof is refused: the nonce is gone.
    assert_eq!(
        present(&socket, &fixture.token, proven),
        Response::Error(ResponseError::Denied)
    );

    // A fresh challenge still works, so the refusal above was about the
    // nonce, not a broken daemon.
    let nonce = challenge(&socket, &fixture.token);
    let digest = RequestDigest::new([0x43; 32]);
    let proof = Proof::compute(fixture.key.as_slice(), &nonce, &digest).expect("compute proof");
    assert_eq!(
        present(
            &socket,
            &fixture.token,
            ProveRequest {
                nonce,
                digest,
                proof,
            }
        ),
        Response::Proven
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    let output = child.wait_with_output().expect("wait for pmd");
    assert!(output.status.success());
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(proof_hex.as_str()),
            "the presence proof must never be written to daemon output"
        );
    }
}

/// Every way a proof can be wrong is refused with the same answer, the nonce
/// is spent by the attempt, and the daemon keeps serving.
#[test]
fn a_bad_presence_proof_is_denied_and_the_daemon_keeps_serving() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let digest = RequestDigest::new([0x11; 32]);

    // A proof made with the wrong key.
    let nonce = challenge(&socket, &fixture.token);
    let proof = Proof::compute(&[0u8; 32], &nonce, &digest).expect("compute proof");
    assert_eq!(
        present(
            &socket,
            &fixture.token,
            ProveRequest {
                nonce,
                digest,
                proof,
            }
        ),
        Response::Error(ResponseError::Denied)
    );

    // A proof for one digest cannot approve a different one.
    let nonce = challenge(&socket, &fixture.token);
    let proof = Proof::compute(fixture.key.as_slice(), &nonce, &digest).expect("compute proof");
    assert_eq!(
        present(
            &socket,
            &fixture.token,
            ProveRequest {
                nonce,
                digest: RequestDigest::new([0x12; 32]),
                proof,
            }
        ),
        Response::Error(ResponseError::Denied)
    );

    // A nonce that was never issued.
    let unknown = ChallengeNonce::from_hex(&"ab".repeat(32)).expect("nonce");
    let proof = Proof::compute(fixture.key.as_slice(), &unknown, &digest).expect("compute proof");
    assert_eq!(
        present(
            &socket,
            &fixture.token,
            ProveRequest {
                nonce: unknown,
                digest,
                proof,
            }
        ),
        Response::Error(ResponseError::Denied)
    );

    // A bad attempt spends the nonce, so the same challenge cannot then be
    // answered correctly.
    let nonce = challenge(&socket, &fixture.token);
    let bad = Proof::compute(&[1u8; 32], &nonce, &digest).expect("compute proof");
    let good = Proof::compute(fixture.key.as_slice(), &nonce, &digest).expect("compute proof");
    assert_eq!(
        present(
            &socket,
            &fixture.token,
            ProveRequest {
                nonce,
                digest,
                proof: bad,
            }
        ),
        Response::Error(ResponseError::Denied)
    );
    assert_eq!(
        present(
            &socket,
            &fixture.token,
            ProveRequest {
                nonce,
                digest,
                proof: good,
            }
        ),
        Response::Error(ResponseError::Denied)
    );

    // The session token still guards both presence requests.
    let wrong = SessionToken::generate().expect("wrong token");
    assert_eq!(
        request(&socket, &wrong, &Request::Challenge),
        Response::Error(ResponseError::Unauthorized)
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Ping),
        Response::Pong
    );
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn run_injects_the_secret_and_redacts_stdout_and_stderr() {
    let fixture = Fixture::new();
    let child = fixture.start();
    let socket = fixture.socket();

    let (frames, raw) = read_run(
        &socket,
        &fixture.token,
        &run_request(
            &fixture.reference,
            "API_KEY",
            &[
                "/bin/sh",
                "-c",
                "printf %s \"$API_KEY\"; printf %s \"$API_KEY\" >&2",
            ],
        ),
    );

    assert_eq!(stdout_bytes(&frames), b"[REDACTED]");
    assert_eq!(stderr_bytes(&frames), b"[REDACTED]");
    assert_eq!(frames.last(), Some(&RunFrame::Exit(RunExit::Code(0))));
    assert!(
        !raw.windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );
    assert!(
        !raw.windows(hex(SECRET.as_bytes()).len())
            .any(|window| { window == hex(SECRET.as_bytes()).as_bytes() })
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    let output = child.wait_with_output().expect("wait for pmd");
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
}

#[test]
fn run_reports_a_missing_reference_and_a_spawn_failure_without_dying() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();

    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &run_request(
            "pm://00112233445566778899aabbccddeeff",
            "API_KEY",
            &["/bin/true"],
        ),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::NotFound)]);

    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &run_request(
            &fixture.reference,
            "API_KEY",
            &["/nonexistent/passmgr-run-test"],
        ),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::SpawnFailed)]);

    // Neither failure is fatal.
    assert_eq!(
        request(&socket, &fixture.token, &Request::Ping),
        Response::Pong
    );
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn run_refuses_loader_and_shell_hook_variables_without_spawning() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let marker = fixture.temp_path("spawned");

    for env in [
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
    ] {
        let (frames, _) = read_run(
            &socket,
            &fixture.token,
            &run_request(
                &fixture.reference,
                env,
                &["/bin/sh", "-c", &format!("touch {}", marker.display())],
            ),
        );
        assert_eq!(
            frames,
            vec![RunFrame::Error(ResponseError::BadRequest)],
            "injecting {env} must be refused"
        );
        assert!(!marker.exists(), "a refused run must not spawn: {env}");
    }

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn run_streams_large_output_in_protocol_sized_chunks_and_redacts() {
    // The vault caps a password at 4096 bytes; the runner's unit tests cover
    // a value split across pipe reads with a longer value. Here the prefix
    // pushes the value to a read boundary anyway, and the output proves the
    // frame cap.
    let secret = format!("{}{}", SECRET, "z".repeat(4096 - SECRET.len()));
    let fixture = Fixture::with_secret(&secret);
    let child = fixture.start();
    let socket = fixture.socket();

    let (frames, raw) = read_run(
        &socket,
        &fixture.token,
        &run_request(
            &fixture.reference,
            "BIG_SECRET",
            &[
                "/bin/sh",
                "-c",
                "dd if=/dev/zero bs=1024 count=40 2>/dev/null | tr '\\000' x; printf %s \"$BIG_SECRET\"",
            ],
        ),
    );

    let chunks: Vec<&Vec<u8>> = frames
        .iter()
        .filter_map(|frame| match frame {
            RunFrame::Stdout(data) => Some(data),
            _ => None,
        })
        .collect();
    assert!(chunks.len() > 1, "long output must span several frames");
    assert!(
        chunks.iter().all(|chunk| chunk.len() <= MAX_CHUNK_BYTES),
        "a frame must never exceed the protocol cap"
    );

    let stdout = stdout_bytes(&frames);
    assert_eq!(stdout.len(), 40 * 1024 + b"[REDACTED]".len());
    assert!(stdout[..40 * 1024].iter().all(|byte| *byte == b'x'));
    assert_eq!(&stdout[40 * 1024..], b"[REDACTED]");
    assert_eq!(frames.last(), Some(&RunFrame::Exit(RunExit::Code(0))));

    assert!(
        !raw.windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );
    let encoded = hex(secret.as_bytes());
    assert!(
        !raw.windows(encoded.len())
            .any(|window| window == encoded.as_bytes())
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    let output = child.wait_with_output().expect("wait for pmd");
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
}
