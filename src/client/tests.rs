use std::io::Read;
use std::os::unix::fs::DirBuilderExt;

use super::*;
use crate::presence::{Proof, RequestDigest};
use crate::protocol::{AuthenticatedRequest, FrameDecoder, RunExit};
use crate::socket::DaemonSocket;
use tempfile::TempDir;

fn test_token() -> SessionToken {
    SessionToken::from_bytes(&[0x5Au8; crate::token::TOKEN_BYTES]).expect("token")
}

/// Bind a socket in `paths` and answer one request with `response` on a
/// background thread. The socket (and its instance lock) lives until the
/// thread finishes.
fn serve_once(
    paths: RuntimePaths,
    response: Response,
) -> std::thread::JoinHandle<AuthenticatedRequest> {
    let socket = DaemonSocket::bind_at(paths.clone())
        .unwrap_or_else(|error| panic!("bind test socket at {paths:?}: {error:?}"));
    std::thread::spawn(move || {
        let (mut stream, _peer) = socket.accept_peer().expect("accept client");
        let mut decoder = FrameDecoder::new();
        let mut buffer = [0u8; 4096];
        let request = loop {
            match stream.read(&mut buffer) {
                Ok(0) => panic!("client closed before sending a request"),
                Ok(read) => decoder.push(&buffer[..read]).expect("frame"),
                Err(err) => panic!("read failed: {err}"),
            }
            if let Some(request) = decoder.next_request().expect("decode request") {
                break request;
            }
        };
        let frame = protocol::encode_response(&response).expect("encode response");
        stream.write_all(&frame).expect("write response");
        request
    })
}

/// A 0700 runtime directory inside a temporary directory.
fn runtime_paths() -> (TempDir, RuntimePaths) {
    let directory = TempDir::new().expect("tempdir");
    let runtime = directory.path().join("runtime");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&runtime)
        .expect("create runtime dir");
    let paths = RuntimePaths::at(&runtime);
    (directory, paths)
}

/// A daemon that goes away between the connect and the request must not
/// look like the CLI's own output pipe closing (TODO R.60). A dropped peer
/// makes the write fail with `EPIPE` deterministically, so this pins the
/// variant `main` sees rather than only the end-to-end exit code: a bare
/// `Error::Io(BrokenPipe)` would be mapped to exit 0 by `main`.
#[test]
fn a_failed_request_write_is_a_daemon_error_not_a_broken_pipe() {
    let (mut stream, peer) = UnixStream::pair().expect("socket pair");
    drop(peer);

    let error = send_request(&mut stream, &test_token(), &Request::Ping)
        .expect_err("a write with no reader must fail");
    assert!(
        matches!(error, Error::Daemon(_)),
        "a socket write failure must not be a bare I/O error: {error:?}"
    );
    assert_ne!(
        error.exit_code(),
        0,
        "a lost request must never report success"
    );
}

/// A daemon that dies after accepting the connection can also fail the
/// *read* (an end-of-file, or a reset, depending on which side wins the
/// race). That must name the daemon too, not surface as a bare
/// `Error::Io`: `main` maps a `BrokenPipe` I/O error to exit 0 for this
/// process's own output, and a lost request must never look like success
/// (TODO R.60).
#[test]
fn a_closed_connection_without_an_answer_is_a_daemon_error() {
    let (mut stream, peer) = UnixStream::pair().expect("socket pair");
    drop(peer);

    let error = read_response(&mut stream).expect_err("a read with no writer must fail");
    assert!(
        matches!(error, Error::Daemon(_)),
        "a socket read failure must not be a bare I/O error: {error:?}"
    );
    assert_ne!(
        error.exit_code(),
        0,
        "a lost answer must never look like success"
    );
    assert!(
        format!("{error}").contains("unlock daemon"),
        "the failure must name the daemon: {error}"
    );
}

#[test]
fn ping_and_lock_round_trip() {
    let (_directory, paths) = runtime_paths();
    let token = test_token();

    let server = serve_once(paths.clone(), Response::Pong);
    ping(&paths, &token).expect("ping");
    let seen = server.join().expect("server thread");
    assert!(
        seen.token().matches(&token),
        "the ping must carry the token"
    );
    assert_eq!(seen.into_request(), Request::Ping);

    session::store(&paths, &token).expect("store token");
    let server = serve_once(paths.clone(), Response::Locked);
    lock(&paths).expect("lock");
    let seen = server.join().expect("server thread");
    assert!(seen.token().matches(&token), "lock must carry the token");
    assert_eq!(seen.into_request(), Request::Lock);
    assert!(
        !paths.session().exists(),
        "lock must not leave a stale session token behind"
    );
}

#[test]
fn challenge_and_prove_round_trip_and_denial_is_reported() {
    let (_directory, paths) = runtime_paths();
    let token = test_token();

    let nonce = ChallengeNonce::from_hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    )
    .expect("nonce");
    let server = serve_once(paths.clone(), Response::Challenge(nonce));
    let received = challenge(&paths, &token).expect("challenge");
    assert!(received.matches(&nonce));
    assert_eq!(
        server.join().expect("server thread").into_request(),
        Request::Challenge
    );

    let digest = RequestDigest::new([0x24; 32]);
    let proof = Proof::compute(&[0x0bu8; 32], &nonce, &digest).expect("proof");
    let request_proof = protocol::ProveRequest {
        nonce,
        digest,
        proof,
    };
    let server = serve_once(paths.clone(), Response::Proven);
    prove(&paths, &token, &request_proof).expect("proven");
    assert_eq!(
        server.join().expect("server thread").into_request(),
        Request::Prove(request_proof.clone())
    );

    // A refusal names the code and never the proof.
    let server = serve_once(paths.clone(), Response::Error(ResponseError::Denied));
    let error = prove(&paths, &token, &request_proof).expect_err("denied");
    let message = error.to_string();
    assert!(message.contains("denied"), "{message}");
    assert!(
        !message.contains(request_proof.proof.to_hex().as_str()),
        "{message}"
    );
    server.join().expect("server thread");

    // A daemon that answers a proof with the wrong shape is a protocol
    // error, not a silently accepted approval.
    let server = serve_once(paths.clone(), Response::Pong);
    assert!(prove(&paths, &token, &request_proof).is_err());
    server.join().expect("server thread");
}

#[test]
fn ping_and_lock_name_an_unexpected_response_by_kind_only() {
    let (_directory, paths) = runtime_paths();
    let token = test_token();

    let server = serve_once(paths.clone(), Response::Locked);
    let error = ping(&paths, &token).expect_err("wrong answer");
    server.join().expect("server thread");
    assert_eq!(
        error.to_string(),
        "the unlock daemon answered a ping with an unexpected response (locked)."
    );

    session::store(&paths, &token).expect("store token");
    let server = serve_once(paths.clone(), Response::Pong);
    let error = lock(&paths).expect_err("wrong answer");
    server.join().expect("server thread");
    assert_eq!(
        error.to_string(),
        "the unlock daemon answered a lock request with an unexpected response (pong)."
    );
}

#[test]
fn lock_keeps_a_session_file_that_holds_another_token() {
    let (_directory, paths) = runtime_paths();
    let newer = SessionToken::from_bytes(&[0x33u8; crate::token::TOKEN_BYTES]).expect("token");
    session::store(&paths, &newer).expect("store token");
    let server = serve_once(paths.clone(), Response::Locked);
    lock_with(&paths, &test_token()).expect("lock");
    server.join().expect("server thread");
    let kept = session::load(&paths).expect("the newer session file survives");
    assert!(kept.matches(&newer));
}

#[test]
fn lock_without_a_session_file_reports_the_real_problem() {
    let (_directory, paths) = runtime_paths();
    // No daemon and no token: the caller hears about the missing daemon.
    let error = lock(&paths).expect_err("no daemon");
    assert!(
        error.to_string().contains("no passmgr daemon is running"),
        "{error}"
    );

    // A daemon is reachable but the token is gone: that is not success,
    // and nothing is sent (the client cannot authenticate).
    let socket = DaemonSocket::bind_at(paths.clone()).expect("bind");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = socket.accept_peer().expect("accept");
        let mut buffer = [0u8; 1];
        assert_eq!(stream.read(&mut buffer).expect("read"), 0);
    });
    let error = lock(&paths).expect_err("no token file");
    assert!(error.to_string().contains("authenticate"), "{error}");
    server.join().expect("server thread");
}

#[test]
fn an_error_response_is_returned_to_the_caller() {
    let (_directory, paths) = runtime_paths();
    let token = test_token();
    let server = serve_once(
        paths.clone(),
        Response::Error(protocol::ResponseError::Unsupported),
    );
    let response = request(&paths, &token, &Request::Ping).expect("request");
    assert_eq!(
        response,
        Response::Error(protocol::ResponseError::Unsupported)
    );
    server.join().expect("server thread");
}

#[test]
fn a_missing_daemon_is_a_clear_error() {
    let directory = TempDir::new().expect("tempdir");
    let paths = RuntimePaths::at(directory.path().join("no-daemon-here"));
    let error = ping(&paths, &test_token()).expect_err("no daemon");
    let message = error.to_string();
    assert!(
        message.contains("no passmgr daemon is running"),
        "{message}"
    );
    assert!(message.contains("passmgr unlock"), "{message}");
}

#[test]
fn garbage_and_empty_responses_are_rejected_without_a_panic() {
    for body in [
        &b"not a frame"[..],
        &b""[..],
        &[0xff, 0xff, 0xff, 0xff, b'{', b'}'][..],
    ] {
        let (_directory, paths) = runtime_paths();
        let socket = DaemonSocket::bind_at(paths.clone()).expect("bind");
        let body = body.to_vec();
        let server = std::thread::spawn(move || {
            let (mut stream, _peer) = socket.accept_peer().expect("accept");
            let mut buffer = [0u8; 4096];
            // Consume the client's request first so it is not racing us.
            let _ = stream.read(&mut buffer);
            stream.write_all(&body).expect("write garbage");
        });
        let error = request(&paths, &test_token(), &Request::Ping).expect_err("garbage response");
        assert!(matches!(error, Error::Daemon(_)), "{error:?}");
        assert!(!error.to_string().contains("not a frame"));
        server.join().expect("server thread");
    }
}

#[test]
fn spawn_refuses_a_key_of_the_wrong_length_before_spawning() {
    let (_directory, paths) = runtime_paths();
    let error = spawn_daemon(
        Path::new("/nonexistent/vault.dat"),
        &paths,
        &[0u8; 4],
        &test_token(),
        crate::daemon::DEFAULT_IDLE_TIMEOUT,
    )
    .expect_err("short key");
    assert!(matches!(error, Error::Daemon(_)));
    assert!(error.to_string().contains("32 bytes"), "{error}");
}

#[test]
fn startup_failure_reports_the_exit_status_and_log() {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("echo 'boom: startup failed' >&2; exit 7")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn helper");

    // Route the helper's stderr through the same anonymous-file path used
    // for pmd, then wait so `try_wait` sees the exit.
    let mut log = tempfile::tempfile().expect("tempfile");
    let mut stderr = child.stderr.take().expect("piped stderr");
    io::copy(&mut stderr, &mut log).expect("copy stderr");
    child.wait().expect("reap helper");

    let error = startup_failure(
        &mut child,
        &mut log,
        "exited during startup (exit 7)".into(),
    );
    let message = error.to_string();
    assert!(message.contains("pmd exited during startup"), "{message}");
    assert!(message.contains("boom: startup failed"), "{message}");
}
/// Bind a socket in `paths` and answer one `run` request with `frames`.
fn serve_frames(
    paths: RuntimePaths,
    frames: Vec<RunFrame>,
) -> std::thread::JoinHandle<AuthenticatedRequest> {
    let socket = DaemonSocket::bind_at(paths.clone())
        .unwrap_or_else(|error| panic!("bind test socket at {paths:?}: {error:?}"));
    std::thread::spawn(move || {
        let (mut stream, _peer) = socket.accept_peer().expect("accept client");
        let mut decoder = FrameDecoder::new();
        let mut buffer = [0u8; 4096];
        let request = loop {
            match stream.read(&mut buffer) {
                Ok(0) => panic!("client closed before sending a request"),
                Ok(read) => decoder.push(&buffer[..read]).expect("frame"),
                Err(err) => panic!("read failed: {err}"),
            }
            if let Some(request) = decoder.next_request().expect("decode request") {
                break request;
            }
        };
        for frame in frames {
            let encoded = protocol::encode_run_frame(&frame).expect("encode frame");
            // A client that stops at a terminal frame closes the stream;
            // that is what some of these tests prove, so a failed write
            // just ends the exchange instead of panicking here.
            if stream.write_all(&encoded).is_err() {
                break;
            }
        }
        request
    })
}

fn run_request() -> protocol::RunRequest {
    protocol::RunRequest {
        limits: Default::default(),
        env: vec![protocol::EnvBinding {
            name: "API_KEY".into(),
            reference: "pm://00112233445566778899aabbccddeeff".into(),
        }],
        plain_env: Vec::new(),
        command: vec!["/bin/true".into()],
        cwd: "/tmp".into(),
        grant: crate::grant::GrantToken::from_hex(&"11".repeat(32)).expect("token"),
    }
}

#[test]
fn run_relays_frames_in_order_and_returns_the_status() {
    let (_directory, paths) = runtime_paths();
    let token = test_token();
    let server = serve_frames(
        paths.clone(),
        vec![
            RunFrame::Stdout(b"one".to_vec()),
            RunFrame::Stderr(b"two".to_vec()),
            RunFrame::Stdout(b"three".to_vec()),
            RunFrame::Exit(RunFinished::exited(RunExit::Code(7))),
        ],
    );

    let mut relayed = Vec::new();
    let outcome = run(&paths, &token, &run_request(), |frame| {
        match frame {
            RunFrame::Stdout(bytes) => relayed.push(("out", bytes.clone())),
            RunFrame::Stderr(bytes) => relayed.push(("err", bytes.clone())),
            other => panic!("terminal frame reached the callback: {other:?}"),
        }
        Ok(())
    })
    .expect("run");

    assert_eq!(
        outcome,
        RunOutcome::Exited(RunFinished::exited(RunExit::Code(7)))
    );
    assert_eq!(
        relayed,
        [
            ("out", b"one".to_vec()),
            ("err", b"two".to_vec()),
            ("out", b"three".to_vec()),
        ]
    );
    let seen = server.join().expect("server thread");
    assert!(seen.token().matches(&token));
    assert_eq!(seen.into_request(), Request::Run(run_request()));
}

#[test]
fn run_returns_a_terminal_error_as_a_refusal() {
    let (_directory, paths) = runtime_paths();
    let server = serve_frames(
        paths.clone(),
        vec![
            RunFrame::Stderr(b"partial".to_vec()),
            RunFrame::Error(protocol::ResponseError::NotFound),
        ],
    );
    let mut relayed = 0;
    let outcome = run(&paths, &test_token(), &run_request(), |_frame| {
        relayed += 1;
        Ok(())
    })
    .expect("run");
    assert_eq!(
        outcome,
        RunOutcome::Refused(protocol::ResponseError::NotFound)
    );
    assert_eq!(relayed, 1, "only the non-terminal frame is relayed");
    server.join().expect("server thread");
}

#[test]
fn run_rejects_a_stream_without_a_terminal_frame() {
    let (_directory, paths) = runtime_paths();
    let server = serve_frames(paths.clone(), vec![RunFrame::Stdout(b"truncated".to_vec())]);
    let error =
        run(&paths, &test_token(), &run_request(), |_frame| Ok(())).expect_err("no terminal frame");
    assert!(
        error
            .to_string()
            .contains("closed the connection before the command finished"),
        "{error}"
    );
    server.join().expect("server thread");
}

#[test]
fn run_stops_at_the_first_terminal_frame() {
    // A stream must end at its terminal frame; a client that has the
    // status must not wait for (or trust) whatever follows it.
    let (_directory, paths) = runtime_paths();
    let server = serve_frames(
        paths.clone(),
        vec![
            RunFrame::Exit(RunFinished::exited(RunExit::Signal(9))),
            RunFrame::Stdout(b"late".to_vec()),
        ],
    );
    let outcome = run(&paths, &test_token(), &run_request(), |_frame| Ok(()))
        .expect("first terminal frame wins");
    assert_eq!(
        outcome,
        RunOutcome::Exited(RunFinished::exited(RunExit::Signal(9)))
    );
    server.join().expect("server thread");
}

#[test]
fn run_rejects_a_malformed_frame() {
    let directory = TempDir::new().expect("tempdir");
    let paths = RuntimePaths::at(directory.path().join("malformed"));
    let socket = DaemonSocket::bind_at(paths.clone()).expect("bind");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = socket.accept_peer().expect("accept");
        let mut decoder = FrameDecoder::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).expect("read");
            if read == 0 {
                break;
            }
            decoder.push(&buffer[..read]).expect("push");
            if decoder.next_request().expect("request").is_some() {
                break;
            }
        }
        // A well-formed frame whose body is not a run frame.
        let body = br#"{"type":"pong"}"#;
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(body);
        stream.write_all(&frame).expect("write");
    });

    let error =
        run(&paths, &test_token(), &run_request(), |_frame| Ok(())).expect_err("not a run frame");
    assert!(
        error.to_string().contains("invalid daemon response"),
        "{error}"
    );
    server.join().expect("server thread");
}
