//! End-to-end tests for the `run` request: grant authorization, injection,
//! redaction, use counting and denial paths. Split from `daemon.rs` so neither
//! file grows past the layout limit.

#![cfg(unix)]

mod support;

use support::*;

use passmgr::grant::GrantToken;
use passmgr::protocol::{
    GrantRevokeRequest, MAX_CHUNK_BYTES, Request, Response, ResponseError, RunExit, RunFrame,
};
use passmgr::vault::Vault;

#[test]
fn run_injects_the_secret_and_redacts_stdout_and_stderr() {
    let fixture = Fixture::new();
    let child = fixture.start();
    let socket = fixture.socket();

    let (frames, raw) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request(
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

    let mut missing = fixture.run_request("API_KEY", &["/bin/true"]);
    if let Request::Run(run) = &mut missing {
        run.reference = "pm://00112233445566778899aabbccddeeff".into();
    }
    let (frames, _) = read_run(&socket, &fixture.token, &missing);
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::NotFound)]);

    let program = fixture.spawn_fail_program.to_str().expect("utf-8 path");
    std::fs::set_permissions(
        &fixture.spawn_fail_program,
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .expect("chmod program");
    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &[program]),
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
fn run_requires_a_grant_beyond_the_session_token() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();

    // A different, well-formed grant token is denied. The session token is
    // not enough on its own.
    let mut wrong = fixture.run_request("API_KEY", &["/bin/true"]);
    if let Request::Run(run) = &mut wrong {
        run.grant = GrantToken::from_hex(&"22".repeat(32)).expect("token");
    }
    let (frames, _) = read_run(&socket, &fixture.token, &wrong);
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);

    // `run` cannot even be decoded without a grant field.
    let body = format!(
        r#"{{"version":4,"token":"{}","request":{{"type":"run","env":"API_KEY","ref":"{}","command":["/bin/true"],"cwd":"/"}}}}"#,
        fixture.token.to_hex().as_str(),
        fixture.reference,
    );
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    assert_eq!(
        raw_request(&socket, &frame),
        Response::Error(ResponseError::BadRequest)
    );

    // The real grant works and the use is recorded before the child starts.
    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames.last(), Some(&RunFrame::Exit(RunExit::Code(0))));

    let vault = Vault::open_with_key(&fixture.vault, fixture.key.as_slice()).expect("open vault");
    assert_eq!(vault.grants().len(), 1);
    assert_eq!(vault.grants()[0].uses(), 1);
    assert!(vault.grants()[0].last_used_unix().is_some());
    let grant_id = vault.grants()[0].id();
    drop(vault);

    // Revocation takes effect immediately.
    assert_eq!(
        request(
            &socket,
            &fixture.token,
            &Request::GrantRevoke(GrantRevokeRequest::Id(grant_id)),
        ),
        Response::GrantRevoked { revoked: 1 }
    );
    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn run_stops_at_a_use_limited_grant() {
    let fixture = Fixture::with_max_uses(1);
    let mut child = fixture.start();
    let socket = fixture.socket();

    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames.last(), Some(&RunFrame::Exit(RunExit::Code(0))));

    // The second use exceeds the limit recorded in the vault.
    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);

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
            &fixture.run_request(
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
        &fixture.run_request(
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
