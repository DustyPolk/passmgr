//! End-to-end tests for the `run` request: grant authorization, injection,
//! redaction, use counting and denial paths. Split from `daemon.rs` so neither
//! file grows past the layout limit.

#![cfg(unix)]

mod support;

use support::*;

use std::fs;
use std::time::{Duration, Instant};

use passmgr::crypto;
use passmgr::grant::{Capabilities, Grant, GrantSpec, GrantToken, Scope};
use passmgr::protocol::{
    GrantRevokeRequest, ListRequest, MAX_CHUNK_BYTES, Request, Response, ResponseError, RunExit,
    RunFrame,
};
use passmgr::store::{self, Credential};
use passmgr::vault::Vault;
use zeroize::Zeroizing;

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
    assert_exited(&frames, 0);
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
        run.env[0].reference = "pm://00112233445566778899aabbccddeeff".into();
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
    assert_exited(&frames, 0);

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
    assert_exited(&frames, 0);

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

/// R.44: the vault is an ordinary file, so an attacker running as the same
/// user can put an older copy back. That copy still opens with the daemon's
/// key, but the daemon remembers that this grant already spent its one use and
/// refuses instead of running it again.
#[test]
fn restoring_an_older_vault_cannot_restore_a_spent_use() {
    let fixture = Fixture::with_max_uses(1);
    let mut child = fixture.start();
    let socket = fixture.socket();
    let snapshot = fs::read(&fixture.vault).expect("snapshot vault");

    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_exited(&frames, 0);

    fs::write(&fixture.vault, &snapshot).expect("restore older vault");
    let (frames, raw) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);
    assert!(
        !raw.windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

/// R.44: a rollback must not clear a revocation either -- and it must not be
/// able to disable the kill switch, so revoking the rolled-back vault still
/// works and is recorded.
#[test]
fn restoring_an_older_vault_cannot_clear_a_revocation() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let snapshot = fs::read(&fixture.vault).expect("snapshot vault");

    assert_eq!(
        request(
            &socket,
            &fixture.token,
            &Request::GrantRevoke(GrantRevokeRequest::All)
        ),
        Response::GrantRevoked { revoked: 1 }
    );
    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);

    fs::write(&fixture.vault, &snapshot).expect("restore older vault");
    let (frames, raw) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);
    assert!(
        !raw.windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );

    // The kill switch still works on the rolled-back file.
    assert_eq!(
        request(
            &socket,
            &fixture.token,
            &Request::GrantRevoke(GrantRevokeRequest::All)
        ),
        Response::GrantRevoked { revoked: 1 }
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

/// Revoke every grant on disk behind the daemon's back, as `pm grant revoke`
/// in another process would.
fn revoke_on_disk(fixture: &Fixture) {
    let vault = Vault::open_with_key(&fixture.vault, fixture.key.as_slice()).expect("open vault");
    let credentials = vault.list().to_vec();
    let mut grants = vault.grants().to_vec();
    for grant in &mut grants {
        grant.revoke(unix_now()).expect("revoke");
    }
    rewrite_vault(fixture, &credentials, &grants);
}

/// Put `snapshot` (taken before the revocation) back and prove the daemon
/// still refuses to run with the grant, then stop it.
fn assert_rollback_is_refused(fixture: &Fixture, child: &mut std::process::Child, snapshot: &[u8]) {
    let socket = fixture.socket();
    fs::write(&fixture.vault, snapshot).expect("restore older vault");
    let (frames, raw) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);
    assert!(
        !raw.windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(child, WAIT).success());
}

/// SECURITY.md limit 7 promises that a revocation this daemon has seen cannot
/// be rolled back. Seeing one at startup counts: the daemon opens the vault
/// to verify its key before it serves anything.
#[test]
fn a_revocation_seen_at_startup_survives_a_rollback() {
    let fixture = Fixture::new();
    let snapshot = fs::read(&fixture.vault).expect("snapshot vault");
    revoke_on_disk(&fixture);
    let mut child = fixture.start();
    assert_rollback_is_refused(&fixture, &mut child, &snapshot);
}

/// A revocation that only ever reached this daemon as a no-op `grant_revoke`
/// (nothing to change, nothing saved) is still one it has seen.
#[test]
fn a_revocation_seen_as_a_no_op_revoke_survives_a_rollback() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let snapshot = fs::read(&fixture.vault).expect("snapshot vault");
    revoke_on_disk(&fixture);
    assert_eq!(
        request(
            &fixture.socket(),
            &fixture.token,
            &Request::GrantRevoke(GrantRevokeRequest::All)
        ),
        Response::GrantRevoked { revoked: 0 }
    );
    assert_rollback_is_refused(&fixture, &mut child, &snapshot);
}

/// A revocation that this daemon only saw while denying a metadata read is
/// still one it has seen.
#[test]
fn a_revocation_seen_by_a_denied_list_survives_a_rollback() {
    let fixture = Fixture::with_capabilities(Capabilities::RUN.union(Capabilities::LIST));
    let mut child = fixture.start();
    let snapshot = fs::read(&fixture.vault).expect("snapshot vault");
    revoke_on_disk(&fixture);
    assert_eq!(
        request(
            &fixture.socket(),
            &fixture.token,
            &Request::List(ListRequest {
                tags: Vec::new(),
                query: None,
                grant: fixture.grant.clone(),
            })
        ),
        Response::Error(ResponseError::Denied)
    );
    assert_rollback_is_refused(&fixture, &mut child, &snapshot);
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Replace the vault's contents without changing the container header, so the
/// running daemon's key still opens it (the salt and KDF parameters are kept).
fn rewrite_vault(fixture: &Fixture, credentials: &[Credential], grants: &[Grant]) {
    let plaintext = store::encode(credentials, grants).expect("encode store");
    let template = fs::read(&fixture.vault).expect("read vault");
    let container = crypto::encrypt_with_key(&plaintext, fixture.key.as_slice(), &template)
        .expect("encrypt vault");
    fs::write(&fixture.vault, &container).expect("write vault");
}

/// Run with an arbitrary reference; `Fixture::run_request` always uses the
/// one credential the fixture was built with.
fn run_with_ref(fixture: &Fixture, reference: &str, command: &[&str]) -> Vec<RunFrame> {
    let mut request = fixture.run_request("API_KEY", command);
    if let Request::Run(run) = &mut request {
        run.env[0].reference = reference.to_owned();
    }
    read_run(&fixture.socket(), &fixture.token, &request).0
}

/// R.31: a grant token must not work as an existence oracle for a grant that
/// can never be used. Every credential-independent refusal has to answer the
/// same for an existing and a nonexistent reference, and a credential that
/// exists but is outside the scope must answer like a missing one.
#[test]
fn a_denied_run_does_not_reveal_whether_a_reference_exists() {
    let fixture = Fixture::new();
    let mut child = fixture.start();

    let now = unix_now();
    let (credentials, base_grant) = {
        let vault = Vault::open_with_key(&fixture.vault, fixture.key.as_slice()).expect("open");
        (vault.list().to_vec(), vault.grants()[0].clone())
    };
    let token_hash = *base_grant.token_hash();
    let scope = base_grant.scope().clone();
    let commands = base_grant.commands().to_vec();
    let marker = fixture.temp_path("denied-run-marker");
    let script = format!("printf ran > {}", marker.display());
    let absent = "pm://00000000000000000000000000000000";

    let mut revoked = base_grant.clone();
    revoked.revoke(now).expect("revoke");
    // `Grant::create` refuses an expiry that is not after its `now`, so the
    // grant is created in the past and is already expired when stored.
    let expired = Grant::create(
        GrantSpec {
            label: "expired".into(),
            scope: scope.clone(),
            commands: commands.clone(),
            capabilities: Capabilities::RUN,
            expires_at: now - 3_600,
            max_uses: None,
        },
        token_hash,
        now - 7_200,
    )
    .expect("expired grant");
    let mut exhausted = Grant::create(
        GrantSpec {
            label: "exhausted".into(),
            scope: scope.clone(),
            commands: commands.clone(),
            capabilities: Capabilities::RUN,
            expires_at: now + 3_600,
            max_uses: Some(1),
        },
        token_hash,
        now,
    )
    .expect("exhausted grant");
    exhausted.mark_used(now).expect("use");
    let unlisted = Credential::new(
        "other.test".into(),
        "bob".into(),
        Zeroizing::new("other-canary-value".into()),
    )
    .expect("credential");
    let out_of_scope = Grant::create(
        GrantSpec {
            label: "out of scope".into(),
            scope: Scope::new(vec![unlisted.id()], Vec::new(), None).expect("scope"),
            commands,
            capabilities: Capabilities::RUN,
            expires_at: now + 3_600,
            max_uses: None,
        },
        token_hash,
        now,
    )
    .expect("out-of-scope grant");

    let cases = [
        ("revoked", revoked, ResponseError::Denied, 0),
        ("expired", expired, ResponseError::Denied, 0),
        ("exhausted", exhausted, ResponseError::Denied, 1),
        ("out of scope", out_of_scope, ResponseError::NotFound, 0),
    ];
    for (label, grant, expected, expected_uses) in cases {
        rewrite_vault(&fixture, &credentials, std::slice::from_ref(&grant));

        let existing = run_with_ref(&fixture, &fixture.reference, &["/bin/sh", "-c", &script]);
        let missing = run_with_ref(&fixture, absent, &["/bin/sh", "-c", &script]);

        assert_eq!(
            existing,
            vec![RunFrame::Error(expected)],
            "{label}: an existing reference"
        );
        assert_eq!(
            missing, existing,
            "{label}: a nonexistent reference must answer exactly like an existing one"
        );
        assert!(!marker.exists(), "{label}: a denied run must not spawn");

        let vault =
            Vault::open_with_key(&fixture.vault, fixture.key.as_slice()).expect("open vault");
        assert_eq!(
            vault.grants()[0].uses(),
            expected_uses,
            "{label}: a denied run must not record a use"
        );
    }

    // The vault rewrites did not disturb the running daemon.
    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Lock),
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
    assert_exited(&frames, 0);

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

/// R.34: the daemon must spawn the canonical path it authorized, and that path
/// must be the child's `argv[0]`. A symlink is the request path here; the old
/// code spawned the link, so a program that behaves differently depending on
/// the name it was called by (a multi-call binary) could be selected by the
/// caller's link name even though the allowlist held the canonical target.
#[test]
fn the_child_is_spawned_as_the_canonical_program_not_the_request_path() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();

    let link = fixture.temp_path("sh-link");
    std::os::unix::fs::symlink("/bin/sh", &link).expect("symlink to /bin/sh");
    let link = link.to_str().expect("utf-8 path").to_owned();
    let canonical = fs::canonicalize("/bin/sh").expect("canonical /bin/sh");
    let canonical = canonical.to_str().expect("utf-8 path").to_owned();

    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &[&link, "-c", "printf %s \"$0\""]),
    );

    assert_eq!(stdout_bytes(&frames), canonical.as_bytes());
    assert_exited(&frames, 0);

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

/// Wait until `pmd` has opened the vault lock and narrowed its mode.
///
/// The daemon is non-dumpable, so `/proc/<pid>/fd` is not readable; the
/// unconditional `chmod` in `acquire_write_lock` updates the lock file's
/// ctime, which is the first observable step after the vault is read and
/// authorized. The caller compares against a ctime captured before the run.
fn wait_until_the_lock_is_open(lock: &std::path::Path, before: (i64, i64)) {
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + WAIT;
    loop {
        if let Ok(metadata) = fs::metadata(lock) {
            if (metadata.ctime(), metadata.ctime_nsec()) != before {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "pmd never opened the vault lock file"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A link swapped after the allowlist check must not redirect the exec.
///
/// The run authorized `/bin/true` through `tool`. While the daemon waits for
/// the vault write lock (it has already canonicalized the path and passed the
/// allowlist check), the link is repointed at a script that writes the secret
/// somewhere. The daemon must still exec the canonical `/bin/true`, so nothing
/// runs and the secret never lands in the loot file.
///
/// The daemon keeps the lock file open while it retries `flock`, so
/// `/proc/<pid>/fd` is a deterministic "the check has happened" signal; no
/// fixed sleep is involved.
#[cfg(target_os = "linux")]
#[test]
fn a_symlink_swapped_after_the_allowlist_check_cannot_change_the_program() {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;

    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();

    let tool = fixture.temp_path("tool");
    std::os::unix::fs::symlink("/bin/true", &tool).expect("symlink to /bin/true");
    let loot = fixture.temp_path("loot");
    let replacement = fixture.temp_path("replacement");
    fs::write(
        &replacement,
        format!("#!/bin/sh\nprintf %s \"$API_KEY\" > '{}'\n", loot.display()),
    )
    .expect("write replacement");
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755))
        .expect("chmod replacement");

    // Hold the vault write lock. The daemon reads and authorizes the vault,
    // then blocks recording the use until this is released.
    let lock_path = passmgr::vault::lock_path(&fixture.vault);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .expect("open vault lock");
    // SAFETY: `as_raw_fd` is a valid descriptor owned by `lock`.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let before = fs::metadata(&lock_path)
        .map(|metadata| (metadata.ctime(), metadata.ctime_nsec()))
        .expect("lock metadata");

    let tool_arg = tool.to_str().expect("utf-8 path").to_owned();
    let run_request = fixture.run_request("API_KEY", &[&tool_arg]);
    let token = fixture.token.clone();
    let run_socket = socket.clone();
    let reader = std::thread::spawn(move || read_run(&run_socket, &token, &run_request));

    wait_until_the_lock_is_open(&lock_path, before);
    fs::remove_file(&tool).expect("remove the checked link");
    std::os::unix::fs::symlink(&replacement, &tool).expect("swap the link");
    drop(lock);

    let (frames, raw) = reader.join().expect("run thread");
    assert!(
        !loot.exists(),
        "the swapped program ran and captured the injected secret"
    );
    assert_exited(&frames, 0);
    assert!(
        !raw.windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

/// R.45: a grant that expires while the run waits for the vault write lock
/// must be denied. The daemon used to read the clock once, before the lock
/// wait, and then authorize with it up to the lock timeout later.
#[test]
fn a_run_is_denied_when_its_grant_expires_during_the_lock_wait() {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::io::AsRawFd;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let fixture = Fixture::with_grant_expiring_in(3);
    let mut child = fixture.start();
    let socket = fixture.socket();

    // Hold the vault write lock before the request is sent, so the daemon can
    // only authorize after this test releases it.
    let lock_path = passmgr::vault::lock_path(&fixture.vault);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .expect("open vault lock");
    // SAFETY: `as_raw_fd` is a valid descriptor owned by `lock`.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let before = fs::metadata(&lock_path)
        .map(|metadata| (metadata.ctime(), metadata.ctime_nsec()))
        .expect("lock metadata");

    let run_request = fixture.run_request("API_KEY", &["/bin/true"]);
    let token = fixture.token.clone();
    let run_socket = socket.clone();
    let reader = std::thread::spawn(move || read_run(&run_socket, &token, &run_request));

    // The daemon opens (and `chmod`s) the lock before it can authorize, so
    // once that is observable the old code had already read its clock. Guard
    // that this happened before expiry, or the test would pass vacuously.
    wait_until_the_lock_is_open(&lock_path, before);
    let observed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    assert!(
        observed < fixture.grant_expires_at,
        "the daemon read the clock after the grant expired; the test proves nothing"
    );

    // Wait until the grant is at least one whole second past expiry, so the
    // daemon's fresh read cannot land in the same second as `expires_at`.
    let expired = UNIX_EPOCH + Duration::from_secs(fixture.grant_expires_at + 1);
    if let Ok(remaining) = expired.duration_since(SystemTime::now()) {
        std::thread::sleep(remaining);
    }
    drop(lock);

    let (frames, raw) = reader.join().expect("run thread");
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);
    assert!(
        !raw.windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

/// R.35: `pmd` itself must enforce the grant's command allowlist and its
/// `run` capability. Each case here fails if the daemon authorizes the
/// grant's first allowed command (or any other command) instead of the
/// program the request names.
#[test]
fn run_enforces_the_command_allowlist_and_the_run_capability() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();

    // A program outside the grant's allowlist that leaves a marker if it
    // runs, so a leak is visible even though every answer is a frame.
    let marker = fixture.temp_path("unlisted-program-ran");
    let program = fixture.temp_path("unlisted-program");
    fs::write(
        &program,
        format!(
            "#!/bin/sh\nprintf ran > '{}'\n",
            marker.to_str().expect("utf-8 path")
        ),
    )
    .expect("write unlisted program");
    fs::set_permissions(
        &program,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("chmod unlisted program");
    let program = fs::canonicalize(&program).expect("canonical unlisted program");
    let program = program.to_str().expect("utf-8 path").to_owned();

    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &[&program]),
    );
    assert_eq!(
        frames,
        vec![RunFrame::Error(ResponseError::Denied)],
        "an unlisted program must be denied"
    );
    assert!(!marker.exists(), "an unlisted program must not run");

    // The same target under an innocent link name: the daemon canonicalizes
    // the path before it consults the allowlist, so the name cannot smuggle
    // the program in.
    let innocent = fixture.temp_path("innocent");
    std::os::unix::fs::symlink(&program, &innocent).expect("symlink to unlisted program");
    let innocent = innocent.to_str().expect("utf-8 path").to_owned();
    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &[&innocent]),
    );
    assert_eq!(
        frames,
        vec![RunFrame::Error(ResponseError::Denied)],
        "a link to an unlisted program must be denied"
    );
    assert!(!marker.exists(), "a linked unlisted program must not run");

    // A grant that allows the same programs but only the `list` capability
    // must still refuse to run one of them.
    let now = unix_now();
    let (credentials, base_grant) = {
        let vault = Vault::open_with_key(&fixture.vault, fixture.key.as_slice()).expect("open");
        (vault.list().to_vec(), vault.grants()[0].clone())
    };
    let list_only = Grant::create(
        GrantSpec {
            label: "list only".into(),
            scope: base_grant.scope().clone(),
            commands: base_grant.commands().to_vec(),
            capabilities: Capabilities::LIST,
            expires_at: now + 3_600,
            max_uses: None,
        },
        *base_grant.token_hash(),
        now,
    )
    .expect("list-only grant");
    rewrite_vault(&fixture, &credentials, std::slice::from_ref(&list_only));

    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request(
            "API_KEY",
            &[
                "/bin/sh",
                "-c",
                &format!("printf ran > '{}'", marker.display()),
            ],
        ),
    );
    assert_eq!(
        frames,
        vec![RunFrame::Error(ResponseError::Denied)],
        "a grant without the run capability must be denied"
    );
    assert!(!marker.exists(), "a grant without RUN must not spawn");
    let vault = Vault::open_with_key(&fixture.vault, fixture.key.as_slice()).expect("open vault");
    assert_eq!(
        vault.grants()[0].uses(),
        0,
        "a denied run must not record a use"
    );
    drop(vault);

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

/// R.35: use limits are enforced by the vault under its write lock, so
/// concurrent runs cannot each pass the check against the same stale state.
#[test]
fn concurrent_runs_cannot_exceed_max_uses() {
    let fixture = Fixture::with_max_uses(3);
    let mut child = fixture.start();
    let socket = fixture.socket();

    let mut readers = Vec::new();
    for _ in 0..16 {
        let socket = socket.clone();
        let token = fixture.token.clone();
        let run = fixture.run_request("API_KEY", &["/bin/true"]);
        readers.push(std::thread::spawn(move || {
            read_run(&socket, &token, &run).0
        }));
    }
    let results: Vec<Vec<RunFrame>> = readers
        .into_iter()
        .map(|reader| reader.join().expect("run thread"))
        .collect();

    let ran = results.iter().filter(|frames| is_exited(frames, 0)).count();
    let denied = results
        .iter()
        .filter(|frames| frames.as_slice() == [RunFrame::Error(ResponseError::Denied)])
        .count();
    assert_eq!(ran, 3, "exactly max_uses runs may spawn, got {results:?}");
    assert_eq!(denied, 13, "every other run must be denied: {results:?}");

    let vault = Vault::open_with_key(&fixture.vault, fixture.key.as_slice()).expect("open vault");
    assert_eq!(vault.grants()[0].uses(), 3);
    drop(vault);

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn run_reports_a_timeout_and_truncation_in_the_terminal_frame() {
    let fixture = Fixture::new();
    let child = fixture.start();
    let socket = fixture.socket();

    // A cap on stdout: the child writes 100 bytes, the daemon relays 16.
    let mut capped = fixture.run_request("API_KEY", &["/bin/sh", "-c", r#"printf "%0100d" 0"#]);
    if let Request::Run(run) = &mut capped {
        run.limits.max_output_bytes = 16;
    }
    let (frames, _) = read_run(&socket, &fixture.token, &capped);
    assert_eq!(stdout_bytes(&frames).len(), 16);
    let Some(RunFrame::Exit(finished)) = frames.last() else {
        panic!("expected a terminal frame");
    };
    assert!(finished.stdout_truncated);
    assert!(!finished.stderr_truncated);
    assert!(!finished.timed_out);
    assert_eq!(finished.exit, RunExit::Code(0));

    // A one-second deadline on a child that would run for thirty.
    let mut slow = fixture.run_request("API_KEY", &["/bin/sh", "-c", "sleep 30"]);
    if let Request::Run(run) = &mut slow {
        run.limits.timeout_secs = 1;
    }
    let started = Instant::now();
    let (frames, _) = read_run(&socket, &fixture.token, &slow);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the timeout took {:?}",
        started.elapsed()
    );
    let Some(RunFrame::Exit(finished)) = frames.last() else {
        panic!("expected a terminal frame");
    };
    assert!(finished.timed_out);
    assert_eq!(finished.exit, RunExit::Signal(libc::SIGTERM as u8));

    // A timed-out run is a completed use, not a daemon failure.
    assert_eq!(
        request(&socket, &fixture.token, &Request::Ping),
        Response::Pong
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
