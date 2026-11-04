//! End-to-end tests for multi-binding `run` requests (TODO 4.5b).
//!
//! Split out of `tests/daemon_run.rs` to keep both files under the layout
//! limit. Every test runs a real `pmd` against a disposable vault.

#![cfg(unix)]

mod support;

use support::*;

use std::fs;

use passmgr::crypto;
use passmgr::grant::{Capabilities, Grant, GrantSpec, Scope};
use passmgr::protocol::{
    EnvBinding, Request, Response, ResponseError, RunExit, RunFinished, RunFrame,
};
use passmgr::store::{self, Credential};
use passmgr::vault::Vault;

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

#[test]
fn a_run_injects_and_redacts_every_binding() {
    let fixture = Fixture::with_two_secrets();
    let second_reference = fixture.second_reference.clone().expect("second entry");
    let mut child = fixture.start();
    let socket = fixture.socket();

    let mut request = fixture.run_request(
        "FIRST",
        &[
            "/bin/sh",
            "-c",
            "printf '%s|%s|%s' \"$FIRST\" \"$SECOND\" \"$PLAIN\"",
        ],
    );
    if let Request::Run(run) = &mut request {
        run.env.push(EnvBinding {
            name: "SECOND".into(),
            reference: second_reference,
        });
        run.plain_env.push(("PLAIN".into(), "visible".into()));
    }

    let (frames, raw) = read_run(&socket, &fixture.token, &request);
    assert_eq!(
        stdout_bytes(&frames),
        b"[REDACTED]|[REDACTED]|visible",
        "both secrets are injected and redacted, the plain value is untouched"
    );
    assert_eq!(
        frames.last(),
        Some(&RunFrame::Exit(RunFinished::exited(RunExit::Code(0))))
    );
    for secret in [SECRET, SECOND_SECRET] {
        assert!(
            !raw.windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "the socket reply leaked a secret"
        );
        assert!(!String::from_utf8_lossy(&raw).contains(secret));
    }
    assert_eq!(
        support::request(&fixture.socket(), &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn one_out_of_scope_binding_denies_the_whole_run_without_spending_it() {
    let fixture = Fixture::with_two_secrets();
    let second_reference = fixture.second_reference.clone().expect("second entry");
    let mut child = fixture.start();

    let now = unix_now();
    let (credentials, base_grant, first_id) = {
        let vault = Vault::open_with_key(&fixture.vault, fixture.key.as_slice()).expect("open");
        let first = vault
            .list()
            .iter()
            .find(|credential| credential.reference() == fixture.reference)
            .expect("first credential")
            .id();
        (vault.list().to_vec(), vault.grants()[0].clone(), first)
    };
    let restricted = Grant::create(
        GrantSpec {
            label: "first only".into(),
            scope: Scope::new(vec![first_id], Vec::new(), None).expect("scope"),
            commands: base_grant.commands().to_vec(),
            capabilities: Capabilities::RUN,
            expires_at: now + 3_600,
            max_uses: None,
        },
        *base_grant.token_hash(),
        now,
    )
    .expect("restricted grant");
    rewrite_vault(&fixture, &credentials, std::slice::from_ref(&restricted));

    let marker = fixture.temp_path("out-of-scope-marker");
    let script = format!("printf ran > {}", marker.display());
    let mut run = fixture.run_request("FIRST", &["/bin/sh", "-c", &script]);
    if let Request::Run(run) = &mut run {
        run.env.push(EnvBinding {
            name: "SECOND".into(),
            reference: second_reference,
        });
    }

    let (frames, raw) = read_run(&fixture.socket(), &fixture.token, &run);
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::NotFound)]);
    assert!(!marker.exists(), "a denied run must not spawn");
    assert_eq!(
        Vault::open_with_key(&fixture.vault, fixture.key.as_slice())
            .expect("open vault")
            .grants()[0]
            .uses(),
        0,
        "an out-of-scope binding must not spend the grant"
    );

    let audit = fs::read_to_string(fixture._directory.path().join("state/passmgr/audit.jsonl"))
        .expect("read audit");
    assert!(
        audit.contains("\"outcome\":\"not_found\""),
        "the denied multi-binding run must be audited: {audit}"
    );
    for secret in [SECRET, SECOND_SECRET] {
        assert!(!audit.contains(secret));
        assert!(!String::from_utf8_lossy(&raw).contains(secret));
    }

    assert_eq!(
        support::request(&fixture.socket(), &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn duplicate_environment_names_are_refused_before_spawning() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let body = format!(
        r#"{{"version":4,"token":"{}","request":{{"type":"run","env":[{{"name":"DUP","ref":"{ref}"}},{{"name":"DUP","ref":"{ref}"}}],"plain_env":{{}},"command":["/bin/sh","-c","true"],"cwd":"/","grant":"{}"}}}}"#,
        fixture.token.to_hex().as_str(),
        fixture.grant.to_hex().as_str(),
        ref = fixture.reference,
    );
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    assert_eq!(
        raw_request(&fixture.socket(), &frame),
        Response::Error(ResponseError::BadRequest)
    );
    assert_eq!(
        support::request(&fixture.socket(), &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}
