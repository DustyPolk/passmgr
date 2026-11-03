//! End-to-end test for approving a grant over the real daemon socket.
//!
//! Split out of `tests/daemon.rs` by TODO 3.4c to keep that file under the
//! ~1,000-line limit.

#![cfg(unix)]

mod support;

use support::*;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use passmgr::grant::{Capabilities, GrantRequest, GrantSpec, Scope, TokenHash};
use passmgr::presence::{ChallengeNonce, Proof};
use passmgr::protocol::{self, GrantCreateRequest, ProveRequest, Request, Response, ResponseError};
use passmgr::token::SessionToken;

/// The digest a human proves over a grant request can be spent exactly once
/// by `grant_create`, and only for that exact request. The answer is a fixed
/// `grant_approved` with no token, hash, id or label, and the daemon never
/// writes the vault: the CLI that holds the raw token does.
#[test]
fn grant_create_spends_the_approval_once_without_writing_the_vault() {
    let fixture = Fixture::new();
    let child = fixture.start();
    let socket = fixture.socket();
    let before = fs::read(&fixture.vault).expect("read vault");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let approved = grant_request(now + 600);
    let hash_hex = approved.token_hash().to_hex();

    let nonce = challenge(&socket, &fixture.token);
    let digest = approved.digest();
    let proof = Proof::compute(fixture.key.as_slice(), &nonce, &digest).expect("compute proof");
    assert_eq!(
        present(
            &socket,
            &fixture.token,
            ProveRequest {
                nonce,
                digest,
                proof,
            },
        ),
        Response::Proven
    );

    let frame = protocol::encode(
        &fixture.token,
        &Request::GrantCreate(GrantCreateRequest::from_grant_request(&approved)),
    )
    .expect("encode");
    let mut stream = UnixStream::connect(&socket).expect("connect");
    stream.write_all(&frame).expect("write request");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).expect("read answer");
    let text = String::from_utf8(answer.clone()).expect("utf8 answer");
    assert!(!text.contains(hash_hex.as_str()), "{text}");
    assert!(!text.contains(SECRET), "{text}");
    assert_eq!(
        protocol::decode_response(&answer).expect("decode answer"),
        Response::GrantApproved
    );

    // The approval is spent by its first use, so the identical request is
    // refused even though its digest is the one that was proven.
    assert_eq!(
        request(
            &socket,
            &fixture.token,
            &Request::GrantCreate(GrantCreateRequest::from_grant_request(&approved)),
        ),
        Response::Error(ResponseError::Denied)
    );
    assert_eq!(
        fs::read(&fixture.vault).expect("read vault"),
        before,
        "grant_create must not write the vault"
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    let output = child.wait_with_output().expect("wait for pmd");
    assert!(output.status.success());
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(hash_hex.as_str()),
            "the token hash must never be written to daemon output"
        );
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

/// A valid grant request for a caller-chosen expiry.
fn grant_request(expires_at: u64) -> GrantRequest {
    GrantRequest::new(
        GrantSpec {
            label: "deploy prod".into(),
            scope: Scope::new(Vec::new(), vec!["prod".into()], None).expect("scope"),
            commands: vec!["/usr/bin/gh".into()],
            capabilities: Capabilities::RUN,
            expires_at,
            max_uses: Some(2),
        },
        TokenHash::of(b"grant-token"),
    )
    .expect("grant request")
}
