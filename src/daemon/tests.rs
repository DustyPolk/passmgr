//! Unit tests for the daemon, moved out of `src/daemon.rs` by TODO 3.4c
//! to keep that file under the ~1,000-line limit. The tests are unchanged
//! apart from the module wrapper.

use super::*;

fn handover_bytes(key: &[u8], token: &SessionToken) -> Vec<u8> {
    let mut bytes = key.to_vec();
    bytes.extend_from_slice(token.as_bytes());
    bytes
}

#[test]
fn reads_exactly_one_key_and_token_and_rejects_short_input() {
    let key = [7u8; KEY_LEN];
    let token = SessionToken::from_bytes(&[0x42u8; TOKEN_BYTES]).expect("token");
    let bytes = handover_bytes(&key, &token);

    let mut reader = &bytes[..];
    let handover = read_handover(&mut reader).expect("valid handover");
    assert_eq!(handover.key().as_slice(), &key);
    assert!(handover.token().matches(&token));

    for length in [0usize, 1, KEY_LEN - 1, KEY_LEN, KEY_LEN + TOKEN_BYTES - 1] {
        let mut reader = &bytes[..length];
        assert!(
            matches!(read_handover(&mut reader), Err(DaemonError::KeyHandover(_))),
            "{length} bytes must be rejected"
        );
    }
}

#[test]
fn rejects_trailing_bytes_after_the_key_and_token() {
    let key = [9u8; KEY_LEN];
    let token = SessionToken::from_bytes(&[1u8; TOKEN_BYTES]).expect("token");
    let mut bytes = handover_bytes(&key, &token);
    bytes.push(0);
    let mut reader = &bytes[..];
    assert!(matches!(
        read_handover(&mut reader),
        Err(DaemonError::KeyHandover(_))
    ));
}

#[test]
fn handover_debug_never_contains_key_or_token_bytes() {
    let key = [0xABu8; KEY_LEN];
    let token = SessionToken::from_bytes(&[0xCDu8; TOKEN_BYTES]).expect("token");
    let bytes = handover_bytes(&key, &token);
    let mut reader = &bytes[..];
    let handover = read_handover(&mut reader).expect("valid handover");
    let text = format!("{handover:?}");
    assert!(!text.contains("171"), "{text}");
    assert!(!text.contains("205"), "{text}");
    assert!(text.contains("redacted"), "{text}");
}

#[test]
fn locked_key_length_is_checked() {
    let key = Zeroizing::new(vec![0u8; KEY_LEN + 1]);
    assert!(matches!(
        LockedKey::new(key),
        Err(DaemonError::KeyHandover(_))
    ));
}

#[test]
fn debug_output_never_contains_key_bytes() {
    let key = Zeroizing::new(vec![0xABu8; KEY_LEN]);
    let locked = LockedKey::new(key).expect("valid key");
    let text = format!("{locked:?}");
    assert!(!text.contains("AB") && !text.contains("171"), "{text}");
    assert!(text.contains("LockedKey"));
}

#[test]
fn key_handover_errors_do_not_echo_bytes() {
    let mut reader = &b"short"[..];
    let error = read_handover(&mut reader).unwrap_err();
    assert!(!error.to_string().contains("short"));
}

#[test]
fn idle_timeout_parser_accepts_positive_seconds_only() {
    assert_eq!(parse_idle_timeout("60").unwrap(), Duration::from_secs(60));
    assert_eq!(parse_idle_timeout("1").unwrap(), Duration::from_secs(1));
    assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(900));

    for bad in ["0", "", "-1", "1.5", "15m", " 60"] {
        assert!(parse_idle_timeout(bad).is_err(), "'{bad}' must be rejected");
    }
}

/// Send one request over a socket pair and return the daemon's answer.
fn exchange(
    token: &SessionToken,
    request: &Request,
    key: &LockedKey,
    challenges: &mut presence::Challenges,
    approvals: &mut presence::Approvals,
) -> Response {
    let frame = protocol::encode(token, request).expect("encode");
    exchange_frame(&frame, token, key, challenges, approvals)
}

/// Send one already-encoded frame, for payloads [`exchange`] cannot build
/// because they are invalid by construction. Everything else is identical.
fn exchange_frame(
    frame: &[u8],
    token: &SessionToken,
    key: &LockedKey,
    challenges: &mut presence::Challenges,
    approvals: &mut presence::Approvals,
) -> Response {
    let (server, mut client) = UnixStream::pair().expect("socket pair");
    client.write_all(frame).expect("send request");
    let handled = handle_connection(server, token, key, challenges, approvals);
    assert!(
        !matches!(handled, Handled::Locked(_) | Handled::Run(..)),
        "a one-shot request must not hand off the socket"
    );

    let mut prefix = [0u8; 4];
    client.read_exact(&mut prefix).expect("read length");
    let length = u32::from_be_bytes(prefix) as usize;
    let mut frame = vec![0u8; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    client.read_exact(&mut frame[4..]).expect("read body");
    protocol::decode_response(&frame).expect("decode response")
}

/// Serve one `prove` over a socket pair and return the daemon's answer.
fn prove_round_trip(
    token: &SessionToken,
    key: &LockedKey,
    digest: presence::RequestDigest,
    challenges: &mut presence::Challenges,
    approvals: &mut presence::Approvals,
) -> Response {
    let nonce = challenges.issue(Instant::now()).expect("issue");
    let proof = presence::Proof::compute(key.as_slice(), &nonce, &digest).expect("compute");
    exchange(
        token,
        &Request::Prove(protocol::ProveRequest {
            nonce,
            digest,
            proof,
        }),
        key,
        challenges,
        approvals,
    )
}

/// A grant that is valid for the daemon's clock plus an offset.
fn grant_request(now: u64, offset: u64) -> crate::grant::GrantRequest {
    use crate::grant::{Capabilities, GrantRequest, GrantSpec, Scope, TokenHash};

    GrantRequest::new(
        GrantSpec {
            label: "deploy prod".into(),
            scope: Scope::new(Vec::new(), vec!["prod".into()], None).expect("scope"),
            commands: vec![std::path::PathBuf::from("/usr/bin/gh")],
            capabilities: Capabilities::RUN,
            expires_at: now + offset,
            max_uses: Some(2),
        },
        TokenHash::of(b"grant-token"),
    )
    .expect("grant request")
}

fn grant_create_round_trip(
    token: &SessionToken,
    key: &LockedKey,
    request: &crate::grant::GrantRequest,
    challenges: &mut presence::Challenges,
    approvals: &mut presence::Approvals,
) -> Response {
    use crate::protocol::GrantCreateRequest;

    exchange(
        token,
        &Request::GrantCreate(GrantCreateRequest::from_grant_request(request)),
        key,
        challenges,
        approvals,
    )
}

/// `Proven` records the digest that was actually proven, and only that
/// one: approving A can never authorize a write for B, and an approval is
/// spent by its first consumer. This is the daemon half of TODO R.15; the
/// write that spends an approval arrives with TODO 3.4.
#[test]
fn a_verified_proof_records_exactly_the_digest_it_covered() {
    let key = LockedKey::new(Zeroizing::new(vec![0x5Au8; KEY_LEN])).expect("key");
    let token = SessionToken::generate().expect("token");
    let mut challenges = presence::Challenges::new();
    let mut approvals = presence::Approvals::new();
    let approved = presence::RequestDigest::new([0xA1; 32]);
    let other = presence::RequestDigest::new([0xB2; 32]);

    assert_eq!(
        prove_round_trip(&token, &key, approved, &mut challenges, &mut approvals),
        Response::Proven
    );
    assert_eq!(approvals.pending(), 1, "exactly one digest was recorded");
    assert_eq!(
        approvals.take(&other, Instant::now()),
        Err(presence::PresenceError::NotApproved),
        "approving A must not authorize B"
    );
    assert_eq!(approvals.take(&approved, Instant::now()), Ok(()));
    assert_eq!(
        approvals.take(&approved, Instant::now()),
        Err(presence::PresenceError::NotApproved),
        "an approval authorizes exactly one write"
    );

    // A later proof records the digest it covered, not the old one.
    assert_eq!(
        prove_round_trip(&token, &key, other, &mut challenges, &mut approvals),
        Response::Proven
    );
    assert_eq!(
        approvals.take(&approved, Instant::now()),
        Err(presence::PresenceError::NotApproved)
    );
    assert_eq!(approvals.take(&other, Instant::now()), Ok(()));
}

#[test]
fn grant_create_is_accepted_only_for_the_digest_the_human_proved() {
    let key = LockedKey::new(Zeroizing::new(vec![0x5Au8; KEY_LEN])).expect("key");
    let token = SessionToken::generate().expect("token");
    let mut challenges = presence::Challenges::new();
    let mut approvals = presence::Approvals::new();
    let now = unix_now().expect("clock");
    let approved = grant_request(now, 600);
    let other = grant_request(now, 900);

    assert_eq!(
        prove_round_trip(
            &token,
            &key,
            approved.digest(),
            &mut challenges,
            &mut approvals
        ),
        Response::Proven
    );
    // A different request (different expiry) is refused and does not
    // spend the approval for the one the human actually saw.
    assert_eq!(
        grant_create_round_trip(&token, &key, &other, &mut challenges, &mut approvals),
        Response::Error(ResponseError::Denied)
    );
    assert_eq!(
        grant_create_round_trip(&token, &key, &approved, &mut challenges, &mut approvals),
        Response::GrantApproved
    );
    // The approval is spent: a replay of the same request is refused.
    assert_eq!(
        grant_create_round_trip(&token, &key, &approved, &mut challenges, &mut approvals),
        Response::Error(ResponseError::Denied)
    );
    assert_eq!(approvals.pending(), 0);
}

#[test]
fn grant_create_refuses_an_expired_request_without_spending_the_approval() {
    let key = LockedKey::new(Zeroizing::new(vec![0x5Au8; KEY_LEN])).expect("key");
    let token = SessionToken::generate().expect("token");
    let mut challenges = presence::Challenges::new();
    let mut approvals = presence::Approvals::new();
    let now = unix_now().expect("clock");
    let expired = grant_request(now - 1, 0);

    assert_eq!(
        prove_round_trip(
            &token,
            &key,
            expired.digest(),
            &mut challenges,
            &mut approvals
        ),
        Response::Proven
    );
    assert_eq!(
        grant_create_round_trip(&token, &key, &expired, &mut challenges, &mut approvals),
        Response::Error(ResponseError::BadRequest)
    );
    // No write could accept this request, so the human's approval is
    // still there for a corrected one.
    assert_eq!(approvals.pending(), 1);
    assert_eq!(approvals.take(&expired.digest(), Instant::now()), Ok(()));
}

/// TODO R.23: the daemon's pre-spend check also enforces the 30-day cap,
/// not just "expires in the future". A request one hour past the cap is a
/// `bad_request` and leaves the human's approval unspent; exactly 30 days is
/// still accepted, so the boundary did not drift shut.
#[test]
fn grant_create_refuses_a_request_longer_than_thirty_days_without_spending_the_approval() {
    use crate::grant::MAX_GRANT_LIFETIME_SECS;

    let key = LockedKey::new(Zeroizing::new(vec![0x5Au8; KEY_LEN])).expect("key");
    let token = SessionToken::generate().expect("token");
    let mut challenges = presence::Challenges::new();
    let mut approvals = presence::Approvals::new();
    let now = unix_now().expect("clock");
    // An hour over the cap, not one second over: the daemon reads its own
    // clock, so a tick between this `now` and the daemon's must not make the
    // test pass a request that is really over the limit. The exact one-second
    // boundary is covered deterministically by `grant::validate_expiry`'s own
    // tests.
    let too_long = grant_request(now, MAX_GRANT_LIFETIME_SECS + 3_600);

    assert_eq!(
        prove_round_trip(
            &token,
            &key,
            too_long.digest(),
            &mut challenges,
            &mut approvals
        ),
        Response::Proven
    );
    assert_eq!(
        grant_create_round_trip(&token, &key, &too_long, &mut challenges, &mut approvals),
        Response::Error(ResponseError::BadRequest)
    );
    // The writer would reject this on its expiry rule alone, so the approval
    // must survive for a corrected request.
    assert_eq!(approvals.pending(), 1);
    assert_eq!(approvals.take(&too_long.digest(), Instant::now()), Ok(()));

    // Exactly 30 days is the documented limit and must still be approved.
    let boundary = grant_request(now, MAX_GRANT_LIFETIME_SECS);
    assert_eq!(
        prove_round_trip(
            &token,
            &key,
            boundary.digest(),
            &mut challenges,
            &mut approvals
        ),
        Response::Proven
    );
    assert_eq!(
        grant_create_round_trip(&token, &key, &boundary, &mut challenges, &mut approvals),
        Response::GrantApproved
    );
    assert_eq!(approvals.pending(), 0);
}

/// TODO R.21: a frame whose command path carries terminal control characters
/// is refused at decode, before the approval store is consulted. The human's
/// approval for the request they actually saw is still spendable, and the
/// forged frame is a `bad_request`, never a `denied` that would look like a
/// spent approval.
#[test]
fn a_grant_frame_with_a_forged_command_does_not_spend_the_approval() {
    use crate::protocol::GrantCreateRequest;

    let key = LockedKey::new(Zeroizing::new(vec![0x5Au8; KEY_LEN])).expect("key");
    let token = SessionToken::generate().expect("token");
    let mut challenges = presence::Challenges::new();
    let mut approvals = presence::Approvals::new();
    let now = unix_now().expect("clock");
    let approved = grant_request(now, 600);

    assert_eq!(
        prove_round_trip(
            &token,
            &key,
            approved.digest(),
            &mut challenges,
            &mut approvals
        ),
        Response::Proven
    );

    // Take the exact frame the approving CLI would send, then rewrite only
    // its command list to the path an agent would like a human to misread.
    let encoded = protocol::encode(
        &token,
        &Request::GrantCreate(GrantCreateRequest::from_grant_request(&approved)),
    )
    .expect("encode");
    let mut value: serde_json::Value =
        serde_json::from_slice(&encoded[4..]).expect("decode envelope");
    value["request"]["commands"] = serde_json::json!(["/usr/bin/gh\u{1b}[2K\r/usr/bin/true"]);
    let body = value.to_string();
    let mut forged = (body.len() as u32).to_be_bytes().to_vec();
    forged.extend_from_slice(body.as_bytes());

    assert_eq!(
        exchange_frame(&forged, &token, &key, &mut challenges, &mut approvals),
        Response::Error(ResponseError::BadRequest)
    );
    assert_eq!(
        approvals.pending(),
        1,
        "a frame no write could accept must not spend the approval"
    );
    assert_eq!(approvals.take(&approved.digest(), Instant::now()), Ok(()));
}
