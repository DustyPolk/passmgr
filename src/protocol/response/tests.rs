//! Tests for response frames, split out of `response.rs` for the line limit.

use super::*;

/// Build a frame by hand, without going through `encode`.
fn frame(body: &str) -> Vec<u8> {
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    frame
}

#[test]
fn round_trips_every_response() {
    let nonce = ChallengeNonce::from_hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    )
    .expect("nonce");
    for response in [
        Response::Pong,
        Response::Locked,
        Response::Challenge(nonce),
        Response::Proven,
        Response::GrantApproved,
        Response::GrantRevoked { revoked: 0 },
        Response::GrantRevoked { revoked: 3 },
        Response::Error(ResponseError::BadRequest),
        Response::Error(ResponseError::Unsupported),
        Response::Error(ResponseError::Unauthorized),
        Response::Error(ResponseError::NotFound),
        Response::Error(ResponseError::SpawnFailed),
        Response::Error(ResponseError::Internal),
        Response::Error(ResponseError::Busy),
        Response::Error(ResponseError::Denied),
    ] {
        let encoded = encode_response(&response).expect("encode response");
        assert_eq!(
            decode_response(&encoded).expect("decode response"),
            response
        );
    }
}

#[test]
fn response_frames_have_a_fixed_shape_with_no_value_fields() {
    let pong = encode_response(&Response::Pong).expect("encode");
    let pong_body = br#"{"response":{"type":"pong"},"version":4}"#;
    assert_eq!(&pong[..4], &(pong_body.len() as u32).to_be_bytes());
    assert_eq!(&pong[4..], pong_body);

    let challenge = encode_response(&Response::Challenge(
        ChallengeNonce::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .expect("nonce"),
    ))
    .expect("encode");
    let challenge_body = br#"{"response":{"nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","type":"challenge"},"version":4}"#;
    assert_eq!(&challenge[4..], challenge_body);

    let error = encode_response(&Response::Error(ResponseError::BadRequest)).expect("encode");
    assert_eq!(
        &error[4..],
        br#"{"response":{"code":"bad_request","type":"error"},"version":4}"#
    );

    // The approval answer is a bare type: no token, hash, grant id or
    // label, so nothing about the grant it authorized can leak here.
    let approved = encode_response(&Response::GrantApproved).expect("encode");
    assert_eq!(
        &approved[4..],
        br#"{"response":{"type":"grant_approved"},"version":4}"#
    );

    // The revocation answer carries a count and nothing else: no id,
    // label or hash of what was revoked.
    let revoked = encode_response(&Response::GrantRevoked { revoked: 2 }).expect("encode");
    assert_eq!(
        &revoked[4..],
        br#"{"response":{"revoked":2,"type":"grant_revoked"},"version":4}"#
    );
}

#[test]
fn grant_revoked_rejects_a_missing_or_invalid_count() {
    for body in [
        r#"{"version":4,"response":{"type":"grant_revoked"}}"#,
        r#"{"version":4,"response":{"type":"grant_revoked","revoked":-1}}"#,
        r#"{"version":4,"response":{"type":"grant_revoked","revoked":"1"}}"#,
        r#"{"version":4,"response":{"type":"grant_revoked","revoked":4294967296}}"#,
    ] {
        assert!(
            decode_response(&frame(body)).is_err(),
            "{body} must be rejected"
        );
    }
    assert_eq!(
        decode_response(&frame(
            r#"{"version":4,"response":{"type":"grant_revoked","revoked":1}}"#
        ))
        .expect("decode"),
        Response::GrantRevoked { revoked: 1 }
    );
}

#[test]
fn unknown_response_types_and_codes_are_rejected() {
    let long = "x".repeat(MAX_TYPE_CHARS * 4);
    let unknown_type = frame(&format!(
        r#"{{"version":4,"response":{{"type":"{long}"}}}}"#
    ));
    match decode_response(&unknown_type) {
        Err(ProtocolError::UnknownResponse(echoed)) => {
            assert_eq!(echoed.chars().count(), MAX_TYPE_CHARS);
        }
        other => panic!("expected unknown response type, got {other:?}"),
    }

    let unknown_code = frame(&format!(
        r#"{{"version":4,"response":{{"type":"error","code":"{long}"}}}}"#
    ));
    assert!(matches!(
        decode_response(&unknown_code),
        Err(ProtocolError::UnknownResponse(_))
    ));
}

#[test]
fn malformed_response_frames_are_rejected() {
    let cases = [
        frame(r#"{"version":1,"response":{"type":"pong"}}"#),
        frame(r#"{"response":{"type":"pong"}}"#),
        frame(r#"{"version":4}"#),
        frame(r#"{"version":4,"response":"pong"}"#),
        frame(r#"{"version":4,"response":{}}"#),
        frame(r#"{"version":4,"response":{"type":7}}"#),
        frame(r#"{"version":4,"response":{"type":"error"}}"#),
        frame(r#"{"version":4,"response":{"type":"error","code":7}}"#),
        frame("not json"),
        vec![0, 0, 0, 10, b'{'],
    ];
    for bytes in cases {
        assert!(
            decode_response(&bytes).is_err(),
            "accepted malformed frame: {bytes:?}"
        );
    }

    let mut trailing = encode_response(&Response::Pong).expect("encode");
    trailing.push(b'x');
    assert_eq!(
        decode_response(&trailing),
        Err(ProtocolError::TrailingBytes { trailing: 1 })
    );
}

#[test]
fn responses_never_repeat_a_body_field_value() {
    // A daemon bug that slipped a value into a response must not turn into
    // an echoed secret in logs: decoding ignores unknown fields and the
    // error text never repeats them.
    let secret_like = "SUPER_SECRET_VALUE_123";
    let body = format!(
        r#"{{"version":4,"response":{{"type":"error","code":"nope","value":"{secret_like}"}}}}"#
    );
    let error = decode_response(&frame(&body)).expect_err("unknown code");
    let text = error.to_string();
    assert!(!text.contains(secret_like), "unexpected message: {text}");
}

#[test]
fn arbitrary_bytes_are_rejected_as_responses_without_panicking() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for length in 0..=96 {
        for _ in 0..32 {
            let mut bytes = vec![0u8; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let _ = decode_response(&bytes);
        }
    }
}

#[test]
fn run_stream_frames_round_trip_arbitrary_bytes() {
    // Every byte value, NUL included, plus sequences that are not valid
    // UTF-8: JSON must not be allowed to mangle child output.
    let mut all_bytes = Vec::new();
    for byte in 0u8..=255 {
        all_bytes.push(byte);
    }
    let invalid_utf8 = vec![0xff, 0xfe, 0x80, b'a', 0x00, b'\n'];
    let cases = [
        Vec::new(),
        all_bytes,
        invalid_utf8,
        b"plain text\nwith a newline\n".to_vec(),
        vec![0u8; MAX_CHUNK_BYTES],
    ];
    let frames = [
        RunFrame::Stdout(cases[0].clone()),
        RunFrame::Stderr(cases[0].clone()),
        RunFrame::Stdout(cases[1].clone()),
        RunFrame::Stderr(cases[2].clone()),
        RunFrame::Stdout(cases[3].clone()),
        RunFrame::Stderr(cases[4].clone()),
    ];
    for frame in frames {
        let encoded = encode_run_frame(&frame).expect("encode run frame");
        assert_eq!(decode_run_frame(&encoded).expect("decode run frame"), frame);
    }
}

#[test]
fn exit_frames_round_trip_and_validate_the_status() {
    for exit in [
        RunFinished::exited(RunExit::Code(0)),
        RunFinished::exited(RunExit::Code(1)),
        RunFinished::exited(RunExit::Code(255)),
        RunFinished::exited(RunExit::Signal(1)),
        RunFinished::exited(RunExit::Signal(9)),
        RunFinished::exited(RunExit::Signal(127)),
    ] {
        let encoded = encode_run_frame(&RunFrame::Exit(exit)).expect("encode exit");
        assert_eq!(
            decode_run_frame(&encoded).expect("decode exit"),
            RunFrame::Exit(exit)
        );
    }

    for body in [
        r#"{"version":4,"response":{"type":"exit"}}"#.to_string(),
        r#"{"version":4,"response":{"type":"exit","code":256}}"#.to_string(),
        r#"{"version":4,"response":{"type":"exit","code":-1}}"#.to_string(),
        r#"{"version":4,"response":{"type":"exit","code":1.5}}"#.to_string(),
        r#"{"version":4,"response":{"type":"exit","code":"0"}}"#.to_string(),
        r#"{"version":4,"response":{"type":"exit","signal":0}}"#.to_string(),
        r#"{"version":4,"response":{"type":"exit","signal":128}}"#.to_string(),
        r#"{"version":4,"response":{"type":"exit","signal":-9}}"#.to_string(),
        r#"{"version":4,"response":{"type":"exit","code":0,"signal":9}}"#.to_string(),
        r#"{"version":4,"response":{"type":"exit","code":null}}"#.to_string(),
    ] {
        assert!(
            decode_run_frame(&frame(&body)).is_err(),
            "accepted invalid exit frame: {body}"
        );
    }
}

#[test]
fn exit_flags_and_stats_round_trip_and_legacy_frames_default_to_zero() {
    let finished = RunFinished {
        exit: RunExit::Signal(9),
        timed_out: true,
        stdout_truncated: true,
        stderr_truncated: false,
        redactions: 2,
        duration_ms: 1234,
    };
    let encoded = encode_run_frame(&RunFrame::Exit(finished)).expect("encode exit");
    let value: serde_json::Value = serde_json::from_slice(&encoded[4..]).expect("json");
    assert_eq!(value["response"]["timed_out"], true);
    assert_eq!(value["response"]["stdout_truncated"], true);
    assert_eq!(value["response"]["stderr_truncated"], false);
    assert_eq!(value["response"]["redactions"], 2);
    assert_eq!(value["response"]["duration_ms"], 1234);
    assert_eq!(
        decode_run_frame(&encoded).expect("decode exit"),
        RunFrame::Exit(finished)
    );

    // A frame from an older peer has no flag or stat fields: all false/zero.
    let legacy = frame(r#"{"version":4,"response":{"type":"exit","code":0}}"#);
    assert_eq!(
        decode_run_frame(&legacy).expect("legacy exit"),
        RunFrame::Exit(RunFinished::exited(RunExit::Code(0)))
    );

    for body in [
        r#"{"version":4,"response":{"type":"exit","code":0,"timed_out":1}}"#,
        r#"{"version":4,"response":{"type":"exit","code":0,"stdout_truncated":"true"}}"#,
        r#"{"version":4,"response":{"type":"exit","code":0,"stderr_truncated":null}}"#,
        r#"{"version":4,"response":{"type":"exit","code":0,"redactions":-1}}"#,
        r#"{"version":4,"response":{"type":"exit","code":0,"redactions":1.5}}"#,
        r#"{"version":4,"response":{"type":"exit","code":0,"duration_ms":null}}"#,
        r#"{"version":4,"response":{"type":"exit","code":0,"duration_ms":"12"}}"#,
    ] {
        assert!(
            decode_run_frame(&frame(body)).is_err(),
            "accepted invalid exit flags: {body}"
        );
    }
}

#[test]
fn output_chunks_are_capped_on_encode_and_decode() {
    let at_limit = RunFrame::Stdout(vec![b'x'; MAX_CHUNK_BYTES]);
    let encoded = encode_run_frame(&at_limit).expect("a maximum chunk must encode");
    assert!(encoded.len() <= MAX_MESSAGE_BYTES + LENGTH_PREFIX_BYTES);
    assert_eq!(decode_run_frame(&encoded).expect("decode"), at_limit);

    let over_limit = RunFrame::Stderr(vec![b'x'; MAX_CHUNK_BYTES + 1]);
    assert_eq!(
        encode_run_frame(&over_limit),
        Err(ProtocolError::ChunkTooLarge {
            length: MAX_CHUNK_BYTES + 1,
            max: MAX_CHUNK_BYTES,
        })
    );

    // The same bound applies to a peer-supplied frame, checked from the hex
    // text length before any decoding allocation.
    let body = format!(
        r#"{{"version":4,"response":{{"type":"stderr","data":"{}"}}}}"#,
        "00".repeat(MAX_CHUNK_BYTES + 1)
    );
    assert!(matches!(
        decode_run_frame(&frame(&body)),
        Err(ProtocolError::ChunkTooLarge { length, max })
            if length == MAX_CHUNK_BYTES + 1 && max == MAX_CHUNK_BYTES
    ));
}

#[test]
fn malformed_run_frames_are_rejected() {
    let cases = [
        // One-shot responses are not stream frames.
        r#"{"version":4,"response":{"type":"pong"}}"#.to_string(),
        r#"{"version":4,"response":{"type":"locked"}}"#.to_string(),
        // Output frames need a string of lowercase hex digits.
        r#"{"version":4,"response":{"type":"stdout"}}"#.to_string(),
        r#"{"version":4,"response":{"type":"stdout","data":7}}"#.to_string(),
        r#"{"version":4,"response":{"type":"stdout","data":"0"}}"#.to_string(),
        r#"{"version":4,"response":{"type":"stdout","data":"0g"}}"#.to_string(),
        r#"{"version":4,"response":{"type":"stdout","data":"AB"}}"#.to_string(),
        r#"{"version":4,"response":{"type":"stdout","data":null}}"#.to_string(),
        // Unknown frame types, and missing/mistyped envelopes.
        r#"{"version":4,"response":{"type":"password","data":"00"}}"#.to_string(),
        r#"{"version":1,"response":{"type":"stdout","data":"00"}}"#.to_string(),
        r#"{"response":{"type":"stdout","data":"00"}}"#.to_string(),
        r#"{"version":4,"response":[]}"#.to_string(),
        r#"{"version":4,"response":{"type":7}}"#.to_string(),
        "not json".to_string(),
        // An error frame still needs a known code.
        r#"{"version":4,"response":{"type":"error"}}"#.to_string(),
        r#"{"version":4,"response":{"type":"error","code":"nope"}}"#.to_string(),
    ];
    for body in cases {
        assert!(
            decode_run_frame(&frame(&body)).is_err(),
            "accepted malformed run frame: {body}"
        );
    }

    let mut trailing = encode_run_frame(&RunFrame::Stdout(b"hi".to_vec())).expect("encode");
    trailing.push(b'x');
    assert_eq!(
        decode_run_frame(&trailing),
        Err(ProtocolError::TrailingBytes { trailing: 1 })
    );
}

#[test]
fn one_shot_and_stream_responses_cannot_be_confused() {
    let pong = encode_response(&Response::Pong).expect("encode pong");
    assert!(matches!(
        decode_run_frame(&pong),
        Err(ProtocolError::UnknownResponse(_))
    ));

    for frame in [
        RunFrame::Stdout(b"out".to_vec()),
        RunFrame::Stderr(b"err".to_vec()),
        RunFrame::Exit(RunFinished::exited(RunExit::Code(0))),
    ] {
        let encoded = encode_run_frame(&frame).expect("encode run frame");
        assert!(matches!(
            decode_response(&encoded),
            Err(ProtocolError::UnknownResponse(_))
        ));
    }
}

#[test]
fn run_error_codes_are_stable_and_round_trip() {
    let expected = [
        (ResponseError::BadRequest, "bad_request"),
        (ResponseError::Unsupported, "unsupported"),
        (ResponseError::Unauthorized, "unauthorized"),
        (ResponseError::NotFound, "not_found"),
        (ResponseError::SpawnFailed, "spawn_failed"),
        (ResponseError::Internal, "internal"),
        (ResponseError::Busy, "busy"),
    ];
    for (error, code) in expected {
        assert_eq!(error.code(), code);
        let encoded = encode_run_frame(&RunFrame::Error(error)).expect("encode error");
        assert_eq!(
            decode_run_frame(&encoded).expect("decode error"),
            RunFrame::Error(error)
        );
        let text = String::from_utf8(encoded[LENGTH_PREFIX_BYTES..].to_vec()).expect("json");
        assert!(text.contains(&format!("\"code\":\"{code}\"")));
    }
}

#[test]
fn run_stream_accepts_nothing_after_a_terminal_frame() {
    for terminal in [
        RunFrame::Exit(RunFinished::exited(RunExit::Code(0))),
        RunFrame::Exit(RunFinished::exited(RunExit::Signal(9))),
        RunFrame::Error(ResponseError::NotFound),
    ] {
        let mut stream = RunStream::new();
        assert!(!stream.is_finished());
        stream
            .accept(&RunFrame::Stdout(b"out".to_vec()))
            .expect("chunk before the end is fine");
        stream
            .accept(&RunFrame::Stderr(b"err".to_vec()))
            .expect("chunk before the end is fine");
        assert!(!stream.is_finished());
        stream.accept(&terminal).expect("terminal frame is fine");
        assert!(stream.is_finished());
        for extra in [
            RunFrame::Stdout(b"late".to_vec()),
            RunFrame::Stderr(b"late".to_vec()),
            RunFrame::Exit(RunFinished::exited(RunExit::Code(0))),
            RunFrame::Error(ResponseError::SpawnFailed),
        ] {
            assert!(
                stream.accept(&extra).is_err(),
                "accepted a frame after {terminal:?}"
            );
        }
    }
}

#[test]
fn run_frame_debug_never_renders_child_output() {
    let canary = "CANARY_CHILD_OUTPUT_2f9a";
    for frame in [
        RunFrame::Stdout(canary.as_bytes().to_vec()),
        RunFrame::Stderr(canary.as_bytes().to_vec()),
    ] {
        let text = format!("{frame:?}");
        assert!(
            !text.contains(canary),
            "Debug rendered child output: {text}"
        );
    }
    assert_eq!(
        format!("{:?}", RunFrame::Stdout(b"abc".to_vec())),
        "RunFrame::Stdout(3 bytes)"
    );
}

#[test]
fn arbitrary_bytes_are_rejected_as_run_frames_without_panicking() {
    let mut state = 0x243f_6a88_85a3_08d3_u64;
    for length in 0..=128 {
        for _ in 0..32 {
            let mut bytes = vec![0u8; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let _ = decode_run_frame(&bytes);
        }
    }
}
