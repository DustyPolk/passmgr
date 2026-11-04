//! A run must not leave the injected value in freed heap memory (TODO R.50b).
//!
//! `pmd` still copies the value into places no passmgr code owns. This test
//! binary runs under a pass-through global allocator that scans every freed
//! block for the test's canary, so a buffer dropped without being wiped is
//! observed even though no public API can show it.
//!
//! Three properties, all deterministic:
//!
//! 1. The redactor's buffers (`src/redact.rs`) - the secret copy, the overlap
//!    window and its growth - are all wiped. A `run` whose child echoes the
//!    value therefore leaves no copy behind from redaction.
//! 2. A real `run` leaves no more secret-bearing freed blocks than a plain
//!    `std::process::Command` doing the same spawn leaves. `Command` keeps its
//!    own copies (its env map and the `NAME=value` string it passes to
//!    `execve`) and offers no way to own or wipe them; those are the documented
//!    residue in `SECURITY.md` limit 6. Measuring the baseline instead of
//!    pinning a count keeps the test meaningful across Rust versions while
//!    still failing if passmgr adds a copy of its own.
//!
//! 3. The wire codec (TODO R.50c) wipes every buffer it copies a request into.
//!    A frame carries the session-token hex, and a `run` frame carries the
//!    grant-token hex; `pmd` is long-lived, so a frame freed unwiped hands a
//!    usable token to anything that can read its heap.
//!
//! Each measurement has its own canary and counter, and the watched windows
//! are serialized behind a mutex, so parallel test threads cannot attribute a
//! free to the wrong measurement. The scan sees *every* thread's frees while a
//! window is open (the run test needs that: its redaction happens on reader
//! threads), so the four wire-codec tests, which all handle a session-token
//! hex, additionally exclude each other for their whole bodies. Without that, a
//! frame or temporary one wire test frees after its own window can be dropped
//! inside another wire test's window and counted against it (TODO R.66).

#![cfg(unix)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use passmgr::grant::GrantToken;
use passmgr::protocol::{self, FrameDecoder, Request, RunRequest};
use passmgr::redact::Redactor;
use passmgr::runner::{self, Stop};
use passmgr::token::SessionToken;

/// Canary injected into the redactor-only test.
const REDACT_CANARY: &[u8] = b"r50b-redact-canary-0001";
/// Canary injected into the child's environment by `runner::execute`.
const RUN_CANARY: &[u8] = b"r50b-run-canary-0000002";
/// Canary used by the `std::process::Command` baseline spawn.
const BASELINE_CANARY: &[u8] = b"r50b-base-canary-000003";
/// Environment variable the canary is injected as.
const ENV_NAME: &str = "PASSMGR_TEST_SECRET";
/// Bytes of the session token used by the wire-codec test. Its hex encoding is
/// what a frame carries, so the needle below is derived from it.
const WIRE_TOKEN_BYTES: [u8; 32] = *b"r50c-wire-token-canary-000000001";
/// A fixed grant token for the chunked-frame test, in the lowercase hex form a
/// `run` frame carries. Only its hex matters: it is the second needle the
/// freed-block scan looks for. Eight copies of an eight-digit pattern.
const WIRE_GRANT_HEX: &str = concat!(
    "9f64a9a19f64a9a1",
    "9f64a9a19f64a9a1",
    "9f64a9a19f64a9a1",
    "9f64a9a19f64a9a1",
);

static WATCHING: AtomicBool = AtomicBool::new(false);
static REDACT_HITS: AtomicUsize = AtomicUsize::new(0);
static RUN_HITS: AtomicUsize = AtomicUsize::new(0);
static BASELINE_HITS: AtomicUsize = AtomicUsize::new(0);
static WIRE_HITS: AtomicUsize = AtomicUsize::new(0);
/// The token hexes (session and grant) to look for in freed blocks. Set once,
/// before any watched window opens; reading a `OnceLock` in the allocator
/// allocates nothing.
static WIRE_NEEDLES: OnceLock<Vec<Vec<u8>>> = OnceLock::new();

/// Serializes the four wire-codec tests for their whole bodies, not just their
/// windows: a token-bearing buffer one of them frees outside its window must
/// never be scanned inside another one's (see the module doc).
static WIRE_SERIAL: Mutex<()> = Mutex::new(());

/// Serializes the watched windows: the counters are process-wide.
static WATCH_LOCK: Mutex<()> = Mutex::new(());

struct CanaryWatcher;

fn scan(ptr: *mut u8, len: usize) {
    // The redactor's overlap window never holds a complete occurrence: it keeps
    // at most `secret.len() - 1` bytes back, so the most it can leave behind is
    // the value's first `len - 1` bytes. Probing for that prefix catches both a
    // partial and a complete copy.
    let redact_probe = &REDACT_CANARY[..REDACT_CANARY.len() - 1];
    for (probe, counter) in [
        (redact_probe, &REDACT_HITS),
        (RUN_CANARY, &RUN_HITS),
        (BASELINE_CANARY, &BASELINE_HITS),
    ] {
        if len < probe.len() {
            continue;
        }
        // SAFETY: the block is still valid for `len` bytes; this runs before
        // the deallocation is forwarded.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        if bytes.windows(probe.len()).any(|window| window == probe) {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    }
    if let Some(needles) = WIRE_NEEDLES.get() {
        // SAFETY: same block and bounds as above.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        if needles
            .iter()
            .any(|needle| len >= needle.len() && contains(bytes, needle))
        {
            WIRE_HITS.fetch_add(1, Ordering::SeqCst);
        }
    }
}

// SAFETY: every method forwards to `System` with the caller's layout. The
// extra read stays inside the block being freed and allocates nothing.
unsafe impl GlobalAlloc for CanaryWatcher {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHING.load(Ordering::SeqCst) {
            scan(ptr, layout.size());
        }
        // SAFETY: `ptr` and `layout` are the caller's deallocation.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A moving `realloc` frees the old block, so inspect it first.
        if WATCHING.load(Ordering::SeqCst) {
            scan(ptr, layout.size());
        }
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CanaryWatcher = CanaryWatcher;

/// Hold `WIRE_SERIAL` for the rest of a wire-codec test.
fn wire_serial() -> MutexGuard<'static, ()> {
    WIRE_SERIAL.lock().unwrap_or_else(|err| err.into_inner())
}

/// Count the freed blocks that still hold the counter's canary while `body`
/// runs.
fn count_releases<T>(counter: &AtomicUsize, body: impl FnOnce() -> T) -> (T, usize) {
    let _guard: MutexGuard<()> = WATCH_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    counter.store(0, Ordering::SeqCst);
    WATCHING.store(true, Ordering::SeqCst);
    let value = body();
    WATCHING.store(false, Ordering::SeqCst);
    (value, counter.load(Ordering::SeqCst))
}

/// Spawn through `runner::execute`, returning what the child wrote to stdout.
fn run_child(program: &str, args: &[String], secret: &str) -> Vec<u8> {
    let inherited = vec![(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))];
    let cancel = Arc::new(AtomicBool::new(false));
    let stop = Stop::on_cancel(&cancel);
    let mut stdout = Vec::new();
    runner::execute(
        Path::new(program),
        args,
        ENV_NAME,
        secret,
        Path::new("/"),
        &inherited,
        &stop,
        |frame| {
            if let passmgr::protocol::RunFrame::Stdout(data) = frame {
                stdout.extend_from_slice(&data);
            }
            Ok(())
        },
    )
    .expect("the child runs");
    stdout
}

/// What a bare `std::process::Command` leaves behind for the same spawn.
fn spawn_baseline(secret: &str) -> usize {
    let (_, hits) = count_releases(&BASELINE_HITS, || {
        let mut command = Command::new("/usr/bin/true");
        command.env_clear();
        command.env("PATH", "/usr/bin:/bin");
        command.env(ENV_NAME, secret);
        command.current_dir("/");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // The same pre-exec hook `execute` installs, so std takes the same
        // spawn path and the comparison is like for like.
        // SAFETY: the closure only calls `setpgid` and reads `errno`.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().expect("spawn the baseline child");
        drop(command);
        child.wait().expect("wait for the baseline child");
    });
    hits
}

#[test]
fn the_redactor_leaves_no_copy_of_the_value_in_freed_memory() {
    let secret = std::str::from_utf8(REDACT_CANARY).expect("ascii canary");
    // The longest fragment the overlap window can hold back: one byte short of
    // the value, which is what a growing window used to leave in freed memory.
    let held_back = &REDACT_CANARY[..REDACT_CANARY.len() - 1];
    let filler = [b'x'; 1024];

    let (_, hits) = count_releases(&REDACT_HITS, || {
        let mut redactor = Redactor::new(secret.as_bytes());
        for size in [64, 128, 256, 512, 1024] {
            // Growing sizes force the window to reallocate while it holds the
            // fragment. Both the fragment and the filler come straight from
            // constants, and every buffer the test receives is wiped, so a
            // freed block holding the value can only come from the redactor.
            let mut emitted = redactor.push(&filler[..size]);
            emitted.extend_from_slice(&redactor.push(held_back));
            assert!(
                !contains(&emitted, REDACT_CANARY),
                "the redactor emitted the value"
            );
            wipe(&mut emitted);
        }
        let mut tail = redactor.finish();
        assert!(!contains(&tail, REDACT_CANARY));
        wipe(&mut tail);
    });

    assert_eq!(
        hits, 0,
        "redaction left the value in freed memory; see SECURITY.md limit 6"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Overwrite a buffer the test owns, so a freed copy the allocator sees came
/// from the code under test rather than from the test's own bookkeeping.
fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` points at a valid, aligned, writable `u8`; a volatile
        // write keeps the wipe from being optimized out before the drop.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}

#[test]
fn a_run_leaves_no_more_copies_than_the_spawn_itself() {
    let baseline_secret = std::str::from_utf8(BASELINE_CANARY).expect("ascii canary");
    let baseline = spawn_baseline(baseline_secret);
    assert!(
        baseline > 0,
        "the baseline found no std copies, so this test would prove nothing"
    );

    // A child that echoes the value exercises redaction of real output, not
    // just an idle spawn. The argv is built before the window opens: it is the
    // test's own copy, not passmgr's, and must not be counted.
    let run_secret = std::str::from_utf8(RUN_CANARY).expect("ascii canary");
    let echo_args = [run_secret.to_string()];
    let (stdout, hits) =
        count_releases(&RUN_HITS, || run_child("/bin/echo", &echo_args, run_secret));
    assert!(
        !stdout
            .windows(RUN_CANARY.len())
            .any(|window| window == RUN_CANARY),
        "the relayed output contained the value"
    );

    assert!(
        hits <= baseline,
        "passmgr left more copies of the value than std::process::Command does \
         ({hits} freed blocks against a baseline of {baseline}); see SECURITY.md \
         limit 6 and wipe the new buffer"
    );
}

/// The whole encode -> decode path must leave no copy of the session-token hex
/// in freed memory: the frame, the encoder's JSON tree, the decoder's buffer,
/// the frame body it returns and the decoder's tree are all wiped.
#[test]
fn the_wire_codec_leaves_no_copy_of_the_token_in_freed_memory() {
    let _serial = wire_serial();
    let token = SessionToken::from_bytes(&WIRE_TOKEN_BYTES).expect("fixed token");
    let grant = GrantToken::from_hex(WIRE_GRANT_HEX).expect("fixed grant");
    // The needles are allocated before the window opens and live until the
    // process exits, so they are never themselves scanned.
    let needles = wire_needles(&token, &grant);

    let (_, hits) = count_releases(&WIRE_HITS, || {
        let frame = protocol::encode(&token, &Request::Ping).expect("encode");
        let mut decoder = FrameDecoder::new();
        decoder.push(&frame).expect("push");
        let request = decoder.next_request().expect("decode").expect("request");
        assert!(request.token().matches(&token));
    });

    assert_eq!(
        hits,
        0,
        "the wire codec left a {}-character token hex in freed memory; see \
         SECURITY.md limit 6",
        needles[0].len()
    );
}

/// The hex needles the freed-block scan looks for, set once before any watched
/// window opens. Both inputs are fixed constants, so whichever wire test runs
/// first initializes the same list.
fn wire_needles(token: &SessionToken, grant: &GrantToken) -> &'static [Vec<u8>] {
    WIRE_NEEDLES.get_or_init(|| {
        vec![
            token.to_hex().as_bytes().to_vec(),
            grant.to_hex().as_bytes().to_vec(),
        ]
    })
}

/// A `run` request whose command is `/usr/bin/true` followed by `arguments`
/// 4 KiB arguments and, when it is non-zero, one `extra`-byte argument. The
/// argument bytes are plain `a`s, so the encoded size grows by exactly `extra`.
fn large_run_request(grant: &GrantToken, arguments: usize, extra: usize) -> Request {
    let command = std::iter::once("/usr/bin/true".to_string())
        .chain(std::iter::repeat_n("a".repeat(4096), arguments))
        .chain((extra > 0).then(|| "a".repeat(extra)))
        .collect();
    Request::Run(RunRequest {
        env: "API_KEY".into(),
        reference: "pm://00112233445566778899aabbccddeeff".into(),
        command,
        cwd: "/tmp".into(),
        grant: grant.clone(),
    })
}

/// A frame at the size cap must not leave the token hex in freed memory when
/// the decoder grows its receive buffer (TODO R.64).
///
/// The envelope orders the token hex last, so the leak happens at the end:
/// a body of exactly [`protocol::MAX_MESSAGE_BYTES`] is pushed as sixteen
/// 4 KiB chunks plus a four-byte tail, and that tail makes `push` grow the
/// 64 KiB buffer one last time while it already holds the token hex (and the
/// grant hex). `grow_for`/`grow_wiped` now allocate, copy, wipe and only then
/// drop the old buffer. The body size is reached by measuring one encoding and
/// sizing the last argument to the remainder, so the test does not depend on
/// the exact JSON overhead.
#[test]
fn a_frame_at_the_size_cap_leaves_no_copy_of_the_token_in_freed_memory() {
    let _serial = wire_serial();
    let token = SessionToken::from_bytes(&WIRE_TOKEN_BYTES).expect("fixed token");
    let grant = GrantToken::from_hex(WIRE_GRANT_HEX).expect("fixed grant");
    let needles = wire_needles(&token, &grant);
    let frame_bytes = protocol::LENGTH_PREFIX_BYTES + protocol::MAX_MESSAGE_BYTES;

    let (_, hits) = count_releases(&WIRE_HITS, || {
        // Measure the encoding with a one-byte last argument; every further
        // byte of that argument adds exactly one byte to the body.
        let probe =
            protocol::encode(&token, &large_run_request(&grant, 15, 1)).expect("encode the probe");
        let extra = 1 + frame_bytes
            .checked_sub(probe.len())
            .expect("the fixed arguments must leave room under the cap");
        assert!(
            extra <= protocol::MAX_ARG_BYTES,
            "the last argument needs {extra} bytes, over the {}-byte cap",
            protocol::MAX_ARG_BYTES
        );
        let frame = protocol::encode(&token, &large_run_request(&grant, 15, extra))
            .expect("encode the frame");
        assert_eq!(
            frame.len(),
            frame_bytes,
            "the probe-sized argument must produce a frame at the cap"
        );

        let mut decoder = FrameDecoder::new();
        for chunk in frame.chunks(4096) {
            decoder.push(chunk).expect("push");
        }
        let decoded = decoder.next_request().expect("decode").expect("request");
        assert!(decoded.token().matches(&token));
    });

    assert_eq!(
        hits,
        0,
        "a frame at the size cap left a {}-character token hex in freed \
         memory; see SECURITY.md limit 6 and wipe the buffer before it is \
         reallocated",
        needles[0].len()
    );
}

/// Encoding a large `run` request must not leave the token or grant hex in
/// freed memory (TODO R.64).
///
/// The freed-block scan caught two encoder leaks: `serde_json::to_vec` grew
/// its writer after the grant hex had been written, freeing the old buffer
/// with the hex in it, and `json!` deep-copied the request `Value` through
/// `serde_json::to_value`, so a second tree holding the grant hex was dropped
/// unwiped. `encode_body` now moves the request into the envelope and
/// serializes through `BodyWriter`, which grows with `grow_wiped`.
#[test]
fn encoding_a_large_run_request_leaves_no_copy_of_the_token_in_freed_memory() {
    let _serial = wire_serial();
    let token = SessionToken::from_bytes(&WIRE_TOKEN_BYTES).expect("fixed token");
    let grant = GrantToken::from_hex(WIRE_GRANT_HEX).expect("fixed grant");
    let needles = wire_needles(&token, &grant);
    let request = large_run_request(&grant, 4, 0);

    let (_, hits) = count_releases(&WIRE_HITS, || {
        let frame = protocol::encode(&token, &request).expect("encode");
        let mut decoder = FrameDecoder::new();
        for chunk in frame.chunks(4096) {
            decoder.push(chunk).expect("push");
        }
        let decoded = decoder.next_request().expect("decode").expect("request");
        assert!(decoded.token().matches(&token));
    });

    assert_eq!(
        hits,
        0,
        "encoding a large frame left a {}-character grant-token hex in freed \
         memory; see SECURITY.md limit 6 and wipe the buffer before it is \
         reallocated",
        needles[1].len()
    );
}

/// A rejected request must wipe the parsed envelope too (TODO R.65).
///
/// `decode_body` used to run `zeroize_json` only after the request match, so
/// every early `?` — the version check, a missing field inside `run` or
/// `grant_create`, and the unknown-type arm — freed the tree while it still
/// held a plain copy of the session-token hex. An old client (`version` 3)
/// hits the same path, so this is not only a hostile-peer case.
#[test]
fn a_rejected_request_leaves_no_copy_of_the_token_in_freed_memory() {
    let _serial = wire_serial();
    let token = SessionToken::from_bytes(&WIRE_TOKEN_BYTES).expect("fixed token");
    let grant = GrantToken::from_hex(WIRE_GRANT_HEX).expect("fixed grant");
    wire_needles(&token, &grant);
    let token_hex = token.to_hex();

    // Build the malformed frames before the window opens: they are the test's
    // own buffers and must not be counted. The unknown type returns straight
    // from the match arm; the `grant_create` fails a field-level `?` inside it.
    // The version check returns before the token is even parsed, which is the
    // path an old client takes.
    let old_version = frame_from_body(&serde_json::json!({
        "version": protocol::PROTOCOL_VERSION - 1,
        "token": token_hex.as_str(),
        "request": { "type": "ping" },
    }));
    let unknown_type = frame_from_body(&serde_json::json!({
        "version": protocol::PROTOCOL_VERSION,
        "token": token_hex.as_str(),
        "request": { "type": "nope" },
    }));
    let missing_label = frame_from_body(&serde_json::json!({
        "version": protocol::PROTOCOL_VERSION,
        "token": token_hex.as_str(),
        "request": {
            "type": "grant_create",
            "refs": [],
            "tags": [],
            "fields": [],
            "commands": [],
            "capabilities": 0,
            "expires_at": 1,
            "max_uses": serde_json::Value::Null,
            "token_hash": grant.to_hex().as_str(),
        },
    }));

    let (_, hits) = count_releases(&WIRE_HITS, || {
        for frame in [&old_version, &unknown_type, &missing_label] {
            let mut decoder = FrameDecoder::new();
            decoder.push(frame).expect("push");
            assert!(
                decoder.next_request().is_err(),
                "the malformed frame must be rejected"
            );
        }
    });

    assert_eq!(
        hits,
        0,
        "a rejected request left a {}-character token hex in freed memory; \
         wipe the parsed envelope before returning the error (SECURITY.md \
         limit 6)",
        token.to_hex().len()
    );
}

/// Wrap a JSON body in the length prefix `FrameDecoder` expects. Test-only: no
/// validation, because the bodies here are deliberately malformed.
fn frame_from_body(body: &serde_json::Value) -> Vec<u8> {
    let body = serde_json::to_vec(body).expect("serialize the test body");
    let mut frame = Vec::with_capacity(protocol::LENGTH_PREFIX_BYTES + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}
