//! A run must not leave the injected value in freed heap memory (TODO R.50b).
//!
//! `pmd` still copies the value into places no passmgr code owns. This test
//! binary runs under a pass-through global allocator that scans every freed
//! block for the test's canary, so a buffer dropped without being wiped is
//! observed even though no public API can show it.
//!
//! Two properties, both deterministic:
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
//! Each measurement has its own canary and counter, and the watched windows
//! are serialized behind a mutex, so parallel test threads cannot attribute a
//! free to the wrong measurement.

#![cfg(unix)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use passmgr::redact::Redactor;
use passmgr::runner::{self, Stop};

/// Canary injected into the redactor-only test.
const REDACT_CANARY: &[u8] = b"r50b-redact-canary-0001";
/// Canary injected into the child's environment by `runner::execute`.
const RUN_CANARY: &[u8] = b"r50b-run-canary-0000002";
/// Canary used by the `std::process::Command` baseline spawn.
const BASELINE_CANARY: &[u8] = b"r50b-base-canary-000003";
/// Environment variable the canary is injected as.
const ENV_NAME: &str = "PASSMGR_TEST_SECRET";

static WATCHING: AtomicBool = AtomicBool::new(false);
static REDACT_HITS: AtomicUsize = AtomicUsize::new(0);
static RUN_HITS: AtomicUsize = AtomicUsize::new(0);
static BASELINE_HITS: AtomicUsize = AtomicUsize::new(0);

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
