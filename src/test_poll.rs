//! Deadline-bounded polling for tests.
//!
//! Tests wait on an observable condition, never on a fixed sleep: a sleep that
//! is long enough on one machine is too short on a loaded CI runner, and a
//! test that sleeps before acting can pass without exercising the path it
//! names. `clippy.toml` disallows `std::thread::sleep`; this module holds the
//! poll interval, and any other test sleep must say why with an `#[expect]`.
//!
//! Unit tests reach this file as `crate::test_poll`. Integration tests cannot
//! see `#[cfg(test)]` items of the library, so the `tests/*_support` modules
//! include this same file with `#[path]`.

use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Polls `probe` until it returns `Some`, panicking with `what` after `timeout`.
pub fn wait_until<T>(timeout: Duration, what: &str, probe: impl FnMut() -> Option<T>) -> T {
    poll_until(timeout, probe).unwrap_or_else(|| panic!("{what}"))
}

/// Polls `condition` until it holds, panicking with `what` after `timeout`.
pub fn wait_for(timeout: Duration, what: &str, mut condition: impl FnMut() -> bool) {
    wait_until(timeout, what, || condition().then_some(()));
}

/// Polls `probe` until it returns `Some`, or returns `None` after `timeout`.
///
/// For callers that must clean up (kill a child, say) before failing.
pub fn poll_until<T>(timeout: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = probe() {
            return Some(value);
        }
        if Instant::now() >= deadline {
            return None;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the poll interval between probes of an observable condition"
        )]
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The calling thread's kernel id, for [`wait_for_thread_to_sleep`].
#[cfg(target_os = "linux")]
pub fn current_tid() -> libc::pid_t {
    // SAFETY: gettid has no preconditions and cannot fail.
    unsafe { libc::gettid() }
}

/// Waits until thread `tid` of this process is blocked in `nanosleep`,
/// panicking with `what` after `timeout`.
///
/// This proves that another thread reached a retry loop's pause (a contended
/// `flock`, say) before the test releases what it is waiting for. Only call it
/// when that pause is the one sleep the thread can reach.
#[cfg(target_os = "linux")]
pub fn wait_for_thread_to_sleep(tid: libc::pid_t, timeout: Duration, what: &str) {
    wait_for(timeout, what, || {
        // The first field is the syscall number, or `running`.
        std::fs::read_to_string(format!("/proc/self/task/{tid}/syscall"))
            .ok()
            .and_then(|text| text.split_whitespace().next()?.parse::<libc::c_long>().ok())
            .is_some_and(|number| {
                number == libc::SYS_nanosleep || number == libc::SYS_clock_nanosleep
            })
    });
}
