//! Interactive password input with terminal echo disabled.

use std::io::{self, BufRead, IsTerminal, Write};

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Passwords longer than this are rejected instead of being stored.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Print `prompt` to stderr and read a line from stdin without echoing it when
/// stdin is a terminal.
///
/// Prompts go to stderr so stdout remains usable for command output. When stdin
/// is not a terminal (for example, a pipe), the line is read normally; this is
/// what makes the CLI scriptable.
pub fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{prompt}");
    io::stderr().flush()?;

    let stdin = io::stdin();
    let is_tty = stdin.is_terminal();

    #[cfg(unix)]
    let echo_guard = if is_tty {
        Some(EchoGuard::disable()?)
    } else {
        None
    };
    #[cfg(not(unix))]
    let echo_guard = {
        let _ = is_tty;
        None::<()>
    };

    let mut line = Zeroizing::new(String::new());
    let read_result = stdin.lock().read_line(&mut line);
    drop(echo_guard);
    if is_tty {
        eprintln!();
    }
    read_result?;

    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    if line.len() > MAX_PASSWORD_BYTES {
        return Err(Error::InvalidInput(format!(
            "password is too long ({} bytes; maximum is {MAX_PASSWORD_BYTES})",
            line.len()
        )));
    }
    Ok(line)
}

/// Print `prompt` to stderr and read one line from stdin as a yes/no answer.
///
/// Only an explicit `y` or `yes` (case-insensitive, surrounding whitespace
/// ignored) is a yes. An empty line, any other word and end of input are all
/// a no: approving a grant must take a deliberate keystroke, never the
/// absence of one.
pub fn prompt_yes_no(prompt: &str) -> Result<bool> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(is_yes(&line))
}

/// The pure answer test behind [`prompt_yes_no`].
pub fn is_yes(answer: &str) -> bool {
    let answer = answer.trim();
    answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")
}

#[cfg(unix)]
struct EchoGuard {
    fd: libc::c_int,
    original: libc::termios,
}

#[cfg(unix)]
impl EchoGuard {
    fn disable() -> Result<Self> {
        let fd = libc::STDIN_FILENO;
        // SAFETY: tcgetattr fills the supplied termios structure, which is
        // valid, aligned, and owned by us.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is a valid file descriptor and `original` is writable.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut no_echo = original;
        no_echo.c_lflag &= !libc::ECHO;
        // SAFETY: `fd` is valid and `no_echo` points to an initialized termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &no_echo) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self { fd, original })
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: `self.fd` was valid when the guard was created and
        // `self.original` is an initialized termios structure.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_yes;

    #[test]
    fn only_an_explicit_yes_is_yes() {
        for yes in ["y", "Y", "yes", "YES", "Yes", " y ", "yes\r\n"] {
            assert!(is_yes(yes), "{yes:?} must be a yes");
        }
        for no in [
            "",
            "\n",
            "n",
            "no",
            "nope",
            "ye",
            "yess",
            "ok",
            "1",
            "yes please",
        ] {
            assert!(!is_yes(no), "{no:?} must not be a yes");
        }
    }
}
