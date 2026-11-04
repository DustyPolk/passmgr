//! Resolving a caller-supplied program name to an absolute path.
//!
//! Both the human-facing `passmgr run` and the MCP server's
//! `run_with_credentials` tool accept a program name from a caller that is not
//! this process, so the resolution rule lives here once instead of being
//! re-implemented on each side. It is deliberately *not* a security boundary:
//! the result is untrusted input to `pmd`, which canonicalizes it, checks the
//! canonical path against the grant's command allowlist and executes exactly
//! that path. Resolving here only means the request carries an absolute path
//! that means the same thing to the daemon as it did to the caller.

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::error::Error;

/// Resolve `program` to an absolute path using `cwd` and `path_var`.
///
/// * An absolute path is used as given (a missing file is reported by the
///   daemon as a spawn failure, which is the honest error).
/// * A path with a separator is relative to `cwd`.
/// * A bare name is searched in `path_var`, in order, skipping empty entries
///   (POSIX says an empty entry means the current directory; searching there
///   would make the result depend on the caller's cwd in a surprising way).
///
/// Only a regular file with at least one execute bit counts, so a directory or
/// a non-executable file earlier on `PATH` does not shadow the real program.
///
/// The error names the program, which is caller-supplied metadata, never a
/// secret. A caller that must not echo its input (the MCP server) maps the
/// error to a fixed message instead of rendering it.
pub fn resolve_program(program: &str, cwd: &Path, path_var: &OsStr) -> Result<PathBuf, Error> {
    let candidate = Path::new(program);
    if candidate.is_absolute() {
        return Ok(candidate.to_path_buf());
    }
    if program.contains('/') {
        let joined = cwd.join(candidate);
        if is_executable_file(&joined) {
            return Ok(absolute(&joined));
        }
        return Err(program_not_found(program));
    }
    for directory in std::env::split_paths(path_var) {
        if directory.as_os_str().is_empty() {
            continue;
        }
        let joined = directory.join(candidate);
        if is_executable_file(&joined) {
            return Ok(absolute(&joined));
        }
    }
    Err(program_not_found(program))
}

fn is_executable_file(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Lexically make `path` absolute without resolving symlinks, so the request
/// carries an absolute path the daemon can resolve itself. The daemon
/// canonicalizes the path it is sent and executes exactly that canonical path,
/// so a link here is resolved once, on the trusted side, and the caller's name
/// is not what decides which program runs.
pub fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

fn program_not_found(program: &str) -> Error {
    Error::InvalidInput(format!(
        "cannot find the command '{program}': use an absolute path or put it on PATH"
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn make_exe(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write fake program");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("set mode");
        path
    }

    #[test]
    fn a_bare_name_is_resolved_through_the_callers_path_in_order() {
        let first = tempfile::tempdir().expect("tempdir");
        let second = tempfile::tempdir().expect("tempdir");
        let expected = make_exe(first.path(), "passmgr-fake-tool", 0o755);
        let shadowed = make_exe(second.path(), "passmgr-fake-tool", 0o755);
        let path_var = std::env::join_paths([first.path(), second.path()]).expect("join PATH");

        let resolved =
            resolve_program("passmgr-fake-tool", Path::new("/"), &path_var).expect("resolve");
        assert_eq!(resolved, absolute(&expected));
        assert_ne!(resolved, absolute(&shadowed));
    }

    #[test]
    fn a_non_executable_or_directory_entry_does_not_shadow_the_program() {
        let broken = tempfile::tempdir().expect("tempdir");
        let working = tempfile::tempdir().expect("tempdir");
        let not_executable = make_exe(broken.path(), "passmgr-fake-tool", 0o644);
        std::fs::create_dir(broken.path().join("passmgr-fake-dir")).expect("mkdir");
        let expected = make_exe(working.path(), "passmgr-fake-tool", 0o755);
        let path_var = std::env::join_paths([broken.path(), working.path()]).expect("join PATH");

        assert!(resolve_program("passmgr-fake-tool", Path::new("/"), &path_var).is_ok());
        assert_ne!(
            resolve_program("passmgr-fake-tool", Path::new("/"), &path_var).expect("resolve"),
            absolute(&not_executable)
        );
        assert_eq!(
            resolve_program("passmgr-fake-tool", Path::new("/"), &path_var).expect("resolve"),
            absolute(&expected)
        );
        // A directory named like the program is not a program either.
        assert!(resolve_program("passmgr-fake-dir", Path::new("/"), &path_var).is_err());
    }

    #[test]
    fn a_path_with_a_separator_is_relative_to_the_callers_cwd() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let expected = make_exe(cwd.path(), "rel-tool", 0o755);

        assert_eq!(
            resolve_program("./rel-tool", cwd.path(), OsStr::new("")).expect("resolve"),
            absolute(&expected)
        );
        assert!(resolve_program("./missing-tool", cwd.path(), OsStr::new("")).is_err());
    }

    #[test]
    fn an_empty_path_entry_is_not_the_current_directory() {
        // POSIX reads an empty PATH entry as the current directory. Searching
        // there would make `run` pick up whatever file happens to sit in the
        // caller's cwd, so it is skipped.
        let cwd = tempfile::tempdir().expect("tempdir");
        make_exe(cwd.path(), "passmgr-local-tool", 0o755);
        let error = resolve_program("passmgr-local-tool", cwd.path(), OsStr::new(""))
            .expect_err("must not search the cwd");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn an_absolute_path_is_passed_through_unchanged() {
        // Existing or not: the daemon's spawn failure is the accurate report,
        // and rewriting the path would change what the caller asked for.
        assert_eq!(
            resolve_program("/nonexistent/passmgr-tool", Path::new("/"), OsStr::new(""))
                .expect("absolute"),
            Path::new("/nonexistent/passmgr-tool")
        );
        assert_eq!(
            resolve_program("/bin/true", Path::new("/"), OsStr::new("")).expect("absolute"),
            Path::new("/bin/true")
        );
    }

    #[test]
    fn a_missing_bare_name_is_a_usage_error() {
        let error = resolve_program(
            "passmgr-no-such-program",
            Path::new("/"),
            OsStr::new("/bin"),
        )
        .expect_err("missing program");
        assert_eq!(error.exit_code(), 2);
        assert!(
            error.to_string().contains("passmgr-no-such-program"),
            "the caller must learn which program was missing: {error}"
        );
    }
}
