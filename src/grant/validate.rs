//! Validation of the human-facing strings a grant carries: the label, the
//! command allowlist and field names.
//!
//! Kept apart from the model in `grant.rs` so that file stays readable; every
//! function here is pure and returns `InvalidInput`, which the payload decoder
//! turns into `MalformedVault`. The label table is the one the review notes
//! (TODO R.18) point at.

use std::path::{Path, PathBuf};

use super::{MAX_COMMANDS, MAX_FIELD_NAME_BYTES, MAX_LABEL_BYTES};
use crate::error::{Error, Result};
use crate::protocol::MAX_PATH_BYTES;
use crate::text::{escape_quoted, is_hidden_or_reordering};

/// The classes of character a grant label or command path may not contain,
/// spelled the same way in the rejection error, `FORMAT.md` and
/// `DECISIONS.md` (TODO R.18, R.21).
///
/// The error names the whole class rather than echoing the offending code
/// point (or the label), because the label is untrusted text that later gets
/// printed to a terminal. A bad command is echoed back, but escaped (see
/// [`escape_quoted`]) so its own characters cannot forge the error line.
pub const LABEL_FORBIDDEN_CLASSES: &str = crate::text::HIDDEN_FORBIDDEN_CLASSES;

pub(super) fn validate_label(label: &str) -> Result<()> {
    if label.trim().is_empty() {
        return Err(Error::InvalidInput("a grant needs a label".into()));
    }
    if label.len() > MAX_LABEL_BYTES {
        return Err(Error::InvalidInput(format!(
            "a grant label holds at most {MAX_LABEL_BYTES} bytes"
        )));
    }
    if label.chars().any(is_hidden_or_reordering) {
        return Err(Error::InvalidInput(format!(
            "a grant label must not contain {LABEL_FORBIDDEN_CLASSES} characters"
        )));
    }
    Ok(())
}

/// Programs that can run another program, or code named by their arguments,
/// so a grant that allows one is a grant to run whatever it can start. A human
/// must pass `--allow-interpreter` to add one.
///
/// A grant binds a canonical absolute path and the daemon checks only
/// `argv[0]`, so a shell is not special: `git -c alias.pwn='!sh' pwn`,
/// `gh alias set --shell pwn '…'`, `find -exec`, `tar --to-command`, `sed`'s
/// `e` command, `ssh`'s `ProxyCommand` and an editor's shell escape all reach
/// a shell through an ordinary program. This table therefore covers the
/// well-known ways out, not just language interpreters that run a script
/// named by their arguments.
///
/// The table is best-effort, not a boundary: no list can name every program
/// that can spawn another, so allowlisting any program is a decision to trust
/// it with the value. Over-refusal is preferred — a false positive costs one
/// flag, a false negative costs the secret.
///
/// Kept as a pure table next to the label rules so the CLI and (from TODO 4.9)
/// the MCP request path refuse the same names. Matching is by file name only:
/// `/usr/bin/python3.12` is a runner even though its path is not
/// `/usr/bin/python`. The versioned bases accept a suffix that starts with a
/// digit or a dot, so `pythonista` is not mistaken for Python.
const PROGRAM_RUNNERS: &[&str] = &[
    // Shells and shell-like command languages.
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ash",
    "ksh",
    "mksh",
    "csh",
    "tcsh",
    "busybox",
    "elvish",
    "xonsh",
    "yash",
    "rc",
    "es",
    "osascript",
    // Launchers whose arguments are a program, or that start one anyway.
    "env",
    "xargs",
    "nohup",
    "setsid",
    "nice",
    "ionice",
    "timeout",
    "stdbuf",
    "flock",
    "watch",
    "time",
    "su",
    "sudo",
    "doas",
    "runuser",
    "chroot",
    "unshare",
    "nsenter",
    "systemd-run",
    "script",
    "expect",
    "strace",
    "ltrace",
    "gdb",
    "perf",
    "parallel",
    "tmux",
    "screen",
    // Editors, pagers and man, which all have a shell escape.
    "vi",
    "vim",
    "nvim",
    "view",
    "ex",
    "ed",
    "emacs",
    "nano",
    "less",
    "more",
    "most",
    "man",
    // Tools with an exec option or a command language.
    "find",
    "sed",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "tar",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "socat",
    "nc",
    "ncat",
    "netcat",
    // Version control, container and infrastructure CLIs that run aliases,
    // plugins or delegated commands.
    "git",
    "gh",
    "glab",
    "hub",
    "docker",
    "podman",
    "kubectl",
    "helm",
    "terraform",
    "ansible",
    "ansible-playbook",
    "vagrant",
    // Build and test runners that execute project-defined commands.
    "make",
    "cargo",
    "npm",
    "npx",
    "yarn",
    "pnpm",
    "deno",
    "bun",
    "go",
    "mvn",
    "gradle",
    "bazel",
    "rake",
    "java",
    "dotnet",
    // Database clients with a shell meta-command (`\!`, `.shell`, `system`).
    "psql",
    "mysql",
    "mariadb",
    "sqlite3",
];

/// Bases whose installed name carries a version, such as `python3.12`,
/// `perl5.36`, `node18` or `pwsh7`.
const VERSIONED_PROGRAM_RUNNERS: &[&str] = &[
    "python",
    "perl",
    "ruby",
    "node",
    "php",
    "lua",
    "luajit",
    "tclsh",
    "wish",
    "pwsh",
    "powershell",
    "julia",
    "Rscript",
    "groovy",
];

/// Whether `path` names a shell, interpreter or other program runner.
///
/// The check is on the final path component, because that is what the daemon
/// execs; a grant stores canonical absolute paths. See [`PROGRAM_RUNNERS`]
/// for why the list can never be complete.
pub fn is_program_runner(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_program_runner_name)
}

fn is_program_runner_name(name: &str) -> bool {
    PROGRAM_RUNNERS.contains(&name)
        || VERSIONED_PROGRAM_RUNNERS.iter().any(|base| {
            name == *base
                || name.strip_prefix(base).is_some_and(|suffix| {
                    suffix
                        .chars()
                        .next()
                        .is_some_and(|first| first.is_ascii_digit() || first == '.')
                })
        })
}

pub(super) fn validate_commands(commands: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    // TODO R.21: a command path has the same provenance as a label, so it
    // must not be able to hide or reorder what an approving human reads.
    // Share the label's class table: one rule, one place. Stored grants need
    // no migration; the check is on the create and decode paths.
    if commands.len() > MAX_COMMANDS {
        return Err(Error::InvalidInput(format!(
            "a grant allows at most {MAX_COMMANDS} commands"
        )));
    }
    let mut commands = commands;
    for command in &commands {
        let text = command
            .to_str()
            .ok_or_else(|| Error::InvalidInput("a grant command must be valid UTF-8".into()))?;
        if text.is_empty() {
            return Err(Error::InvalidInput(
                "a grant command must be a non-empty path".into(),
            ));
        }
        if text.chars().any(is_hidden_or_reordering) {
            return Err(Error::InvalidInput(format!(
                "grant command '{}' must not contain {LABEL_FORBIDDEN_CLASSES} \
                 characters",
                escape_quoted(text)
            )));
        }
        if !command.is_absolute() {
            return Err(Error::InvalidInput(format!(
                "grant command '{}' must be an absolute path",
                escape_quoted(text)
            )));
        }
        if text.len() > MAX_PATH_BYTES {
            return Err(Error::InvalidInput(format!(
                "grant command '{}' exceeds {MAX_PATH_BYTES} bytes",
                escape_quoted(text)
            )));
        }
    }
    commands.sort();
    commands.dedup();
    Ok(commands)
}

/// Field names (`password`, `token`, `api_key`, …): 1-32 bytes of
/// `[a-z0-9_-]`, as fixed by TODO 6.1.
pub fn validate_field_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= MAX_FIELD_NAME_BYTES
        && name
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "invalid field name '{}': expected 1-{MAX_FIELD_NAME_BYTES} characters of [a-z0-9_-]",
            escape_quoted(name)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A field name from `--field` is echoed in the rejection, so a control
    /// character must be escaped there rather than driven to the terminal.
    #[test]
    fn field_name_rejection_escapes_control_characters() {
        let error = validate_field_name("bad\u{1b}]52;c;ZXZpbA==\u{7}")
            .unwrap_err()
            .to_string();
        assert!(error.contains(r"\u{1b}"), "{error}");
        assert!(!error.contains('\u{1b}'), "{error}");
        assert!(!error.contains('\u{7}'), "{error}");
    }

    /// Program runners are recognised by their file name, including versioned
    /// interpreters, while ordinary programs (and lookalike names) are not.
    /// A grant binds only `argv[0]`, so the table has to cover more than
    /// language interpreters: `gh` and `git` run shells through aliases
    /// (TODO R.25), and `find`, `tar`, `ssh`, `sed`, editors and pagers each
    /// have an exec option or a shell escape.
    #[test]
    fn program_runners_are_recognised_by_file_name() {
        for path in [
            // Shells.
            "/bin/sh",
            "/usr/bin/bash",
            "/usr/bin/zsh",
            "/usr/bin/busybox",
            // Interpreters, including versioned spellings.
            "/usr/bin/python3",
            "/usr/bin/python3.12",
            "/usr/local/bin/perl5.36",
            "/usr/bin/node18",
            "/usr/bin/ruby",
            "/usr/bin/tclsh8.6",
            "/usr/bin/wish",
            // Launchers.
            "/usr/bin/env",
            "/usr/bin/xargs",
            "/usr/bin/timeout",
            "/usr/bin/sudo",
            "/usr/bin/tmux",
            // Tools with an exec option or a shell escape.
            "/usr/bin/find",
            "/usr/bin/sed",
            "/usr/bin/tar",
            "/usr/bin/ssh",
            "/usr/bin/nc",
            "/usr/bin/vim",
            "/usr/bin/less",
            "/usr/bin/man",
            // CLIs that run aliases, plugins or project commands.
            "/usr/bin/gh",
            "/usr/bin/git",
            "/usr/bin/docker",
            "/usr/bin/podman",
            "/usr/bin/kubectl",
            "/usr/bin/terraform",
            "/usr/bin/make",
            "/usr/bin/cargo",
            "/usr/bin/npm",
            "/usr/bin/go",
            "/usr/bin/psql",
            "/usr/bin/sqlite3",
        ] {
            assert!(is_program_runner(Path::new(path)), "{path}");
        }
        for path in [
            "/usr/bin/curl",
            "/usr/bin/jq",
            "/usr/bin/tree",
            "/usr/bin/envoy",
            "/usr/bin/pythonista",
            "/usr/bin/shadow",
            "/usr/bin/maker",
            "/opt/tools/tar.gz",
        ] {
            assert!(!is_program_runner(Path::new(path)), "{path}");
        }
    }
}
