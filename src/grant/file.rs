//! Read the grant token an agent was given, without trusting the file.
//!
//! A human creates a grant with `passmgr grant create --out FILE`; the agent
//! receives that 0600 file (or its path in `PASSMGR_GRANT_FILE`). This module
//! is the one place that turns the file into a [`GrantToken`], so every
//! caller gets the same strict checks:
//!
//! - refuse a symlink, a directory or any other non-regular file
//! - refuse a file owned by another user
//! - refuse a file that is group- or world-readable (`0600` or `0400`)
//! - read at most [`MAX_TOKEN_FILE_BYTES`] and parse exactly one lowercase
//!   hex token, ignoring one trailing newline
//!
//! The checks run on the opened descriptor, not on a path looked up first, so
//! replacing the file between check and open cannot bypass them. Error text
//! names the path and the reason, never the token.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::token::{GRANT_TOKEN_HEX_CHARS, GrantToken};

/// A token file larger than this is not one `grant create --out` wrote.
const MAX_TOKEN_FILE_BYTES: usize = 128;

/// Why a grant token file was refused.
#[derive(Debug)]
pub enum GrantFileError {
    /// The file could not be opened or read.
    Io {
        /// The path the caller named (metadata, never a secret).
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The file exists but is not safe to read.
    Insecure {
        /// The path the caller named.
        path: PathBuf,
        /// What was wrong, without any file content.
        detail: String,
    },
    /// The file does not contain one valid token.
    Token {
        /// The path the caller named.
        path: PathBuf,
    },
}

impl fmt::Display for GrantFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "cannot read grant token file {}: {source}", shown(path))
            }
            Self::Insecure { path, detail } => {
                write!(f, "refusing grant token file {}: {detail}", shown(path))
            }
            Self::Token { path } => write!(
                f,
                "grant token file {} does not contain one {GRANT_TOKEN_HEX_CHARS}-character \
                 lowercase hex token",
                shown(path)
            ),
        }
    }
}

/// A path is untrusted argv input; never let it drive the terminal.
fn shown(path: &Path) -> String {
    super::escape_hidden(&path.to_string_lossy())
}

impl std::error::Error for GrantFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Insecure { .. } | Self::Token { .. } => None,
        }
    }
}

/// Read and validate a grant token file.
pub fn read_grant_token(path: &Path) -> Result<GrantToken, GrantFileError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| GrantFileError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    // Check the descriptor we actually opened. `symlink_metadata` before an
    // open is a time-of-check/time-of-use gap; `fstat` on the open file is not.
    let metadata = file.metadata().map_err(|source| GrantFileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(GrantFileError::Insecure {
            path: path.to_path_buf(),
            detail: "not a regular file".into(),
        });
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(GrantFileError::Insecure {
            path: path.to_path_buf(),
            detail: format!("permissions {mode:04o} let another user read it; use 0600"),
        });
    }
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    let own_uid = unsafe { libc::geteuid() };
    if metadata.uid() != own_uid {
        return Err(GrantFileError::Insecure {
            path: path.to_path_buf(),
            detail: "not owned by the current user".into(),
        });
    }

    // The hex text is the bearer secret; wipe it when it goes out of scope.
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_TOKEN_FILE_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|source| GrantFileError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if text.len() > MAX_TOKEN_FILE_BYTES {
        return Err(GrantFileError::Insecure {
            path: path.to_path_buf(),
            detail: format!("larger than {MAX_TOKEN_FILE_BYTES} bytes"),
        });
    }
    GrantToken::from_hex(text.trim_end()).map_err(|_| GrantFileError::Token {
        path: path.to_path_buf(),
    })
}

/// Create a private token file for tests and for `grant create --out`.
///
/// Kept here so the writer and the reader agree on the mode and the trailing
/// newline. Production code writes the token through `TokenFile` in the CLI;
/// this helper exists only under `cfg(test)`.
#[cfg(test)]
fn write_for_test(path: &Path, token: &GrantToken, mode: u32) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(token.to_hex().as_bytes())?;
    file.write_all(b"\n")?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::token::GrantToken;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    fn token_file(dir: &Path, mode: u32) -> (PathBuf, GrantToken) {
        let token = GrantToken::generate().expect("token");
        let path = dir.join("grant.token");
        write_for_test(&path, &token, mode).expect("write token file");
        (path, token)
    }

    #[test]
    fn a_0600_file_round_trips_and_ignores_one_trailing_newline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, token) = token_file(dir.path(), 0o600);
        let read = read_grant_token(&path).expect("read token");
        assert!(read.hash().matches(&token.hash()));
    }

    #[test]
    fn a_0400_file_is_readable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, token) = token_file(dir.path(), 0o400);
        let read = read_grant_token(&path).expect("read token");
        assert!(read.hash().matches(&token.hash()));
    }

    #[test]
    fn group_or_world_readable_files_are_refused_without_echoing_the_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        for mode in [0o640, 0o604, 0o644] {
            let (path, token) = token_file(dir.path(), mode);
            let error = read_grant_token(&path).expect_err("must refuse loose mode");
            let text = error.to_string();
            assert!(text.contains("permissions"), "{text}");
            assert!(
                !text.contains(&*token.to_hex()),
                "error echoed the token: {text}"
            );
            fs::remove_file(&path).expect("cleanup");
        }
    }

    #[test]
    fn a_symlink_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, token) = token_file(dir.path(), 0o600);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        let error = read_grant_token(&link).expect_err("must refuse a symlink");
        let text = error.to_string();
        assert!(
            !text.contains(&*token.to_hex()),
            "error echoed the token: {text}"
        );
        assert!(text.contains("grant token file"), "{text}");
    }

    #[test]
    fn a_directory_and_an_oversized_file_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let directory = dir.path().join("directory");
        fs::create_dir(&directory).expect("mkdir");
        assert!(read_grant_token(&directory).is_err());

        let path = dir.path().join("large");
        fs::write(&path, "a".repeat(MAX_TOKEN_FILE_BYTES + 1)).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let error = read_grant_token(&path).expect_err("must refuse oversized");
        assert!(error.to_string().contains("larger than"), "{error}");
    }

    #[test]
    fn a_bad_token_is_refused_without_echoing_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.token");
        let canary = "A".repeat(GRANT_TOKEN_HEX_CHARS);
        fs::write(&path, format!("{canary}\n")).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let error = read_grant_token(&path).expect_err("must refuse uppercase");
        let text = error.to_string();
        assert!(!text.contains(&canary), "error echoed the token: {text}");
    }

    #[test]
    fn a_path_with_hidden_characters_is_rendered_as_text() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad\u{1b}[2K\r.token");
        fs::write(&path, "x").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let text = read_grant_token(&path).expect_err("loose mode").to_string();
        assert!(text.contains(r"\u{1b}"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
        assert!(!text.contains('\r'), "{text}");
    }

    #[test]
    fn a_missing_file_is_an_io_error_naming_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent");
        let error = read_grant_token(&path).expect_err("must refuse missing");
        assert!(error.to_string().contains("absent"), "{error}");
    }
}
