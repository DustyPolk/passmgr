//! The 0600 session file that carries an unlock-session token.
//!
//! `passmgr unlock` writes the token here; every client reads it and puts it
//! in its request envelope; `pmd` rejects a mismatch with `unauthorized`
//! before doing anything else. See [`crate::token`] for what the token is and
//! is not.
//!
//! # File handling
//!
//! The token is written atomically (temporary file inside the 0700 runtime
//! directory, `fsync`, rename, directory `fsync`) with mode 0600. Reading it is
//! strict: the path must be a regular file owned by the current user with mode
//! exactly 0600, opened with `O_NOFOLLOW`. Anything else is refused rather
//! than repaired, so a planted symlink or a loosened mode is a visible error
//! instead of a silent token leak.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::socket::{RuntimePaths, SocketError};
use crate::text::escape_path;
use crate::token::{SessionToken, TokenError};
use zeroize::Zeroizing;

/// A session file larger than this is not one we wrote.
const MAX_SESSION_FILE_BYTES: usize = 512;
/// The only mode a session file may have.
const SESSION_FILE_MODE: u32 = 0o600;

/// Write `token` to the session file atomically, creating the 0700 runtime
/// directory if needed.
///
/// The temporary file is created with mode 0600 and renamed into place, so a
/// crash cannot leave a partially written or world-readable token behind. Any
/// previous file is replaced.
pub fn store(paths: &RuntimePaths, token: &SessionToken) -> Result<(), SessionError> {
    paths.ensure_dir().map_err(SessionError::Socket)?;
    let path = paths.session();
    let mut temporary = tempfile::Builder::new()
        .prefix(".session-")
        .permissions(fs::Permissions::from_mode(SESSION_FILE_MODE))
        .tempfile_in(paths.dir())
        .map_err(|source| SessionError::Io {
            path: paths.dir().to_path_buf(),
            source,
        })?;

    let hex = token.to_hex();
    temporary
        .write_all(hex.as_bytes())
        .and_then(|()| temporary.write_all(b"\n"))
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| SessionError::Io {
            path: path.clone(),
            source,
        })?;
    temporary.persist(&path).map_err(|err| SessionError::Io {
        path: path.clone(),
        source: err.error,
    })?;

    // Make the rename durable. Failure here is not fatal for a runtime file:
    // the token is already readable.
    if let Ok(directory) = File::open(paths.dir()) {
        let _ = directory.sync_all();
    }
    Ok(())
}

/// Read and validate the session token.
///
/// Missing, symlinked, non-regular, foreign-owned or loosely-permissioned
/// files are refused; the caller can only proceed with a token this user wrote
/// at 0600.
pub fn load(paths: &RuntimePaths) -> Result<SessionToken, SessionError> {
    let path = paths.session();
    let (file, metadata) = open_regular(&path)?;
    let mode = metadata.mode() & 0o777;
    if mode != SESSION_FILE_MODE {
        return Err(SessionError::Insecure {
            path,
            detail: format!("permissions {mode:04o}, expected 0600"),
        });
    }
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    let own_uid = unsafe { libc::geteuid() };
    if metadata.uid() != own_uid {
        return Err(SessionError::Insecure {
            path,
            detail: "not owned by the current user".into(),
        });
    }
    read_token(file, &path)
}

/// Remove the session file, if it exists.
///
/// Used when starting a new session (to clear a stale file) and when a client
/// has confirmed the daemon wiped its key.
pub fn remove(paths: &RuntimePaths) -> Result<bool, SessionError> {
    let path = paths.session();
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(SessionError::Io { path, source }),
    }
}

/// Remove the session file only if it still holds `token`.
///
/// A daemon that shuts down calls this so it can never delete a *newer*
/// session's token: if another unlock already replaced the file, the content
/// no longer matches and the file is left alone. The check is lenient about
/// permissions (removal is cleanup, not authorization), but never follows a
/// symlink and never removes a foreign file.
pub fn remove_if_matches(paths: &RuntimePaths, token: &SessionToken) -> bool {
    let path = paths.session();
    let Ok((file, _)) = open_regular(&path) else {
        return false;
    };
    let Ok(found) = read_token(file, &path) else {
        return false;
    };
    found.matches(token) && fs::remove_file(&path).is_ok()
}

/// Open `path` and refuse anything but a regular file.
///
/// The checks use the descriptor that was opened, so the file cannot be
/// swapped between the check and the read. A symlink planted at the path is an
/// attack, not a convenience, and `O_NONBLOCK` keeps a FIFO from blocking the
/// open until the regular-file check refuses it.
fn open_regular(path: &Path) -> Result<(File, fs::Metadata), SessionError> {
    let io_error = |source| SessionError::Io {
        path: path.to_path_buf(),
        source,
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| match source.raw_os_error() {
            Some(libc::ELOOP) => SessionError::Insecure {
                path: path.to_path_buf(),
                detail: "not a regular file".into(),
            },
            _ => io_error(source),
        })?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() {
        return Err(SessionError::Insecure {
            path: path.to_path_buf(),
            detail: "not a regular file".into(),
        });
    }
    Ok((file, metadata))
}

/// Read the bounded token text and parse it. The hex is the bearer secret, so
/// the buffer is wiped when it goes out of scope.
fn read_token(file: File, path: &Path) -> Result<SessionToken, SessionError> {
    let mut text = Zeroizing::new(Vec::with_capacity(MAX_SESSION_FILE_BYTES + 1));
    file.take(MAX_SESSION_FILE_BYTES as u64 + 1)
        .read_to_end(&mut text)
        .map_err(|source| SessionError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if text.len() > MAX_SESSION_FILE_BYTES {
        return Err(SessionError::Invalid(
            "the session token file is larger than expected".into(),
        ));
    }
    // Invalid UTF-8 parses as empty text, which `from_hex` rejects.
    let text = std::str::from_utf8(&text).unwrap_or_default();
    SessionToken::from_hex(text.trim_end()).map_err(SessionError::Token)
}

/// Why the session file could not be written, read or removed.
///
/// Messages contain paths and fixed reasons only, never token bytes.
#[derive(Debug)]
pub enum SessionError {
    /// The runtime directory could not be prepared.
    Socket(SocketError),
    /// Local file I/O failure.
    Io { path: PathBuf, source: io::Error },
    /// The file exists but is not a plain 0600 file owned by this user.
    Insecure { path: PathBuf, detail: String },
    /// The file content is not a session token.
    Token(TokenError),
    /// The file is larger than a session file can be.
    Invalid(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(err) => write!(f, "{err}"),
            Self::Io { path, source } => {
                write!(f, "cannot access '{}': {source}", escape_path(path))
            }
            Self::Insecure { path, detail } => write!(
                f,
                "refusing the session token file '{}': {detail}",
                escape_path(path)
            ),
            Self::Token(err) => write!(f, "invalid session token file: {err}"),
            Self::Invalid(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Socket(err) => Some(err),
            Self::Io { source, .. } => Some(source),
            Self::Token(err) => Some(err),
            Self::Insecure { .. } | Self::Invalid(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::DirBuilderExt;

    use super::*;
    use tempfile::TempDir;

    fn runtime_paths() -> (TempDir, RuntimePaths) {
        let directory = TempDir::new().expect("tempdir");
        let runtime = directory.path().join("runtime");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&runtime)
            .expect("create runtime dir");
        let paths = RuntimePaths::at(&runtime);
        (directory, paths)
    }

    #[test]
    fn store_writes_a_0600_file_and_load_reads_it_back() {
        let (_directory, paths) = runtime_paths();
        let token = SessionToken::generate().expect("generate");
        store(&paths, &token).expect("store");

        let path = paths.session();
        let metadata = fs::metadata(&path).expect("metadata");
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        let content = fs::read_to_string(&path).expect("read");
        assert_eq!(content.len(), crate::token::TOKEN_HEX_CHARS + 1);
        assert_eq!(content.trim_end(), token.to_hex().as_str());

        let loaded = load(&paths).expect("load");
        assert!(loaded.matches(&token));

        // A second store replaces the file.
        let replacement = SessionToken::generate().expect("generate");
        store(&paths, &replacement).expect("store again");
        assert!(load(&paths).expect("load").matches(&replacement));
    }

    #[test]
    fn no_temporary_file_survives_a_store() {
        let (_directory, paths) = runtime_paths();
        let token = SessionToken::generate().expect("generate");
        store(&paths, &token).expect("store");
        let leftovers: Vec<_> = fs::read_dir(paths.dir())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".session-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn load_refuses_missing_symlinked_and_loose_files() {
        let (_directory, paths) = runtime_paths();
        assert!(matches!(load(&paths), Err(SessionError::Io { .. })));

        let token = SessionToken::generate().expect("generate");
        store(&paths, &token).expect("store");
        let path = paths.session();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let error = load(&paths).expect_err("loose mode");
        assert!(matches!(error, SessionError::Insecure { .. }), "{error:?}");
        assert!(error.to_string().contains("0644"), "{error}");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        assert!(load(&paths).is_ok());

        // A symlink pointing at a valid token file is still refused.
        let target = paths.dir().join("elsewhere");
        fs::rename(&path, &target).expect("move token");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        let error = load(&paths).expect_err("symlink");
        assert!(matches!(error, SessionError::Insecure { .. }), "{error:?}");

        fs::remove_file(&path).expect("unlink symlink");
        fs::create_dir(&path).expect("directory at the token path");
        let error = load(&paths).expect_err("directory");
        assert!(matches!(error, SessionError::Insecure { .. }), "{error:?}");
    }

    #[test]
    fn load_rejects_content_that_is_not_a_token_without_echoing_it() {
        let (_directory, paths) = runtime_paths();
        let token = SessionToken::generate().expect("generate");
        store(&paths, &token).expect("store");

        let marker = "not-a-token-SUPER-SECRET";
        fs::write(paths.session(), format!("{marker}\n")).expect("overwrite");
        let error = load(&paths).expect_err("invalid content");
        assert!(matches!(error, SessionError::Token(_)), "{error:?}");
        let text = format!("{error} {error:?}");
        assert!(!text.contains(marker), "{text}");
    }

    #[test]
    fn remove_and_remove_if_matches_are_scoped() {
        let (_directory, paths) = runtime_paths();
        let token = SessionToken::generate().expect("generate");
        store(&paths, &token).expect("store");

        let other = SessionToken::generate().expect("generate");
        assert!(!remove_if_matches(&paths, &other));
        assert!(paths.session().exists(), "a non-matching token must stay");

        assert!(remove_if_matches(&paths, &token));
        assert!(!paths.session().exists());

        // Removing an absent file is not an error.
        assert!(!remove(&paths).expect("remove"));
    }

    #[test]
    fn a_fifo_at_the_session_path_is_left_alone_without_blocking() {
        let (_directory, paths) = runtime_paths();
        let made = std::process::Command::new("mkfifo")
            .arg(paths.session())
            .status();
        assert!(made.expect("run mkfifo").success(), "mkfifo");

        let token = SessionToken::generate().expect("generate");
        let (sender, receiver) = std::sync::mpsc::channel();
        let shared = paths.clone();
        std::thread::spawn(move || {
            let _ = sender.send(remove_if_matches(&shared, &token));
        });
        let removed = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("reading a FIFO must not block");
        assert!(!removed);
        assert!(paths.session().exists(), "the FIFO is not removed");
        let error = load(&paths).expect_err("a FIFO is not a session file");
        assert!(matches!(error, SessionError::Insecure { .. }), "{error:?}");
    }

    #[test]
    fn a_hidden_character_in_the_runtime_path_is_rendered_as_text() {
        let directory = TempDir::new().expect("tempdir");
        let runtime = directory.path().join("run\u{1b}]0;x\u{7}");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&runtime)
            .expect("create runtime dir");
        let text = load(&RuntimePaths::at(&runtime))
            .expect_err("no session file")
            .to_string();
        assert!(text.contains(r"\u{1b}"), "{text:?}");
        assert!(
            !text.contains('\u{1b}') && !text.contains('\u{7}'),
            "{text:?}"
        );
    }

    #[test]
    fn store_rejects_an_insecure_runtime_directory() {
        let directory = TempDir::new().expect("tempdir");
        let runtime = directory.path().join("runtime");
        fs::DirBuilder::new()
            .mode(0o755)
            .create(&runtime)
            .expect("create runtime dir");
        let paths = RuntimePaths::at(&runtime);
        let token = SessionToken::generate().expect("generate");
        let error = store(&paths, &token).expect_err("insecure dir");
        assert!(matches!(error, SessionError::Socket(_)), "{error:?}");
        assert!(!paths.session().exists());
    }
}
