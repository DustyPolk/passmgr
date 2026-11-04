use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::text::{escape_hidden, escape_path, escape_quoted};

pub type Result<T> = std::result::Result<T, Error>;

/// Stable process exit codes. These are part of the command-line contract:
/// scripts and agents may rely on them, so do not renumber them.
pub const EXIT_OK: u8 = 0;
/// Any runtime failure without a more specific code below.
pub const EXIT_FAILURE: u8 = 1;
/// Usage error (bad arguments) or invalid input supplied at a prompt.
pub const EXIT_USAGE: u8 = 2;
/// The requested vault or credential does not exist.
pub const EXIT_NOT_FOUND: u8 = 3;
/// The master password was wrong (or the vault failed authentication).
pub const EXIT_AUTH_FAILED: u8 = 4;
/// The operation was refused (for example a plaintext reveal outside a TTY).
pub const EXIT_REFUSED: u8 = 5;
/// The vault file or the audit log is malformed, truncated, or its hash chain
/// does not verify.
pub const EXIT_MALFORMED_VAULT: u8 = 6;
/// `run` could not relay its own output because the caller closed the pipe.
/// 141 is the shell's SIGPIPE status (128 + 13): the child's status can no
/// longer reach the caller, so reporting success would hide a failure.
pub const EXIT_OUTPUT_CLOSED: u8 = 141;

/// Errors returned by the library.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    VaultNotFound(PathBuf),
    NotAVault,
    LegacyVault,
    UnsupportedVersion(u8),
    UnsupportedFormat(String),
    MalformedVault(String),
    Crypto(String),
    AuthenticationFailed,
    /// The operation is not allowed in this context (for example a plaintext
    /// reveal without a terminal, or in an agent context). Maps to exit code 5.
    Refused(String),
    DuplicateService(String),
    ServiceNotFound(String),
    /// No credential matches the given `pm://` reference. Maps to exit code 3.
    EntryNotFound(String),
    /// No grant has the given id. Maps to exit code 3. The id is already public
    /// metadata (it appears in `pm grant list`), so it is safe to echo.
    GrantNotFound(crate::grant::GrantId),
    /// The vault was opened read-only and cannot be saved. Library misuse;
    /// mutating commands open it with [`crate::Vault::open_for_update`].
    ReadOnlyVault(PathBuf),
    /// Another process held the vault write lock for longer than the timeout.
    /// Maps to exit code 1: nothing was changed, so retrying is safe.
    VaultBusy(PathBuf),
    /// The vault was read, the human was prompted, and another process changed
    /// the vault before the write lock could be taken. Maps to exit code 1:
    /// nothing was changed, so retrying is safe.
    VaultChanged(PathBuf),
    /// The unlock daemon could not be reached, exited during startup, or
    /// answered an error. The detail is user-facing and never contains secret
    /// material. Maps to exit code 1.
    Daemon(String),
    /// The audit log could not be read or written. The detail is a path and a
    /// fixed reason, never a record. Maps to exit code 1.
    Audit(String),
    /// The audit log is malformed or its hash chain does not verify. The
    /// detail names the first broken line and is safe to print. Maps to exit
    /// code 6, like a malformed vault.
    AuditBroken(String),
    InvalidInput(String),
}

impl Error {
    /// The stable exit code for this error. See the `EXIT_*` constants.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::VaultNotFound(_)
            | Self::ServiceNotFound(_)
            | Self::EntryNotFound(_)
            | Self::GrantNotFound(_) => EXIT_NOT_FOUND,
            Self::AuthenticationFailed => EXIT_AUTH_FAILED,
            Self::Refused(_) => EXIT_REFUSED,
            Self::NotAVault
            | Self::LegacyVault
            | Self::UnsupportedVersion(_)
            | Self::UnsupportedFormat(_)
            | Self::MalformedVault(_)
            | Self::AuditBroken(_) => EXIT_MALFORMED_VAULT,
            Self::InvalidInput(_) => EXIT_USAGE,
            // Duplicate entries, I/O failures, crypto failures (RNG or
            // encryption setup) and daemon failures are plain runtime errors.
            Self::Io(_)
            | Self::Crypto(_)
            | Self::DuplicateService(_)
            | Self::Daemon(_)
            | Self::ReadOnlyVault(_)
            | Self::VaultBusy(_)
            | Self::VaultChanged(_)
            | Self::Audit(_) => EXIT_FAILURE,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::VaultNotFound(path) => {
                write!(f, "no vault found at '{}'", escape_path(path))
            }
            Self::NotAVault => write!(f, "file is not a passmgr vault"),
            Self::LegacyVault => write!(
                f,
                "vault uses the legacy C format (version 1), which this build does not read; \
                 use the binary in legacy-c/, or re-add the credentials"
            ),
            Self::UnsupportedVersion(version) => write!(
                f,
                "unsupported vault format version {version} (this build expects version 2)"
            ),
            Self::UnsupportedFormat(detail) => {
                write!(f, "unsupported vault format: {}", escape_hidden(detail))
            }
            Self::MalformedVault(detail) => {
                write!(f, "malformed vault: {}", escape_hidden(detail))
            }
            Self::Crypto(detail) => write!(f, "crypto error: {}", escape_hidden(detail)),
            Self::AuthenticationFailed => {
                write!(f, "wrong master password or corrupted vault")
            }
            Self::Refused(detail) => f.write_str(&escape_hidden(detail)),
            Self::DuplicateService(service) => write!(
                f,
                "a credential for '{}' already exists; delete it first",
                escape_quoted(service)
            ),
            Self::ServiceNotFound(service) => {
                write!(f, "no credential found for '{}'", escape_quoted(service))
            }
            Self::EntryNotFound(reference) => {
                write!(
                    f,
                    "no credential found for reference '{}'",
                    escape_quoted(reference)
                )
            }
            Self::GrantNotFound(id) => write!(f, "no grant found with id '{id}'"),
            Self::ReadOnlyVault(path) => write!(
                f,
                "vault '{}' was opened read-only; reopen it for update to save",
                escape_path(path)
            ),
            Self::VaultBusy(path) => write!(
                f,
                "another passmgr process is updating '{}'; nothing was changed, try again",
                escape_path(path)
            ),
            Self::VaultChanged(path) => write!(
                f,
                "vault '{}' changed while it was open; nothing was changed, try again",
                escape_path(path)
            ),
            Self::Daemon(detail) => f.write_str(&escape_hidden(detail)),
            Self::Audit(detail) => write!(f, "audit log: {}", escape_hidden(detail)),
            Self::AuditBroken(detail) => {
                write!(
                    f,
                    "audit log verification failed: {}",
                    escape_hidden(detail)
                )
            }
            Self::InvalidInput(detail) => f.write_str(&escape_hidden(detail)),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<crate::audit::AuditError> for Error {
    /// A malformed log is a verification failure (exit 6); every other audit
    /// error is a read/write problem (exit 1). The conversion keeps the
    /// detail, which never contains a record or a secret.
    fn from(error: crate::audit::AuditError) -> Self {
        match error {
            crate::audit::AuditError::Malformed(detail) => Self::AuditBroken(detail),
            other => Self::Audit(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable_and_distinct() {
        let cases: Vec<(Error, u8)> = vec![
            (Error::VaultNotFound(PathBuf::from("v.dat")), EXIT_NOT_FOUND),
            (Error::ServiceNotFound("svc".into()), EXIT_NOT_FOUND),
            (Error::EntryNotFound("pm://00".into()), EXIT_NOT_FOUND),
            (Error::AuthenticationFailed, EXIT_AUTH_FAILED),
            (Error::Refused("no".into()), EXIT_REFUSED),
            (Error::NotAVault, EXIT_MALFORMED_VAULT),
            (Error::LegacyVault, EXIT_MALFORMED_VAULT),
            (Error::UnsupportedVersion(9), EXIT_MALFORMED_VAULT),
            (Error::UnsupportedFormat("x".into()), EXIT_MALFORMED_VAULT),
            (Error::MalformedVault("x".into()), EXIT_MALFORMED_VAULT),
            (Error::InvalidInput("x".into()), EXIT_USAGE),
            (Error::DuplicateService("svc".into()), EXIT_FAILURE),
            (Error::Crypto("x".into()), EXIT_FAILURE),
            (Error::Daemon("x".into()), EXIT_FAILURE),
            (Error::ReadOnlyVault(PathBuf::from("v.dat")), EXIT_FAILURE),
            (Error::VaultBusy(PathBuf::from("v.dat")), EXIT_FAILURE),
            (Error::VaultChanged(PathBuf::from("v.dat")), EXIT_FAILURE),
            (Error::Audit("x".into()), EXIT_FAILURE),
            (Error::AuditBroken("x".into()), EXIT_MALFORMED_VAULT),
            (Error::Io(std::io::Error::other("x")), EXIT_FAILURE),
        ];
        for (error, expected) in cases {
            assert_eq!(error.exit_code(), expected, "wrong code for {error:?}");
        }

        // The documented contract: 0 success, 2 usage, 3 not found,
        // 4 auth, 5 refused, 6 malformed vault.
        assert_eq!(EXIT_OK, 0);
        assert_eq!(EXIT_USAGE, 2);
        assert_eq!(EXIT_NOT_FOUND, 3);
        assert_eq!(EXIT_AUTH_FAILED, 4);
        assert_eq!(EXIT_REFUSED, 5);
        assert_eq!(EXIT_MALFORMED_VAULT, 6);
    }
}
