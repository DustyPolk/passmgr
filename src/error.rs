use std::fmt;
use std::io;
use std::path::PathBuf;

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
/// The vault file is malformed, truncated, or in an unsupported format.
pub const EXIT_MALFORMED_VAULT: u8 = 6;

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
    /// The unlock daemon could not be reached, exited during startup, or
    /// answered an error. The detail is user-facing and never contains secret
    /// material. Maps to exit code 1.
    Daemon(String),
    InvalidInput(String),
}

impl Error {
    /// The stable exit code for this error. See the `EXIT_*` constants.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::VaultNotFound(_) | Self::ServiceNotFound(_) | Self::EntryNotFound(_) => {
                EXIT_NOT_FOUND
            }
            Self::AuthenticationFailed => EXIT_AUTH_FAILED,
            Self::Refused(_) => EXIT_REFUSED,
            Self::NotAVault
            | Self::LegacyVault
            | Self::UnsupportedVersion(_)
            | Self::UnsupportedFormat(_)
            | Self::MalformedVault(_) => EXIT_MALFORMED_VAULT,
            Self::InvalidInput(_) => EXIT_USAGE,
            // Duplicate entries, I/O failures, crypto failures (RNG or
            // encryption setup) and daemon failures are plain runtime errors.
            Self::Io(_) | Self::Crypto(_) | Self::DuplicateService(_) | Self::Daemon(_) => {
                EXIT_FAILURE
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::VaultNotFound(path) => write!(f, "no vault found at '{}'", path.display()),
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
                write!(f, "unsupported vault format: {detail}")
            }
            Self::MalformedVault(detail) => write!(f, "malformed vault: {detail}"),
            Self::Crypto(detail) => write!(f, "crypto error: {detail}"),
            Self::AuthenticationFailed => {
                write!(f, "wrong master password or corrupted vault")
            }
            Self::Refused(detail) => f.write_str(detail),
            Self::DuplicateService(service) => write!(
                f,
                "a credential for '{service}' already exists; delete it first"
            ),
            Self::ServiceNotFound(service) => {
                write!(f, "no credential found for '{service}'")
            }
            Self::EntryNotFound(reference) => {
                write!(f, "no credential found for reference '{reference}'")
            }
            Self::Daemon(detail) => f.write_str(detail),
            Self::InvalidInput(detail) => f.write_str(detail),
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
