use std::fmt;
use std::io;
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

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
    DuplicateService(String),
    ServiceNotFound(String),
    InvalidInput(String),
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
            Self::DuplicateService(service) => write!(
                f,
                "a credential for '{service}' already exists; delete it first"
            ),
            Self::ServiceNotFound(service) => {
                write!(f, "no credential found for '{service}'")
            }
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
