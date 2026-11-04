//! A small, local password manager.
//!
//! The vault is a single file protected with Argon2id and AES-256-GCM.
//! See `FORMAT.md` for the on-disk layout.

pub mod agent;
#[cfg(unix)]
pub mod audit;
#[cfg(unix)]
pub mod client;
pub mod crypto;
#[cfg(unix)]
pub mod daemon;
pub mod error;
pub mod grant;
pub mod password;
pub mod presence;
pub mod protocol;
pub mod redact;
#[cfg(unix)]
pub mod runner;
#[cfg(unix)]
pub mod session;
#[cfg(unix)]
pub mod socket;
pub mod store;
pub mod terminal;
pub mod text;
pub mod timestamp;
pub mod token;
pub mod vault;

pub use error::{
    EXIT_AUTH_FAILED, EXIT_FAILURE, EXIT_MALFORMED_VAULT, EXIT_NOT_FOUND, EXIT_OK, EXIT_REFUSED,
    EXIT_USAGE, Error, Result,
};
pub use password::{MAX_LEN, MIN_LEN, Preset, generate_password};
pub use store::Credential;
pub use vault::Vault;
