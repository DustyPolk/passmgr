//! A small, local password manager.
//!
//! The vault is a single file protected with Argon2id and AES-256-GCM.
//! See `FORMAT.md` for the on-disk layout.

pub mod crypto;
pub mod error;
pub mod password;
pub mod store;
pub mod terminal;
pub mod vault;

pub use error::{Error, Result};
pub use password::{MAX_LEN, MIN_LEN, Preset, generate_password};
pub use store::Credential;
pub use vault::Vault;
