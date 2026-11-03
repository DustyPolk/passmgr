//! Vault container encryption.
//!
//! Layout (all integers little-endian):
//!
//! | offset | size | field                                  |
//! |--------|------|----------------------------------------|
//! | 0      | 4    | magic `PMGR`                           |
//! | 4      | 1    | format version (2)                     |
//! | 5      | 1    | KDF id (1 = Argon2id)                  |
//! | 6      | 1    | AEAD id (1 = AES-256-GCM)              |
//! | 7      | 1    | flags (0)                              |
//! | 8      | 4    | Argon2 memory cost, KiB                |
//! | 12     | 4    | Argon2 time cost                       |
//! | 16     | 4    | Argon2 parallelism                     |
//! | 20     | 16   | salt                                   |
//! | 36     | 12   | nonce                                  |
//! | 48     | 8    | ciphertext length (includes GCM tag)   |
//! | 56     | ..   | ciphertext followed by 16-byte tag     |
//!
//! The first 56 bytes are authenticated as AES-GCM associated data.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use getrandom::fill;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const HEADER_LEN: usize = 56;

pub const MAGIC: [u8; 4] = *b"PMGR";
pub const FORMAT_VERSION: u8 = 2;

pub const MAX_VAULT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PLAINTEXT_BYTES: usize = 10 * 1024 * 1024;

const KDF_ARGON2ID: u8 = 1;
const AEAD_AES256_GCM: u8 = 1;
const FLAGS: u8 = 0;

/// Bounds accepted when reading KDF parameters from a vault file. They keep a
/// malicious or corrupted header from requesting an unbounded amount of memory.
pub const MIN_M_COST_KIB: u32 = 8 * 1024;
pub const MAX_M_COST_KIB: u32 = 1024 * 1024;
pub const MIN_T_COST: u32 = 1;
pub const MAX_T_COST: u32 = 16;
pub const MIN_P_COST: u32 = 1;
pub const MAX_P_COST: u32 = 8;

/// Argon2id parameters stored in the vault header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub const fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost_kib,
            t_cost,
            p_cost,
        }
    }

    pub fn validate(self) -> Result<()> {
        if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&self.m_cost_kib) {
            return Err(Error::UnsupportedFormat(format!(
                "Argon2 memory cost {} KiB is outside the supported range {}..={} KiB",
                self.m_cost_kib, MIN_M_COST_KIB, MAX_M_COST_KIB
            )));
        }
        if !(MIN_T_COST..=MAX_T_COST).contains(&self.t_cost) {
            return Err(Error::UnsupportedFormat(format!(
                "Argon2 time cost {} is outside the supported range {}..={}",
                self.t_cost, MIN_T_COST, MAX_T_COST
            )));
        }
        if !(MIN_P_COST..=MAX_P_COST).contains(&self.p_cost) {
            return Err(Error::UnsupportedFormat(format!(
                "Argon2 parallelism {} is outside the supported range {}..={}",
                self.p_cost, MIN_P_COST, MAX_P_COST
            )));
        }
        if self.m_cost_kib < 8 * self.p_cost {
            return Err(Error::UnsupportedFormat(
                "Argon2 memory cost is too small for its parallelism".into(),
            ));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, single lane. Tuned for interactive unlock times on
    /// desktop machines; the parameters are stored in every vault so they can
    /// be raised in the future without breaking existing files.
    fn default() -> Self {
        Self::new(64 * 1024, 3, 1)
    }
}

struct Header {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext_len: u64,
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = FORMAT_VERSION;
        out[5] = KDF_ARGON2ID;
        out[6] = AEAD_AES256_GCM;
        out[7] = FLAGS;
        out[8..12].copy_from_slice(&self.params.m_cost_kib.to_le_bytes());
        out[12..16].copy_from_slice(&self.params.t_cost.to_le_bytes());
        out[16..20].copy_from_slice(&self.params.p_cost.to_le_bytes());
        out[20..36].copy_from_slice(&self.salt);
        out[36..48].copy_from_slice(&self.nonce);
        out[48..56].copy_from_slice(&self.ciphertext_len.to_le_bytes());
        out
    }

    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(Error::NotAVault);
        }
        if data[0..4] != MAGIC {
            return Err(Error::NotAVault);
        }
        if data[4] == 1 {
            return Err(Error::LegacyVault);
        }
        if data[4] != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(data[4]));
        }
        if data.len() < HEADER_LEN {
            return Err(Error::MalformedVault("truncated header".into()));
        }

        if data[5] != KDF_ARGON2ID {
            return Err(Error::UnsupportedFormat(format!(
                "unknown KDF id {}",
                data[5]
            )));
        }
        if data[6] != AEAD_AES256_GCM {
            return Err(Error::UnsupportedFormat(format!(
                "unknown AEAD id {}",
                data[6]
            )));
        }
        if data[7] != FLAGS {
            return Err(Error::UnsupportedFormat(format!(
                "unsupported flags 0x{:02x}",
                data[7]
            )));
        }

        let params = KdfParams::new(
            u32::from_le_bytes(data[8..12].try_into().expect("fixed-size slice")),
            u32::from_le_bytes(data[12..16].try_into().expect("fixed-size slice")),
            u32::from_le_bytes(data[16..20].try_into().expect("fixed-size slice")),
        );
        params.validate()?;

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[20..36]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&data[36..48]);
        let ciphertext_len = u64::from_le_bytes(data[48..56].try_into().expect("fixed-size slice"));

        if ciphertext_len < TAG_LEN as u64 {
            return Err(Error::MalformedVault(
                "declared ciphertext is shorter than the authentication tag".into(),
            ));
        }
        if ciphertext_len > MAX_VAULT_BYTES as u64 {
            return Err(Error::MalformedVault(
                "declared ciphertext is too large".into(),
            ));
        }

        Ok(Self {
            params,
            salt,
            nonce,
            ciphertext_len,
        })
    }
}

fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
    out: &mut [u8; KEY_LEN],
) -> Result<()> {
    params.validate()?;
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|err| Error::Crypto(format!("invalid Argon2 parameters: {err}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    argon
        .hash_password_into(password.as_bytes(), salt, out)
        .map_err(|err| Error::Crypto(format!("key derivation failed: {err}")))?;
    Ok(())
}

/// Encrypt `plaintext` into a complete vault container.
pub fn encrypt(plaintext: &[u8], master_password: &str, params: KdfParams) -> Result<Vec<u8>> {
    params.validate()?;
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::InvalidInput(format!(
            "vault contents are too large ({} bytes; maximum is {MAX_PLAINTEXT_BYTES})",
            plaintext.len()
        )));
    }

    let mut salt = [0u8; SALT_LEN];
    fill(&mut salt)
        .map_err(|err| Error::Crypto(format!("secure random generator failed: {err}")))?;
    let mut nonce = [0u8; NONCE_LEN];
    fill(&mut nonce)
        .map_err(|err| Error::Crypto(format!("secure random generator failed: {err}")))?;

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    derive_key(master_password, &salt, params, &mut key)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| Error::Crypto("failed to initialize AES-256-GCM".into()))?;
    drop(key);

    let ciphertext_len = (plaintext.len() + TAG_LEN) as u64;
    let header = Header {
        params,
        salt,
        nonce,
        ciphertext_len,
    };
    let header_bytes = header.encode();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header_bytes,
            },
        )
        .map_err(|_| Error::Crypto("encryption failed".into()))?;
    if ciphertext.len() as u64 != ciphertext_len {
        return Err(Error::Crypto(
            "encryption produced an unexpected ciphertext length".into(),
        ));
    }

    let mut container = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    container.extend_from_slice(&header_bytes);
    container.extend_from_slice(&ciphertext);
    Ok(container)
}

/// Decrypt a complete vault container. The returned plaintext is wiped when
/// dropped.
pub fn decrypt(container: &[u8], master_password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
    derive_vault_key(container, master_password, key.as_mut_slice())?;
    decrypt_with_key(container, key.as_slice())
}

/// Derive the vault key into `out` (exactly [`KEY_LEN`] bytes).
///
/// The key is *not* verified against the container here: pair it with
/// [`decrypt_with_key`], which authenticates. `out` is caller-owned so a
/// daemon can keep the key at one stable heap address (see `daemon`).
///
/// The KDF parameters and salt come from the authenticated vault header, so a
/// key derived here only opens this container.
pub fn derive_vault_key(container: &[u8], master_password: &str, out: &mut [u8]) -> Result<()> {
    if container.len() > MAX_VAULT_BYTES {
        return Err(Error::MalformedVault("vault file is too large".into()));
    }
    let key: &mut [u8; KEY_LEN] = out
        .try_into()
        .map_err(|_| Error::Crypto(format!("vault key must be exactly {KEY_LEN} bytes")))?;
    let header = Header::decode(container)?;
    derive_key(master_password, &header.salt, header.params, key)
}

/// Decrypt a container with an already-derived key.
///
/// This skips Argon2: the caller must have obtained `key` from
/// [`derive_vault_key`] (or [`unlock_key`]) for this exact container. The
/// returned plaintext is wiped when dropped.
pub fn decrypt_with_key(container: &[u8], key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != KEY_LEN {
        return Err(Error::Crypto(format!(
            "vault key must be exactly {KEY_LEN} bytes"
        )));
    }
    if container.len() > MAX_VAULT_BYTES {
        return Err(Error::MalformedVault("vault file is too large".into()));
    }
    let header = Header::decode(container)?;
    let header_bytes = &container[..HEADER_LEN];
    let ciphertext = &container[HEADER_LEN..];
    if ciphertext.len() as u64 != header.ciphertext_len {
        return Err(Error::MalformedVault(
            "ciphertext length does not match the header".into(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Crypto("failed to initialize AES-256-GCM".into()))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&header.nonce),
            Payload {
                msg: ciphertext,
                aad: header_bytes,
            },
        )
        .map_err(|_| Error::AuthenticationFailed)?;

    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::MalformedVault(
            "decrypted vault contents are too large".into(),
        ));
    }
    Ok(Zeroizing::new(plaintext))
}

/// Derive the vault key from the master password and prove that it
/// authenticates `container` before returning it.
///
/// This is the handover primitive for the unlock daemon: the human process
/// derives the key once, and a daemon that only ever holds the key (never the
/// master password) can decrypt the vault on demand. The returned key is
/// wiped when dropped.
pub fn unlock_key(container: &[u8], master_password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
    derive_vault_key(container, master_password, key.as_mut_slice())?;
    // Authenticate before handing the key out: a wrong password must fail
    // here, not later in the daemon.
    drop(decrypt_with_key(container, key.as_slice())?);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        KdfParams::new(8 * 1024, 1, 1)
    }

    #[test]
    fn roundtrip() {
        let params = fast_params();
        let plaintext = b"hello, vault";
        let container = encrypt(plaintext, "correct horse", params).unwrap();
        assert_eq!(container.len(), HEADER_LEN + plaintext.len() + TAG_LEN);
        assert_eq!(&container[0..4], b"PMGR");
        assert_eq!(container[4], FORMAT_VERSION);

        let decrypted = decrypt(&container, "correct horse").unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let container = encrypt(b"secret", "right password", fast_params()).unwrap();
        let err = decrypt(&container, "wrong password").unwrap_err();
        assert!(matches!(err, Error::AuthenticationFailed));
    }

    #[test]
    fn derived_key_decrypts_without_the_password() {
        let container = encrypt(b"secret", "right password", fast_params()).unwrap();
        let key = unlock_key(&container, "right password").unwrap();
        assert_eq!(key.len(), KEY_LEN);
        let plaintext = decrypt_with_key(&container, key.as_slice()).unwrap();
        assert_eq!(&*plaintext, b"secret");
    }

    #[test]
    fn a_wrong_key_is_rejected_by_authentication() {
        let container = encrypt(b"secret", "password", fast_params()).unwrap();
        let mut wrong = vec![0u8; KEY_LEN];
        // Derive a valid key for a *different* salt/password.
        let other = encrypt(b"other", "password", fast_params()).unwrap();
        wrong.copy_from_slice(unlock_key(&other, "password").unwrap().as_slice());
        assert!(matches!(
            decrypt_with_key(&container, &wrong).unwrap_err(),
            Error::AuthenticationFailed
        ));
    }

    #[test]
    fn key_lengths_are_enforced() {
        let container = encrypt(b"secret", "password", fast_params()).unwrap();
        assert!(matches!(
            decrypt_with_key(&container, &[0u8; KEY_LEN - 1]).unwrap_err(),
            Error::Crypto(_)
        ));
        let mut short = [0u8; KEY_LEN - 1];
        assert!(matches!(
            derive_vault_key(&container, "password", &mut short).unwrap_err(),
            Error::Crypto(_)
        ));
    }

    #[test]
    fn unlock_key_rejects_a_wrong_password() {
        let container = encrypt(b"secret", "password", fast_params()).unwrap();
        assert!(matches!(
            unlock_key(&container, "not the password").unwrap_err(),
            Error::AuthenticationFailed
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut container = encrypt(b"secret", "password", fast_params()).unwrap();
        let last = container.len() - 1;
        container[last] ^= 0x01;
        assert!(matches!(
            decrypt(&container, "password").unwrap_err(),
            Error::AuthenticationFailed
        ));
    }

    #[test]
    fn tampered_header_fails() {
        let mut container = encrypt(b"secret", "password", fast_params()).unwrap();
        // The nonce is authenticated as part of the AAD.
        container[36] ^= 0x01;
        assert!(matches!(
            decrypt(&container, "password").unwrap_err(),
            Error::AuthenticationFailed
        ));
    }

    #[test]
    fn truncated_container_fails() {
        let container = encrypt(b"secret", "password", fast_params()).unwrap();
        assert!(matches!(
            decrypt(&container[..container.len() - 1], "password").unwrap_err(),
            Error::MalformedVault(_)
        ));
        assert!(matches!(
            decrypt(&container[..10], "password").unwrap_err(),
            Error::MalformedVault(_)
        ));
    }

    #[test]
    fn trailing_data_fails() {
        let mut container = encrypt(b"secret", "password", fast_params()).unwrap();
        container.push(0);
        assert!(matches!(
            decrypt(&container, "password").unwrap_err(),
            Error::MalformedVault(_)
        ));
    }

    #[test]
    fn rejects_non_vault_and_legacy_files() {
        assert!(matches!(
            decrypt(b"definitely not a vault file", "pw").unwrap_err(),
            Error::NotAVault
        ));

        let mut legacy = Vec::from(*b"PMGR");
        legacy.push(1);
        legacy.extend_from_slice(&[0u8; 40]);
        assert!(matches!(
            decrypt(&legacy, "pw").unwrap_err(),
            Error::LegacyVault
        ));
    }

    #[test]
    fn rejects_out_of_range_kdf_parameters() {
        let params = KdfParams::new(1024, 1, 1);
        assert!(matches!(
            encrypt(b"x", "pw", params).unwrap_err(),
            Error::UnsupportedFormat(_)
        ));
    }
}
