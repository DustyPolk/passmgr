//! Vault file handling: loading, saving, and credential operations.

mod lock;
#[cfg(test)]
mod tests;

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use crate::crypto::{self, KdfParams};
use crate::error::{Error, Result};
use crate::grant::{Grant, GrantId};
use crate::store::{self, Credential, EntryId};

use self::lock::{acquire_write_lock, with_path, write_container};

pub use self::lock::{LOCK_SUFFIX, lock_path};

/// An open vault. Changes are kept in memory until [`Vault::save`] is called.
///
/// A vault that may be saved holds an exclusive `flock` on the sidecar
/// `<vault>.lock` until the `Vault` is dropped. That makes the whole
/// read-modify-write atomic with respect to other passmgr processes. The lock
/// is either taken before the read ([`Vault::open_for_update`],
/// [`Vault::open_for_add`]) or afterwards with [`Vault::lock_for_update`],
/// which first proves the file did not change in between. A read-only vault
/// does not take the lock: reads are safe because saves rename a complete
/// temp file into place.
pub struct Vault {
    path: PathBuf,
    credentials: Vec<Credential>,
    /// Grants live inside the encrypted payload, next to the credentials, so
    /// they are covered by the same encryption, lock and atomic write.
    grants: Vec<Grant>,
    /// `Some` when the vault may be saved. Held for the vault's lifetime.
    write_lock: Option<File>,
    /// The exact container bytes this state was decrypted from, or `None` when
    /// the file did not exist. [`Vault::lock_for_update`] compares it with the
    /// file after taking the lock, so a writer that read before locking can
    /// never save over a change it did not see. Ciphertext only, never plaintext.
    source: Option<Vec<u8>>,
}

impl Vault {
    /// Open and decrypt an existing vault.
    pub fn open(path: impl AsRef<Path>, master_password: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let container = read_container(&path)?;
        let plaintext = crypto::decrypt(&container, master_password)?;
        let payload = store::decode(&plaintext)?;
        Ok(Self {
            path,
            credentials: payload.credentials,
            grants: payload.grants,
            write_lock: None,
            source: Some(container),
        })
    }

    /// Open and decrypt an existing vault for modification.
    ///
    /// Takes the exclusive write lock **before** reading, so two concurrent
    /// writers cannot each read the same old state and overwrite one
    /// another's change. The lock is released when the returned vault is
    /// dropped.
    pub fn open_for_update(path: impl AsRef<Path>, master_password: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = acquire_write_lock(&path)?;
        let mut vault = Self::open(&path, master_password)?;
        vault.write_lock = Some(lock);
        Ok(vault)
    }

    /// Open and decrypt an existing vault with an already-derived key.
    ///
    /// Used by the unlock daemon, which holds only the 32-byte key (never the
    /// master password). The key must come from [`crypto::unlock_key`] for
    /// this vault file.
    pub fn open_with_key(path: impl AsRef<Path>, key: &[u8]) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let container = read_container(&path)?;
        let plaintext = crypto::decrypt_with_key(&container, key)?;
        let payload = store::decode(&plaintext)?;
        Ok(Self {
            path,
            credentials: payload.credentials,
            grants: payload.grants,
            write_lock: None,
            source: Some(container),
        })
    }

    /// Open and decrypt an existing vault for modification with an
    /// already-derived key, taking the write lock **before** reading.
    ///
    /// This is the key-based counterpart of [`Vault::open_for_update`], for a
    /// writer that holds the daemon's key rather than the master password:
    /// the daemon recording a use or a revocation (`src/daemon.rs`), and `pm
    /// grant create` once the human has approved. Reading before locking would
    /// let another writer slip a change in between, and the caller would then
    /// either fail with [`Error::VaultChanged`] on a request that is
    /// authorized by design (a revocation must not be flaky, TODO R.39) or
    /// spend an approval and write nothing. Taking the lock first means the
    /// state that is read is the state that is modified.
    ///
    /// The key must come from [`crypto::unlock_key`] for this vault file.
    /// [`Vault::save_with_key`] authenticates it, so a wrong key changes
    /// nothing.
    pub fn open_with_key_for_update(path: impl AsRef<Path>, key: &[u8]) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = acquire_write_lock(&path)?;
        let mut vault = Self::open_with_key(&path, key)?;
        vault.write_lock = Some(lock);
        Ok(vault)
    }

    /// Open a vault for modification, starting with an empty one if the file
    /// does not exist.
    ///
    /// Errors other than "not found" (notably authentication failures) are
    /// returned unchanged, so a misspelled master password can never cause an
    /// existing vault to be replaced.
    pub fn open_for_add(path: impl AsRef<Path>, master_password: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = acquire_write_lock(&path)?;
        let mut vault = match Self::open(&path, master_password) {
            Ok(vault) => vault,
            Err(Error::VaultNotFound(_)) => Self {
                path,
                credentials: Vec::new(),
                grants: Vec::new(),
                write_lock: None,
                source: None,
            },
            Err(err) => return Err(err),
        };
        vault.write_lock = Some(lock);
        Ok(vault)
    }

    /// An empty in-memory vault for a file that does not exist yet.
    ///
    /// This is for commands that must read, check and prompt the human before
    /// they may create anything, so that a prompt never holds the write lock.
    /// [`Vault::save`] still refuses until [`Vault::lock_for_update`] has
    /// confirmed that the file is *still* absent, so a vault created by a
    /// concurrent process is never silently replaced.
    pub fn empty(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            credentials: Vec::new(),
            grants: Vec::new(),
            write_lock: None,
            source: None,
        }
    }

    /// Take the write lock and confirm the vault on disk is unchanged.
    ///
    /// Use this after a lock-free [`Vault::open`] when the read-modify-write
    /// has to prompt the human in between: a prompt can last minutes, and a
    /// writer that holds the lock that long blocks unrelated commands. Anything
    /// that does *not* have to prompt first should use one of the
    /// `open*_for_update` constructors instead, so it never reads a state it
    /// cannot write back (TODO R.39). The
    /// lock is the same exclusive `flock` as [`Vault::open_for_update`] uses,
    /// and the container is compared byte for byte with the one this vault was
    /// decrypted from, so a change made while the human was typing is reported
    /// as [`Error::VaultChanged`] instead of being overwritten. The state that
    /// is then modified is exactly the state that was read.
    pub fn lock_for_update(&mut self) -> Result<()> {
        if self.write_lock.is_some() {
            return Ok(());
        }
        let lock = acquire_write_lock(&self.path)?;
        let current = match read_container(&self.path) {
            Ok(container) => Some(container),
            Err(Error::VaultNotFound(_)) => None,
            Err(err) => return Err(err),
        };
        if current != self.source {
            return Err(Error::VaultChanged(self.path.clone()));
        }
        self.write_lock = Some(lock);
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Encrypt and atomically replace the vault file.
    ///
    /// Only a vault opened for update (which holds the write lock) may be
    /// saved. This keeps "read, change, write" under one lock even if a
    /// future caller forgets to use [`Vault::open_for_update`].
    pub fn save(&self, master_password: &str) -> Result<()> {
        if self.write_lock.is_none() {
            return Err(Error::ReadOnlyVault(self.path.clone()));
        }
        let plaintext = store::encode(&self.credentials, &self.grants)?;
        let container = crypto::encrypt(&plaintext, master_password, KdfParams::default())?;
        write_container(&self.path, &container)
    }

    /// Encrypt and atomically replace the vault file with an already-derived
    /// key, keeping the container's salt and KDF parameters.
    ///
    /// This is for a writer that holds the vault key but not the master
    /// password — the CLI writing a grant while `pmd` is unlocked. A fresh
    /// salt (as [`Vault::save`] takes) would invalidate the daemon's key on
    /// its next request, so the source container's header is reused and only
    /// the nonce and ciphertext change. The key must open the container this
    /// vault was read from; [`crypto::encrypt_with_key`] authenticates it
    /// before writing, so a wrong key changes nothing.
    ///
    /// Like [`Vault::save`], this requires the write lock. A vault with no
    /// source container (a brand-new file) has no salt or KDF parameters to
    /// reuse and is refused.
    pub fn save_with_key(&self, key: &[u8]) -> Result<()> {
        if self.write_lock.is_none() {
            return Err(Error::ReadOnlyVault(self.path.clone()));
        }
        let template = self.source.as_deref().ok_or_else(|| {
            Error::Crypto(
                "cannot save with a key: this vault has no container to take its KDF \
                 parameters from"
                    .into(),
            )
        })?;
        let plaintext = store::encode(&self.credentials, &self.grants)?;
        let container = crypto::encrypt_with_key(&plaintext, key, template)?;
        write_container(&self.path, &container)
    }

    pub fn add(&mut self, credential: Credential) -> Result<()> {
        if self.get(credential.service()).is_some() {
            return Err(Error::DuplicateService(credential.service().to_owned()));
        }
        self.credentials.push(credential);
        Ok(())
    }

    pub fn get(&self, service: &str) -> Option<&Credential> {
        self.credentials
            .iter()
            .find(|credential| credential.service() == service)
    }

    pub fn get_mut(&mut self, service: &str) -> Option<&mut Credential> {
        self.credentials
            .iter_mut()
            .find(|credential| credential.service() == service)
    }

    /// Look a credential up by its stable id. Unlike service names, a
    /// reference is unambiguous and survives renames.
    pub fn get_by_ref(&self, id: EntryId) -> Option<&Credential> {
        self.credentials
            .iter()
            .find(|credential| credential.id() == id)
    }

    /// Give an existing credential a new service name. The new name must not
    /// collide with another credential.
    pub fn rename(&mut self, service: &str, new_service: &str) -> Result<()> {
        if service == new_service {
            return self
                .get(service)
                .map(|_| ())
                .ok_or_else(|| Error::ServiceNotFound(service.to_owned()));
        }
        if self.get(new_service).is_some() {
            return Err(Error::DuplicateService(new_service.to_owned()));
        }
        let credential = self
            .get_mut(service)
            .ok_or_else(|| Error::ServiceNotFound(service.to_owned()))?;
        credential.set_service(new_service.to_owned())
    }

    pub fn delete(&mut self, service: &str) -> Result<Credential> {
        let index = self
            .credentials
            .iter()
            .position(|credential| credential.service() == service)
            .ok_or_else(|| Error::ServiceNotFound(service.to_owned()))?;
        Ok(self.credentials.remove(index))
    }

    pub fn list(&self) -> &[Credential] {
        &self.credentials
    }

    /// Credentials carrying every tag in `tags`, in vault order. An empty
    /// filter matches everything.
    pub fn list_tagged<'a>(&'a self, tags: &'a [String]) -> impl Iterator<Item = &'a Credential> {
        self.credentials
            .iter()
            .filter(move |credential| credential.has_all_tags(tags))
    }

    /// Every grant in the vault, in vault order.
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    pub fn grant(&self, id: GrantId) -> Option<&Grant> {
        self.grants.iter().find(|grant| grant.id() == id)
    }

    pub fn grant_mut(&mut self, id: GrantId) -> Option<&mut Grant> {
        self.grants.iter_mut().find(|grant| grant.id() == id)
    }

    /// Store a new grant. Grant ids are the agent-facing identity, so a
    /// duplicate would make revocation ambiguous and is refused, just like a
    /// duplicate service name.
    pub fn add_grant(&mut self, grant: Grant) -> Result<()> {
        if self.grant(grant.id()).is_some() {
            return Err(Error::InvalidInput(format!(
                "duplicate grant id {}",
                grant.id()
            )));
        }
        self.grants.push(grant);
        Ok(())
    }

    /// Check that adding `grant` and saving this vault would be accepted.
    ///
    /// [`Vault::save_with_key`] refuses a payload that holds more than
    /// [`crate::grant::MAX_GRANTS`] grants or more than
    /// [`crypto::MAX_PLAINTEXT_BYTES`] bytes, but `pm grant create` spends the
    /// human's one-shot approval *before* it writes. The CLI asks this question
    /// first, with the vault it opened using the same derived key, so a vault
    /// that is already full is refused before the proof is spent (TODO R.22).
    /// The check runs the writer's own [`store::encode`] over the candidate
    /// grant list, so the pre-check and the write cannot drift apart.
    ///
    /// Nothing is written and the vault is not modified. A concurrent writer
    /// can still fill the vault between this check and the save; the write
    /// lock then reports [`Error::VaultChanged`] (or the encode refuses), which
    /// would take two grant creations racing by hand.
    pub fn check_grant_writable(&self, grant: &Grant) -> Result<()> {
        let mut grants = self.grants.clone();
        grants.push(grant.clone());
        store::encode(&self.credentials, &grants).map(|_| ())
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    pub fn len(&self) -> usize {
        self.credentials.len()
    }
}

/// Read and validate the encrypted container at `path`.
///
/// `unlock` needs the bytes (not the decrypted vault) to derive the key it
/// hands to the daemon; every check here is format-independent.
pub fn read_container(path: &Path) -> Result<Vec<u8>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(Error::VaultNotFound(path.to_path_buf()));
        }
        Err(err) => return Err(with_path(path, err)),
    };
    if !metadata.is_file() {
        return Err(Error::MalformedVault(format!(
            "'{}' is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > crypto::MAX_VAULT_BYTES as u64 {
        return Err(Error::MalformedVault(format!(
            "'{}' is too large",
            path.display()
        )));
    }
    let data = fs::read(path).map_err(|err| with_path(path, err))?;
    if data.len() > crypto::MAX_VAULT_BYTES {
        return Err(Error::MalformedVault(format!(
            "'{}' is too large",
            path.display()
        )));
    }
    Ok(data)
}

/// Return the file mode when the vault is readable by group or others.
#[cfg(unix)]
pub fn insecure_permissions(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path).ok()?.permissions().mode() & 0o777;
    (mode & 0o077 != 0).then_some(mode)
}

#[cfg(not(unix))]
pub fn insecure_permissions(_path: &Path) -> Option<u32> {
    None
}
