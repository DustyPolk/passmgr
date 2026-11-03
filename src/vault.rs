//! Vault file handling: loading, saving, and credential operations.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::crypto::{self, KdfParams};
use crate::error::{Error, Result};
use crate::grant::{Grant, GrantId};
use crate::store::{self, Credential, EntryId};

/// Suffix of the sidecar file whose `flock` serializes vault writers.
pub const LOCK_SUFFIX: &str = ".lock";

/// How long a writer waits for another writer before giving up.
///
/// Writers are short-lived CLI commands, so a healthy lock is released in
/// milliseconds. A longer wait would only hide a stuck process, and an
/// unattended caller must not hang forever.
const WRITE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_LOCK_RETRY: Duration = Duration::from_millis(10);

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

/// The sidecar lock path for `vault`: `<vault>.lock` in the same directory.
///
/// The lock file is never unlinked: removing it while it is held would let a
/// second writer lock a fresh inode and break mutual exclusion.
pub fn lock_path(vault: &Path) -> PathBuf {
    let mut path = vault.as_os_str().to_os_string();
    path.push(LOCK_SUFFIX);
    PathBuf::from(path)
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
    /// writer that holds the lock that long blocks unrelated commands. The
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

/// Take the exclusive write lock for `vault`, creating the sidecar 0600 file
/// if needed.
fn acquire_write_lock(vault: &Path) -> Result<File> {
    acquire_write_lock_with_timeout(vault, WRITE_LOCK_TIMEOUT)
}

#[cfg(unix)]
fn acquire_write_lock_with_timeout(vault: &Path, timeout: Duration) -> Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = lock_path(vault);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        // Never follow a symlink planted at the lock path, and never leak the
        // descriptor into a child process.
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|err| with_path(&path, err))?;

    let metadata = file.metadata().map_err(|err| with_path(&path, err))?;
    if !metadata.is_file() {
        return Err(Error::MalformedVault(format!(
            "lock '{}' is not a regular file",
            path.display()
        )));
    }
    // An old lock file could carry a wider mode; narrow it before use.
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|err| with_path(&path, err))?;

    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `as_raw_fd` returns a valid descriptor owned by `file`,
        // which outlives each call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(file);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::WouldBlock {
            return Err(with_path(&path, err));
        }
        if Instant::now() >= deadline {
            return Err(Error::VaultBusy(vault.to_path_buf()));
        }
        thread::sleep(WRITE_LOCK_RETRY);
    }
}

#[cfg(not(unix))]
fn acquire_write_lock_with_timeout(vault: &Path, _timeout: Duration) -> Result<File> {
    let _ = vault;
    Err(Error::UnsupportedFormat(
        "vault write locking requires a Unix system".to_owned(),
    ))
}

fn write_container(path: &Path, container: &[u8]) -> Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };

    let mut temp = tempfile::Builder::new()
        .prefix(".passmgr-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|err| with_path(path, err))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| with_path(path, err))?;
    }

    temp.write_all(container)
        .map_err(|err| with_path(path, err))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| with_path(path, err))?;
    temp.persist(path)
        .map_err(|err| with_path(path, err.error))?;

    // Best effort: make the rename durable across a crash. Some filesystems do
    // not support fsync on directories, so failure is ignored.
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn with_path(path: &Path, err: io::Error) -> Error {
    Error::Io(io::Error::new(
        err.kind(),
        format!("{}: {err}", path.display()),
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    use crate::grant::{Capabilities, Grant, GrantSpec, Scope, TokenHash};

    fn credential(service: &str, username: &str, password: &str) -> Credential {
        Credential::new(
            service.to_owned(),
            username.to_owned(),
            Zeroizing::new(password.to_owned()),
        )
        .unwrap()
    }

    #[test]
    fn save_open_and_modify_roundtrip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "test master password";

        let mut vault = Vault::open_for_add(&path, master).unwrap();
        assert!(vault.is_empty());
        vault
            .add(credential("example.com", "user", "secret"))
            .unwrap();
        vault.add(credential("other.example", "", "pin")).unwrap();
        assert!(matches!(
            vault.add(credential("example.com", "dup", "dup")),
            Err(Error::DuplicateService(_))
        ));
        vault.save(master).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            assert_eq!(insecure_permissions(&path), None);
        }

        let loaded = Vault::open(&path, master).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get("example.com").unwrap().username(), "user");
        assert_eq!(loaded.get("example.com").unwrap().password(), "secret");
        assert_eq!(loaded.get("other.example").unwrap().username(), "");
        assert!(loaded.get("missing").is_none());

        assert!(matches!(
            Vault::open(&path, "wrong password"),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn opens_with_a_derived_key_instead_of_the_password() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "test master password";

        let mut vault = Vault::open_for_add(&path, master).unwrap();
        vault
            .add(credential("example.com", "user", "secret"))
            .unwrap();
        vault.save(master).unwrap();

        let container = fs::read(&path).unwrap();
        let key = crypto::unlock_key(&container, master).unwrap();
        let loaded = Vault::open_with_key(&path, key.as_slice()).unwrap();
        assert_eq!(loaded.get("example.com").unwrap().password(), "secret");

        // A key that was not derived for this vault does not open it.
        assert!(matches!(
            Vault::open_with_key(&path, &[0u8; crypto::KEY_LEN]),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn entry_ids_are_stable_across_vault_saves() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        let mut vault = Vault::open_for_add(&path, master).unwrap();
        vault
            .add(credential("one.example", "alice", "secret-one"))
            .unwrap();
        vault
            .add(credential("two.example", "bob", "secret-two"))
            .unwrap();
        let ids: Vec<_> = vault
            .list()
            .iter()
            .map(|credential| credential.id())
            .collect();
        assert_ne!(ids[0], ids[1]);
        vault.save(master).unwrap();
        // Shadowed bindings are dropped at the end of the scope, not at the
        // shadowing line, so release the write lock explicitly here.
        drop(vault);

        // Opened for update because this test renames and saves below.
        let loaded = Vault::open_for_update(&path, master).unwrap();
        let loaded_ids: Vec<_> = loaded
            .list()
            .iter()
            .map(|credential| credential.id())
            .collect();
        assert_eq!(loaded_ids, ids, "ids survive a save and reopen");

        // Renaming changes the service name, never the id: agent references
        // must stay valid across edits.
        let mut loaded = loaded;
        loaded.rename("one.example", "renamed.example").unwrap();
        loaded.save(master).unwrap();

        let reopened = Vault::open(&path, master).unwrap();
        let credential = reopened.get("renamed.example").unwrap();
        assert_eq!(credential.id(), ids[0]);
        assert_eq!(credential.reference(), credential.id().to_ref());
        assert!(credential.reference().starts_with("pm://"));
    }

    #[test]
    fn deleting_credential_and_saving() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        let mut vault = Vault::open_for_add(&path, master).unwrap();
        vault.add(credential("keep", "u", "p")).unwrap();
        vault.add(credential("remove", "u", "p")).unwrap();
        let removed = vault.delete("remove").unwrap();
        assert_eq!(removed.service(), "remove");
        assert!(matches!(
            vault.delete("remove"),
            Err(Error::ServiceNotFound(_))
        ));
        vault.save(master).unwrap();

        let loaded = Vault::open(&path, master).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.get("keep").is_some());
    }

    #[test]
    fn renaming_and_editing_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        let mut vault = Vault::open_for_add(&path, master).unwrap();
        vault
            .add(credential("first", "alice", "old-secret"))
            .unwrap();
        vault.add(credential("second", "bob", "other")).unwrap();

        vault.rename("first", "renamed").unwrap();
        assert!(vault.get("first").is_none());
        assert_eq!(vault.get("renamed").unwrap().username(), "alice");

        assert!(matches!(
            vault.rename("renamed", "second"),
            Err(Error::DuplicateService(_))
        ));
        assert!(matches!(
            vault.rename("missing", "anything"),
            Err(Error::ServiceNotFound(_))
        ));
        assert!(matches!(
            vault.rename("missing", "missing"),
            Err(Error::ServiceNotFound(_))
        ));
        vault.rename("renamed", "renamed").unwrap();

        let credential = vault.get_mut("renamed").unwrap();
        credential.set_username("carol".to_owned()).unwrap();
        credential
            .set_password(Zeroizing::new("new-secret".to_owned()))
            .unwrap();
        vault.save(master).unwrap();

        let loaded = Vault::open(&path, master).unwrap();
        let credential = loaded.get("renamed").unwrap();
        assert_eq!(credential.username(), "carol");
        assert_eq!(credential.password(), "new-secret");
    }

    #[test]
    fn timestamps_survive_saves_and_rotation_keeps_created() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        let mut vault = Vault::open_for_add(&path, master).unwrap();
        vault
            .add(credential("timed.example", "alice", "first"))
            .unwrap();
        let created = vault.get("timed.example").unwrap().created_unix();
        let rotated = vault.get("timed.example").unwrap().last_rotated_unix();
        assert!(created > 0);
        assert_eq!(rotated, created);
        vault.save(master).unwrap();
        drop(vault);

        let mut vault = Vault::open_for_update(&path, master).unwrap();
        let credential = vault.get("timed.example").unwrap();
        assert_eq!(credential.created_unix(), created);
        assert_eq!(credential.last_rotated_unix(), rotated);

        vault
            .get_mut("timed.example")
            .unwrap()
            .set_password(Zeroizing::new("second".to_owned()))
            .unwrap();
        vault.save(master).unwrap();

        let reopened = Vault::open(&path, master).unwrap();
        let credential = reopened.get("timed.example").unwrap();
        assert_eq!(credential.password(), "second");
        assert_eq!(
            credential.created_unix(),
            created,
            "rotation must never change the creation time"
        );
        assert!(
            credential.last_rotated_unix() >= rotated,
            "rotation must record a new timestamp"
        );
    }

    #[test]
    fn lookup_by_reference_is_stable_across_renames() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "test master password";

        let mut vault = Vault::open_for_add(&path, master).unwrap();
        vault
            .add(credential("one.example", "alice", "first"))
            .unwrap();
        vault
            .add(credential("two.example", "bob", "second"))
            .unwrap();
        let id = vault.get("one.example").unwrap().id();

        assert_eq!(
            vault.get_by_ref(id).map(Credential::service),
            Some("one.example")
        );
        assert!(vault.get_by_ref(EntryId::generate().unwrap()).is_none());

        vault.rename("one.example", "renamed.example").unwrap();
        assert_eq!(
            vault.get_by_ref(id).map(Credential::service),
            Some("renamed.example")
        );
    }

    #[test]
    fn tags_persist_and_filter() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        let mut vault = Vault::open_for_add(&path, master).unwrap();
        vault
            .add(
                credential("work.example", "alice", "secret")
                    .with_tags(vec!["prod".to_owned(), "work".to_owned()])
                    .expect("valid tags"),
            )
            .unwrap();
        vault
            .add(
                credential("home.example", "bob", "other")
                    .with_tags(vec!["home".to_owned()])
                    .expect("valid tags"),
            )
            .unwrap();
        vault
            .add(credential("plain.example", "carol", "third"))
            .unwrap();
        vault.save(master).unwrap();
        drop(vault);

        let reopened = Vault::open_for_update(&path, master).unwrap();
        let prod_filter = ["prod".to_owned()];
        let prod: Vec<_> = reopened
            .list_tagged(&prod_filter)
            .map(Credential::service)
            .collect();
        assert_eq!(prod, ["work.example"]);
        let both_filter = ["prod".to_owned(), "home".to_owned()];
        let none: Vec<_> = reopened
            .list_tagged(&both_filter)
            .map(Credential::service)
            .collect();
        assert!(none.is_empty(), "filters are ANDed");
        assert_eq!(reopened.list_tagged(&[]).count(), 3);

        // Tags are editable and survive another save; the password is not
        // touched by set_tags.
        let mut reopened = reopened;
        let credential = reopened.get_mut("plain.example").unwrap();
        let before = credential.password().to_owned();
        credential
            .set_tags(vec!["prod".to_owned(), "late".to_owned()])
            .unwrap();
        assert_eq!(credential.password(), before);
        reopened.save(master).unwrap();

        let reopened = Vault::open(&path, master).unwrap();
        assert_eq!(
            reopened.get("plain.example").unwrap().tags(),
            ["late", "prod"]
        );
    }

    #[test]
    fn write_lock_is_exclusive_private_and_released_on_drop() {
        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.dat");
        let master = "master";

        let first = Vault::open_for_add(&vault_path, master).unwrap();
        let lock_path = lock_path(&vault_path);
        assert_eq!(lock_path, directory.path().join("vault.dat.lock"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the lock file must not be readable by others");
        }

        // A second writer cannot take the lock while the first is alive. The
        // short timeout keeps the test fast; production waits 30 s.
        let started = Instant::now();
        assert!(matches!(
            acquire_write_lock_with_timeout(&vault_path, Duration::from_millis(100)),
            Err(Error::VaultBusy(_))
        ));
        assert!(started.elapsed() >= Duration::from_millis(100));

        // Dropping the first vault releases the kernel lock.
        drop(first);
        let second = Vault::open_for_add(&vault_path, master);
        assert!(second.is_ok(), "the lock must be released on drop");
    }

    #[test]
    fn lock_for_update_detects_a_writer_that_arrived_while_the_human_typed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        {
            let mut seed = Vault::open_for_add(&path, master).unwrap();
            seed.add(credential("seed", "u", "p")).unwrap();
            seed.save(master).unwrap();
        }

        // Stands in for `edit`: it reads, then prompts for a while.
        let mut stale = Vault::open(&path, master).unwrap();

        {
            let mut other = Vault::open_for_update(&path, master).unwrap();
            other.add(credential("other", "u", "p")).unwrap();
            other.save(master).unwrap();
        }

        assert!(matches!(
            stale.lock_for_update(),
            Err(Error::VaultChanged(_))
        ));
        assert!(
            matches!(stale.save(master), Err(Error::ReadOnlyVault(_))),
            "a vault whose lock was refused must stay unsaveable"
        );

        let loaded = Vault::open(&path, master).unwrap();
        let services: Vec<_> = loaded.list().iter().map(Credential::service).collect();
        assert_eq!(
            services,
            ["seed", "other"],
            "the concurrent change must survive a refused save"
        );
    }

    #[test]
    fn lock_for_update_takes_the_lock_only_after_the_check_and_blocks_writers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        {
            let mut seed = Vault::open_for_add(&path, master).unwrap();
            seed.add(credential("seed", "u", "p")).unwrap();
            seed.save(master).unwrap();
        }

        let mut vault = Vault::open(&path, master).unwrap();
        vault.lock_for_update().unwrap();
        assert!(
            matches!(
                acquire_write_lock_with_timeout(&path, Duration::from_millis(100)),
                Err(Error::VaultBusy(_))
            ),
            "a vault locked after a lock-free read must exclude other writers"
        );
        // Locking twice is a no-op, not an error.
        vault.lock_for_update().unwrap();
        vault.add(credential("second", "u", "p")).unwrap();
        vault.save(master).unwrap();

        assert_eq!(Vault::open(&path, master).unwrap().len(), 2);
    }

    #[test]
    fn an_empty_vault_cannot_replace_a_file_that_appeared_meanwhile() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        let mut empty = Vault::empty(&path);
        assert!(matches!(empty.save(master), Err(Error::ReadOnlyVault(_))));

        {
            let mut other = Vault::open_for_add(&path, master).unwrap();
            other.add(credential("seed", "u", "p")).unwrap();
            other.save(master).unwrap();
        }

        assert!(matches!(
            empty.lock_for_update(),
            Err(Error::VaultChanged(_))
        ));
        assert!(matches!(empty.save(master), Err(Error::ReadOnlyVault(_))));
        assert!(
            Vault::open(&path, master).unwrap().get("seed").is_some(),
            "the vault that appeared must not be replaced"
        );
    }

    #[test]
    fn an_empty_vault_saves_only_after_the_lock_confirms_it_is_absent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        let mut vault = Vault::empty(&path);
        vault.add(credential("first", "u", "p")).unwrap();
        assert!(
            !lock_path(&path).exists(),
            "an unlocked empty vault must not create the lock file"
        );
        vault.lock_for_update().unwrap();
        vault.save(master).unwrap();

        assert_eq!(
            Vault::open(&path, master)
                .unwrap()
                .get("first")
                .unwrap()
                .password(),
            "p"
        );
    }

    #[test]
    fn concurrent_writers_serialize_and_both_changes_land() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        {
            let mut seed = Vault::open_for_add(&path, master).unwrap();
            seed.add(credential("seed", "u", "p")).unwrap();
            seed.save(master).unwrap();
        }

        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let first_path = path.clone();
        let first = thread::spawn(move || {
            let mut vault = Vault::open_for_update(&first_path, master).unwrap();
            vault.add(credential("alpha", "u", "p")).unwrap();
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            vault.save(master).unwrap();
        });
        locked_rx.recv_timeout(Duration::from_secs(10)).unwrap();

        let (done_tx, done_rx) = mpsc::channel();
        let second_path = path.clone();
        let second = thread::spawn(move || {
            let mut vault = Vault::open_for_update(&second_path, master).unwrap();
            vault.add(credential("beta", "u", "p")).unwrap();
            vault.save(master).unwrap();
            done_tx.send(()).unwrap();
        });

        // While the first writer holds the lock, the second must not get as
        // far as reading and saving. Without the lock it would overwrite the
        // first writer's change (the lost update this lock prevents).
        assert!(
            done_rx.recv_timeout(Duration::from_secs(2)).is_err(),
            "a second writer completed while the first held the write lock"
        );

        release_tx.send(()).unwrap();
        first.join().unwrap();
        done_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        second.join().unwrap();

        let vault = Vault::open(&path, master).unwrap();
        let services: Vec<_> = vault.list().iter().map(Credential::service).collect();
        assert_eq!(services, ["seed", "alpha", "beta"]);
    }

    #[test]
    fn readers_never_see_a_torn_vault_while_a_writer_saves() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        {
            let mut seed = Vault::open_for_add(&path, master).unwrap();
            seed.add(credential("seed", "u", "p")).unwrap();
            seed.save(master).unwrap();
        }

        let (finished_tx, finished_rx) = mpsc::channel();
        let writer_path = path.clone();
        let writer = thread::spawn(move || {
            for index in 0..3 {
                let mut vault = Vault::open_for_update(&writer_path, master).unwrap();
                vault
                    .add(credential(&format!("writer-{index}"), "u", "p"))
                    .unwrap();
                vault.save(master).unwrap();
            }
            finished_tx.send(()).unwrap();
        });

        loop {
            let read = Vault::open(&path, master);
            assert!(read.is_ok(), "a reader saw a torn vault: {:?}", read.err());
            match finished_rx.try_recv() {
                Ok(()) => break,
                Err(mpsc::TryRecvError::Empty) => continue,
                Err(mpsc::TryRecvError::Disconnected) => panic!("writer died"),
            }
        }
        writer.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn write_lock_refuses_a_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.dat");
        let target = directory.path().join("target");
        fs::write(&target, b"do not touch").unwrap();
        symlink(&target, lock_path(&vault_path)).unwrap();

        assert!(matches!(
            Vault::open_for_add(&vault_path, "master"),
            Err(Error::Io(_))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"do not touch");
    }

    #[test]
    fn read_only_vault_refuses_to_save() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "master";

        {
            let mut vault = Vault::open_for_add(&path, master).unwrap();
            vault.add(credential("one", "u", "p")).unwrap();
            vault.save(master).unwrap();
        }

        let vault = Vault::open(&path, master).unwrap();
        assert!(matches!(vault.save(master), Err(Error::ReadOnlyVault(_))));
        assert_eq!(Vault::open(&path, master).unwrap().len(), 1);
    }

    #[test]
    fn missing_and_invalid_files() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.dat");
        assert!(matches!(
            Vault::open(&missing, "pw"),
            Err(Error::VaultNotFound(_))
        ));

        let invalid = directory.path().join("invalid.dat");
        fs::write(&invalid, b"not a vault").unwrap();
        assert!(matches!(Vault::open(&invalid, "pw"), Err(Error::NotAVault)));
    }

    #[cfg(unix)]
    #[test]
    fn reports_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("loose.dat");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(insecure_permissions(&path), Some(0o644));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(insecure_permissions(&path), None);
    }

    fn test_grant(entry: EntryId, label: &str, now: u64) -> Grant {
        Grant::create(
            GrantSpec {
                label: label.to_owned(),
                scope: Scope::new(vec![entry], Vec::new(), None).unwrap(),
                commands: vec![PathBuf::from("/usr/bin/env")],
                capabilities: Capabilities::LIST.union(Capabilities::RUN),
                expires_at: now + 3_600,
                max_uses: Some(2),
            },
            TokenHash::of(b"canary-vault-grant-token"),
            now,
        )
        .unwrap()
    }

    #[test]
    fn refuses_a_duplicate_grant_id() {
        let directory = tempfile::tempdir().unwrap();
        let mut vault = Vault::empty(directory.path().join("vault.dat"));
        assert!(vault.grants().is_empty());

        let grant = test_grant(EntryId::generate().unwrap(), "duplicate", 1_700_000_000);
        let copy = grant.clone();
        vault.add_grant(grant).unwrap();
        assert!(matches!(
            vault.add_grant(copy),
            Err(Error::InvalidInput(message)) if message.contains("duplicate grant id")
        ));
        assert_eq!(vault.grants().len(), 1);
    }

    #[test]
    fn grants_are_saved_and_reloaded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.dat");
        let master = "test master password";

        let mut vault = Vault::open_for_add(&path, master).unwrap();
        let credential = credential("example.com", "user", "secret");
        let entry = credential.id();
        vault.add(credential).unwrap();
        let mut grant = test_grant(entry, "deploy", 1_700_000_000);
        grant.mark_used(1_700_000_100).unwrap();
        let id = grant.id();
        let copy = grant.clone();
        vault.add_grant(grant).unwrap();
        assert!(vault.add_grant(copy).is_err());
        vault.save(master).unwrap();
        drop(vault);

        let mut vault = Vault::open_for_update(&path, master).unwrap();
        let loaded = vault.grant(id).expect("saved grant");
        assert_eq!(loaded.label(), "deploy");
        assert_eq!(loaded.uses(), 1);
        assert_eq!(loaded.last_used_unix(), Some(1_700_000_100));
        assert_eq!(loaded.max_uses(), Some(2));
        assert_eq!(loaded.scope().refs(), [entry]);
        assert!(loaded.matches_token(&TokenHash::of(b"canary-vault-grant-token")));
        vault.grant_mut(id).unwrap().revoke(1_700_000_200).unwrap();
        vault.save(master).unwrap();
        drop(vault);

        let vault = Vault::open(&path, master).unwrap();
        assert_eq!(vault.grants().len(), 1);
        assert!(vault.grant(id).unwrap().is_revoked());
        assert_eq!(vault.len(), 1);
        assert_eq!(vault.get("example.com").unwrap().password(), "secret");
    }
}
