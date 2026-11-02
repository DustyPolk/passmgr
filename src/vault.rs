//! Vault file handling: loading, saving, and credential operations.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{self, KdfParams};
use crate::error::{Error, Result};
use crate::store::{self, Credential};

/// An open vault. Changes are kept in memory until [`Vault::save`] is called.
pub struct Vault {
    path: PathBuf,
    credentials: Vec<Credential>,
}

impl Vault {
    /// Open and decrypt an existing vault.
    pub fn open(path: impl AsRef<Path>, master_password: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let container = read_container(&path)?;
        let plaintext = crypto::decrypt(&container, master_password)?;
        let credentials = store::decode(&plaintext)?;
        Ok(Self { path, credentials })
    }

    /// Open a vault, starting with an empty one if the file does not exist.
    ///
    /// Errors other than "not found" (notably authentication failures) are
    /// returned unchanged, so a misspelled master password can never cause an
    /// existing vault to be replaced.
    pub fn open_for_add(path: impl AsRef<Path>, master_password: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        match Self::open(&path, master_password) {
            Ok(vault) => Ok(vault),
            Err(Error::VaultNotFound(_)) => Ok(Self {
                path,
                credentials: Vec::new(),
            }),
            Err(err) => Err(err),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Encrypt and atomically replace the vault file.
    pub fn save(&self, master_password: &str) -> Result<()> {
        let plaintext = store::encode(&self.credentials)?;
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

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    pub fn len(&self) -> usize {
        self.credentials.len()
    }
}

fn read_container(path: &Path) -> Result<Vec<u8>> {
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
    use zeroize::Zeroizing;

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

        let loaded = Vault::open(&path, master).unwrap();
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
}
