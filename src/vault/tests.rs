//! Unit tests for the vault lifecycle, the write lock and grant persistence.
//!
//! Moved out of `src/vault.rs` by TODO R.20b to keep the module under the
//! line limit; the tests are unchanged apart from the imports below.

use super::*;
use crate::vault::lock::{acquire_write_lock_with_timeout, lock_path};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use zeroize::Zeroizing;

use crate::grant::{Capabilities, Grant, GrantSpec, MAX_GRANTS, Scope, TokenHash};

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
fn saving_with_the_key_keeps_the_key_and_the_password_working() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.dat");
    let master = "test master password";

    let credential = credential("example.com", "user", "secret");
    let entry = credential.id();
    {
        let mut vault = Vault::open_for_add(&path, master).unwrap();
        vault.add(credential).unwrap();
        vault.save(master).unwrap();
    }

    let before = fs::read(&path).unwrap();
    let key = crypto::unlock_key(&before, master).unwrap();

    // A writer that holds the key (never the password) rewrites the vault.
    let mut vault = Vault::open_with_key(&path, key.as_slice()).unwrap();
    vault.lock_for_update().unwrap();
    let grant = test_grant(entry, "deploy", 1_700_000_000);
    let grant_id = grant.id();
    vault.add_grant(grant).unwrap();
    vault.save_with_key(key.as_slice()).unwrap();
    drop(vault);

    let after = fs::read(&path).unwrap();
    assert_eq!(&after[8..20], &before[8..20], "KDF params are reused");
    assert_eq!(&after[20..36], &before[20..36], "the salt is reused");
    assert_ne!(&after[36..48], &before[36..48], "a fresh nonce is used");

    // The daemon's key still opens the rewritten vault.
    let daemon_view = Vault::open_with_key(&path, key.as_slice()).unwrap();
    assert_eq!(daemon_view.get("example.com").unwrap().password(), "secret");
    assert!(daemon_view.grant(grant_id).is_some());

    // And so does the master password.
    let human_view = Vault::open(&path, master).unwrap();
    assert_eq!(human_view.get("example.com").unwrap().password(), "secret");
    assert!(human_view.grant(grant_id).is_some());
}

#[test]
fn saving_with_the_key_refuses_a_read_only_or_containerless_vault() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.dat");
    let master = "master";
    {
        let mut vault = Vault::open_for_add(&path, master).unwrap();
        vault.add(credential("one", "u", "p")).unwrap();
        vault.save(master).unwrap();
    }
    let container = fs::read(&path).unwrap();
    let key = crypto::unlock_key(&container, master).unwrap();

    let read_only = Vault::open(&path, master).unwrap();
    assert!(matches!(
        read_only.save_with_key(key.as_slice()),
        Err(Error::ReadOnlyVault(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), container, "nothing was written");

    // A brand-new file has no header to reuse, even with the write lock.
    let fresh_path = directory.path().join("fresh.dat");
    let fresh = Vault::open_for_add(&fresh_path, master).unwrap();
    assert!(matches!(
        fresh.save_with_key(key.as_slice()),
        Err(Error::Crypto(_))
    ));
    assert!(!fresh_path.exists(), "nothing was written");
}

#[test]
fn saving_with_the_wrong_key_writes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.dat");
    let master = "master";
    {
        let mut vault = Vault::open_for_add(&path, master).unwrap();
        vault.add(credential("one", "u", "p")).unwrap();
        vault.save(master).unwrap();
    }

    let before = fs::read(&path).unwrap();
    let mut vault = Vault::open_for_update(&path, master).unwrap();
    vault.add(credential("two", "u", "p")).unwrap();
    assert!(matches!(
        vault.save_with_key(&[0u8; crypto::KEY_LEN]),
        Err(Error::AuthenticationFailed)
    ));
    drop(vault);

    assert_eq!(fs::read(&path).unwrap(), before, "nothing was written");
    assert!(Vault::open(&path, master).unwrap().get("two").is_none());
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

/// TODO R.22: `save_with_key` refuses a vault holding more than `MAX_GRANTS`
/// grants, but `pm grant create` spends the human's approval before it writes.
/// The pre-check must report the writer's own error and touch nothing.
#[test]
fn check_grant_writable_refuses_a_full_vault_without_writing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.dat");
    let mut vault = Vault::empty(&path);
    let entry = EntryId::generate().unwrap();
    for index in 0..MAX_GRANTS {
        vault
            .add_grant(test_grant(entry, &format!("g{index}"), 1_700_000_000))
            .unwrap();
    }

    let error = vault
        .check_grant_writable(&test_grant(entry, "one too many", 1_700_000_000))
        .expect_err("a vault at MAX_GRANTS cannot take another grant");
    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("too many grants")),
        "the pre-check must run the writer's own rule: {error}"
    );
    assert_eq!(
        vault.grants().len(),
        MAX_GRANTS,
        "must not modify the vault"
    );
    assert!(!path.exists(), "a capacity check must not create the vault");
}

#[test]
fn check_grant_writable_accepts_a_grant_that_still_fits() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("vault.dat");
    let mut vault = Vault::empty(&vault_path);
    let entry = EntryId::generate().unwrap();
    for index in 0..MAX_GRANTS - 1 {
        vault
            .add_grant(test_grant(entry, &format!("g{index}"), 1_700_000_000))
            .unwrap();
    }

    // One slot left: the next grant fits, so the CLI may proceed to the proof.
    assert!(
        vault
            .check_grant_writable(&test_grant(entry, "last slot", 1_700_000_000))
            .is_ok()
    );
    assert_eq!(vault.grants().len(), MAX_GRANTS - 1);

    // The same check runs the writer's duplicate-id rule too, so a replayed
    // grant is refused here instead of after the approval is spent.
    let duplicate = vault.grants()[0].clone();
    let error = vault
        .check_grant_writable(&duplicate)
        .expect_err("a duplicate grant id must be refused before the write");
    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("duplicate grant id")),
        "the pre-check must report a duplicate id: {error}"
    );
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
