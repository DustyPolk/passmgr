//! The vault path must name a regular file: links and FIFOs are refused.

use super::*;

fn saved_vault(path: &Path) -> Vec<u8> {
    let mut vault = Vault::open_for_add(path, "master").unwrap();
    vault
        .add(credential("example.com", "user", "secret"))
        .unwrap();
    vault.save("master").unwrap();
    fs::read(path).unwrap()
}

#[test]
fn a_symlinked_vault_is_refused_and_its_target_is_untouched() {
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real.dat");
    let link = directory.path().join("link.dat");
    let before = saved_vault(&real);
    std::os::unix::fs::symlink(&real, &link).unwrap();

    for result in [
        Vault::open(&link, "master").map(drop),
        Vault::open_for_update(&link, "master").map(drop),
        Vault::open_for_add(&link, "master").map(drop),
    ] {
        let error = result.expect_err("a symlinked vault must be refused");
        assert!(matches!(error, Error::Refused(_)), "{error:?}");
        assert!(error.to_string().contains("symbolic link"), "{error}");
    }
    assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
    assert_eq!(fs::read(&real).unwrap(), before, "the target is unchanged");
    assert!(Vault::open(&real, "master").is_ok());
}

#[test]
fn a_dangling_symlink_is_not_replaced_by_a_new_vault() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("absent.dat");
    let link = directory.path().join("link.dat");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let error = Vault::open_for_add(&link, "master").map(drop).unwrap_err();
    assert!(matches!(error, Error::Refused(_)), "{error:?}");
    assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
    assert!(!target.exists());
}

#[test]
fn a_fifo_vault_is_refused_without_waiting_for_a_writer() {
    let directory = tempfile::tempdir().unwrap();
    let fifo = directory.path().join("vault.dat");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status();
    assert!(made.unwrap().success(), "mkfifo");

    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(read_container(&fifo).map(drop));
    });
    let result = receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("reading a FIFO vault must not block");
    assert!(
        matches!(result, Err(Error::MalformedVault(_))),
        "{result:?}"
    );
}
