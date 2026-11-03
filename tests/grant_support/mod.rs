//! Shared fixture for the `grant` CLI integration tests: a temp vault, a real
//! `pmd`, and helpers to run the CLI on a pseudo-terminal.
//!
//! Vaults use deliberately cheap Argon2 parameters; these tests are not
//! testing the KDF. Each test owns its `XDG_RUNTIME_DIR` and temp vault.

#![allow(dead_code)] // each test binary uses a subset

#[path = "../cli_support/mod.rs"]
mod cli_support;

pub use cli_support::*;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use passmgr::crypto::{self, KdfParams};
use passmgr::grant::{Capabilities, Grant, GrantSpec, Scope, TokenHash};
use passmgr::socket::RuntimePaths;
use passmgr::store::{self, Credential};
use tempfile::TempDir;
use zeroize::Zeroizing;

pub const MASTER: &str = "grant cli test master password";
pub const SECRET: &str = "s3cret-grant-cli-value-must-never-leak";
pub const WAIT: Duration = Duration::from_secs(10);

pub struct Fixture {
    directory: TempDir,
    pub vault: PathBuf,
    pub reference: String,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_grants(0)
    }

    pub fn with_grants(count: usize) -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault = directory.path().join("vault.dat");
        let credential = Credential::new(
            "example.test".into(),
            "alice".into(),
            Zeroizing::new(SECRET.into()),
        )
        .expect("credential");
        let reference = credential.reference();

        let now = unix_now();
        let grants: Vec<Grant> = (0..count)
            .map(|index| {
                let spec = GrantSpec {
                    label: format!("seed grant {index}"),
                    scope: Scope::new(vec![], vec!["prod".into()], None).expect("scope"),
                    commands: vec![PathBuf::from("/usr/bin/true")],
                    capabilities: Capabilities::RUN,
                    expires_at: now + 3_600,
                    max_uses: None,
                };
                Grant::create(
                    spec,
                    TokenHash::of(format!("seed-token-{index}").as_bytes()),
                    now,
                )
                .expect("seed grant")
            })
            .collect();

        let plaintext = store::encode(&[credential], &grants).expect("encode store");
        let container = crypto::encrypt(&plaintext, MASTER, KdfParams::new(8 * 1024, 1, 1))
            .expect("encrypt vault");
        fs::write(&vault, &container).expect("write vault");
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o600)).expect("chmod vault");

        Self {
            directory,
            vault,
            reference,
        }
    }

    pub fn runtime(&self) -> &Path {
        self.directory.path()
    }

    pub fn runtime_text(&self) -> &str {
        self.runtime().to_str().expect("runtime path is UTF-8")
    }

    pub fn db(&self) -> &str {
        self.vault.to_str().expect("vault path is UTF-8")
    }

    pub fn daemon_paths(&self) -> RuntimePaths {
        RuntimePaths::at(self.runtime().join("passmgr"))
    }

    pub fn temp_path(&self, name: &str) -> PathBuf {
        self.runtime().join(name)
    }

    /// A stand-in program with the given name, executable so command
    /// resolution accepts it. No test ever runs it.
    pub fn fake_program(&self, name: &str) -> String {
        let path = self.temp_path(name);
        fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write fake program");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod fake program");
        path.to_str().expect("path is UTF-8").to_owned()
    }

    pub fn run_pty(&self, args: &[&str], input: &str) -> PtyOutput {
        run_on_pty(
            args,
            input,
            true,
            true,
            &[("XDG_RUNTIME_DIR", self.runtime_text())],
        )
    }

    pub fn unlock(&self) {
        let output = self.run_pty(&["--db", self.db(), "unlock"], &format!("{MASTER}\n"));
        assert!(output.status.success(), "unlock failed: {}", output.stderr);
        self.wait_ready();
    }

    pub fn wait_ready(&self) {
        let deadline = Instant::now() + WAIT;
        loop {
            let ready = passmgr::session::load(&self.daemon_paths())
                .ok()
                .is_some_and(|token| passmgr::client::ping(&self.daemon_paths(), &token).is_ok());
            if ready {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon did not become ready within {WAIT:?}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Never leave a detached daemon behind, even after a failed assertion.
        let _ = base_command(&["lock"])
            .env("XDG_RUNTIME_DIR", self.runtime())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

pub fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex has an even number of digits");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex digit"))
        .collect()
}

pub fn assert_ok(output: &PtyOutput) {
    assert!(
        output.status.success(),
        "command failed with {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        output.stdout,
        output.stderr
    );
}
