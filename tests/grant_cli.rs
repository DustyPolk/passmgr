//! End-to-end tests for `passmgr grant create` (TODO 3.4d).
//!
//! The CLI is exercised on a real pseudo-terminal against a real `pmd`, or
//! against a stub socket when the test must prove that no daemon request was
//! made. Every test uses its own `XDG_RUNTIME_DIR` and temp vault.

#![cfg(unix)]

mod grant_support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;

use passmgr::grant::{Capabilities, MAX_GRANTS, TokenHash, is_program_runner};
use passmgr::token::SessionToken;
use passmgr::vault::Vault;

use grant_support::*;

#[test]
fn grant_create_writes_a_scoped_grant_and_never_prints_the_token() {
    let _guard = serial();
    let fixture = Fixture::new();
    fixture.unlock();

    let out = fixture.temp_path("deploy.token");
    let out_text = out.to_str().expect("path is UTF-8");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "deploy prod",
            "--ref",
            &fixture.reference,
            "--tag",
            "prod",
            "--command",
            "/usr/bin/printenv",
            "--expires",
            "1h",
            "--max-uses",
            "2",
            "--out",
            out_text,
        ],
        &format!("{MASTER}\ny\n"),
    );
    assert_ok(&output);

    // The human types the password, then sees the whole request with the
    // credential names, then the confirmation (TODO R.41). Nothing is written
    // and no daemon is contacted before the explicit yes.
    let stderr = &output.stderr;
    let password_at = stderr
        .find("Enter Master Password:")
        .expect("the password is prompted first");
    let summary_at = stderr.find("Grant request:").expect("the request is shown");
    let confirm_at = stderr
        .find("Approve this grant? [y/N]")
        .expect("the confirmation follows the request");
    assert!(
        password_at < summary_at && summary_at < confirm_at,
        "the credential names and confirmation must follow the password, before anything else: {stderr}"
    );
    let canonical_printenv = fs::canonicalize("/usr/bin/printenv").expect("canonical printenv");
    let canonical_printenv = canonical_printenv.to_str().expect("path is UTF-8");
    let expected = [
        "label: deploy prod".to_owned(),
        format!("example.test (alice) [{}]", fixture.reference),
        "tags:".to_owned(),
        "      prod:".to_owned(),
        format!("    {canonical_printenv}"),
        "capabilities: run".to_owned(),
        "expires: ".to_owned(),
        "max uses: 2".to_owned(),
    ];
    for expected in expected {
        assert!(
            stderr.contains(&expected),
            "missing {expected:?} in {stderr}"
        );
    }

    let token_text = fs::read_to_string(&out).expect("token file");
    let token_hex = token_text.trim_end();
    assert_eq!(token_hex.len(), 64, "a grant token is 32 bytes of hex");
    assert!(
        token_hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "the token file holds lowercase hex"
    );
    assert_eq!(token_text, format!("{token_hex}\n"));
    assert_eq!(
        fs::metadata(&out).expect("metadata").permissions().mode() & 0o777,
        0o600,
        "the token file must be private"
    );
    for text in [&output.stdout, &output.stderr] {
        assert!(!text.contains(token_hex), "the token reached the terminal");
        assert!(
            !text.contains(SECRET),
            "the vault secret reached the terminal"
        );
    }

    let vault = Vault::open(&fixture.vault, MASTER).expect("open vault");
    assert_eq!(vault.grants().len(), 1);
    let grant = &vault.grants()[0];
    assert_eq!(grant.label(), "deploy prod");
    assert_eq!(grant.scope().refs().len(), 1);
    assert_eq!(grant.scope().refs()[0].to_ref(), fixture.reference);
    assert_eq!(grant.scope().tags(), ["prod"]);
    assert_eq!(grant.scope().fields(), None);
    assert!(grant.capabilities().contains(Capabilities::RUN));
    assert_eq!(
        grant.commands(),
        [fs::canonicalize("/usr/bin/printenv").expect("canonical printenv")]
    );
    assert_eq!(grant.max_uses(), Some(2));
    let expected = TokenHash::of(&decode_hex(token_hex));
    assert!(grant.token_hash().matches(&expected));

    let now = unix_now();
    assert!(grant.expires_at_unix() > now);
    assert!(grant.expires_at_unix() <= now + 3_600 + 60);

    // The CLI rewrote the vault with the key it derived; the daemon's hot key
    // must still open the new bytes and serve an injected run.
    let run = run_with_env(
        &[
            "run",
            "--env",
            &format!("TOKEN={}", fixture.reference),
            "--",
            "/usr/bin/printenv",
            "TOKEN",
        ],
        "",
        &[
            ("XDG_RUNTIME_DIR", fixture.runtime_text()),
            (
                "PASSMGR_GRANT_FILE",
                out.to_str().expect("utf-8 token path"),
            ),
        ],
    );
    assert_success(&run);
    assert!(stdout(&run).contains("[REDACTED]"), "{}", stdout(&run));
    assert!(!stdout(&run).contains(SECRET));
}

/// TODO R.41: the summary names the credential behind each reference, so an
/// approval cannot be steered onto a different entry by a trusty-looking
/// label. Cancelling here also proves the summary comes before any write.
#[test]
fn grant_create_shows_the_credential_behind_a_reference() {
    let _guard = serial();
    let fixture = Fixture::new();
    fixture.unlock();

    let out = fixture.temp_path("named.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "github ci token",
            "--ref",
            &fixture.reference,
            "--command",
            "/usr/bin/true",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\nn\n"),
    );

    assert_eq!(output.status.code(), Some(2), "{}", output.stderr);
    let summary_at = output.stderr.find("Grant request:").expect("summary");
    let named_at = output
        .stderr
        .find(&format!("example.test (alice) [{}]", fixture.reference))
        .expect("the service and username behind the ref are shown");
    let confirm_at = output
        .stderr
        .find("Approve this grant? [y/N]")
        .expect("confirmation");
    assert!(
        summary_at < named_at && named_at < confirm_at,
        "the credential must be named before the human approves: {}",
        output.stderr
    );
    assert!(!output.stderr.contains(SECRET), "no value is shown");
    assert!(!out.exists(), "a cancelled grant writes no token");
    assert!(
        Vault::open(&fixture.vault, MASTER)
            .expect("vault")
            .grants()
            .is_empty()
    );
}

/// A reference the vault does not hold is refused before the summary and
/// before any socket contact (TODO R.41): the human is never asked to approve
/// a grant that names nothing, and no approval is spent.
#[test]
fn grant_create_refuses_an_unknown_reference_before_any_socket_contact() {
    let _guard = serial();
    let fixture = Fixture::new();
    let paths = fixture.daemon_paths();
    let token = SessionToken::generate().expect("session token");
    passmgr::session::store(&paths, &token).expect("session file");
    let listener = UnixListener::bind(paths.socket()).expect("stub socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");

    let missing = "pm://ffffffffffffffffffffffffffffffff";
    let out = fixture.temp_path("missing.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "deploy prod",
            "--ref",
            missing,
            "--command",
            "/usr/bin/true",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\ny\n"),
    );

    assert_eq!(output.status.code(), Some(3), "{}", output.stderr);
    assert!(output.stderr.contains(missing), "{}", output.stderr);
    assert!(
        output.stderr.contains("no credential found for reference"),
        "{}",
        output.stderr
    );
    assert!(
        !output.stderr.contains("Grant request:"),
        "{}",
        output.stderr
    );
    assert!(
        !output.stderr.contains("Approve this grant?"),
        "{}",
        output.stderr
    );
    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "an unknown ref must not contact the daemon"
    );
    assert!(!out.exists(), "a refused grant must write no token file");
    assert!(
        Vault::open(&fixture.vault, MASTER)
            .expect("vault")
            .grants()
            .is_empty()
    );
}

/// An existing `--out` file is never truncated, even when everything else is
/// valid; the command fails before it prompts for the master password.
#[test]
fn grant_create_refuses_to_overwrite_an_existing_token_file() {
    let _guard = serial();
    let fixture = Fixture::new();
    fixture.unlock();

    let out = fixture.temp_path("existing.token");
    fs::write(&out, b"keep me").expect("seed token file");
    fs::set_permissions(&out, fs::Permissions::from_mode(0o600)).expect("chmod");

    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "deploy",
            "--tag",
            "prod",
            "--command",
            "/usr/bin/printenv",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("y\n{MASTER}\n"),
    );

    assert_eq!(output.status.code(), Some(2), "{}", output.stderr);
    assert!(
        output.stderr.contains("refusing to overwrite"),
        "{}",
        output.stderr
    );
    assert!(
        !output.stderr.contains("Master Password"),
        "the refusal must happen before the prompt: {}",
        output.stderr
    );
    assert_eq!(fs::read(&out).expect("token file"), b"keep me");
    assert!(
        Vault::open(&fixture.vault, MASTER)
            .expect("vault")
            .grants()
            .is_empty()
    );
}

/// Interpreter and shell paths are refused before any prompt, file or socket
/// work unless the human explicitly allows them.
#[test]
fn grant_create_refuses_an_interpreter_without_the_flag() {
    let _guard = serial();
    let fixture = Fixture::new();
    let out = fixture.temp_path("shell.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "shell",
            "--tag",
            "prod",
            "--command",
            "/bin/sh",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\n"),
    );

    assert_eq!(output.status.code(), Some(5), "{}", output.stderr);
    assert!(output.stderr.contains("interpreter"), "{}", output.stderr);
    assert!(!output.stderr.contains("Master Password"));
    assert!(!out.exists(), "a refused grant must not leave a token file");
    assert!(is_program_runner(Path::new("/bin/sh")));
}

/// A grant binds only `argv[0]`, so allowing `gh` would allow a shell through
/// `gh alias set --shell`. A program runner that is not a shell is refused
/// exactly like a shell, before the password prompt, any daemon request and
/// any token file (TODO R.25).
#[test]
fn grant_create_refuses_a_program_runner_without_the_flag() {
    let _guard = serial();
    let fixture = Fixture::new();
    let runner = fixture.fake_program("gh");
    let out = fixture.temp_path("gh.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "deploy prod",
            "--tag",
            "prod",
            "--command",
            &runner,
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\n"),
    );

    assert_eq!(output.status.code(), Some(5), "{}", output.stderr);
    assert!(
        output.stderr.contains("program runner"),
        "{}",
        output.stderr
    );
    assert!(
        output.stderr.contains("--allow-interpreter"),
        "a refusal must say how a human overrides it: {}",
        output.stderr
    );
    assert!(!output.stderr.contains("Master Password"));
    assert!(!out.exists(), "a refused grant must not leave a token file");
    assert!(
        passmgr::session::load(&fixture.daemon_paths())
            .ok()
            .is_none(),
        "a refused grant must not start a daemon"
    );
    let vault = Vault::open(&fixture.vault, MASTER).expect("open vault");
    assert!(vault.grants().is_empty());
}

/// The same runner is accepted once the human passes `--allow-interpreter`:
/// the flag is the decision, not the name list.
#[test]
fn grant_create_accepts_a_program_runner_when_the_human_allows_it() {
    let _guard = serial();
    let fixture = Fixture::new();
    fixture.unlock();
    let runner = fixture.fake_program("gh");
    let out = fixture.temp_path("gh-allowed.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "deploy prod",
            "--tag",
            "prod",
            "--command",
            &runner,
            "--allow-interpreter",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\ny\n"),
    );
    assert_ok(&output);

    // Allowing a runner is the human's decision, so the summary says what it
    // means before the confirmation. stderr is piped here, not a terminal, so
    // the warning is plain text with no escape sequences.
    let runner_path = fs::canonicalize(&runner).expect("canonical runner");
    let runner_path = runner_path.to_str().expect("path is UTF-8");
    let warning = format!(
        "WARNING: '{runner_path}' is a shell, interpreter or program runner: \
         it can run any command with the credentials this grant covers"
    );
    let warning_at = output
        .stderr
        .find(&warning)
        .unwrap_or_else(|| panic!("missing {warning:?} in {}", output.stderr));
    let password_at = output
        .stderr
        .find("Enter Master Password:")
        .expect("the password prompt comes first");
    assert!(password_at < warning_at, "{}", output.stderr);
    assert!(
        !output.stderr.contains('\u{1b}'),
        "a piped summary must not gain colour escapes: {}",
        output.stderr
    );

    let token = fs::read_to_string(&out).expect("token file");
    assert_eq!(token.trim_end().len(), 64);
    for text in [&output.stdout, &output.stderr] {
        assert!(!text.contains(token.trim_end()));
        assert!(!text.contains(SECRET));
    }

    let vault = Vault::open(&fixture.vault, MASTER).expect("open vault");
    assert_eq!(vault.grants().len(), 1);
    assert_eq!(
        vault.grants()[0].commands(),
        [fs::canonicalize(&runner).expect("canonical runner")]
    );
}

/// Agent context is refused with exit 5, even on a terminal.
#[test]
fn grant_create_is_refused_in_agent_context() {
    let _guard = serial();
    let fixture = Fixture::new();
    let out = fixture.temp_path("agent.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "--agent",
            "grant",
            "create",
            "--label",
            "agent",
            "--tag",
            "prod",
            "--command",
            "/usr/bin/printenv",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\n"),
    );

    assert_eq!(output.status.code(), Some(5), "{}", output.stderr);
    assert!(
        output.stderr.contains("reserved for a human"),
        "{}",
        output.stderr
    );
    assert!(!output.stderr.contains("Master Password"));
    assert!(!out.exists());
}

/// A full vault is refused before the approval is requested: the CLI opens the
/// vault and checks writability, so no `challenge`/`prove` frame reaches the
/// stub socket and no approval is spent (TODO R.22b).
#[test]
fn grant_create_refuses_a_full_vault_before_asking_the_daemon() {
    let _guard = serial();
    let fixture = Fixture::with_grants(MAX_GRANTS);
    let paths = fixture.daemon_paths();
    let token = SessionToken::generate().expect("session token");
    passmgr::session::store(&paths, &token).expect("session file");
    let listener = UnixListener::bind(paths.socket()).expect("stub socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");

    let out = fixture.temp_path("full.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "too many",
            "--tag",
            "prod",
            "--command",
            "/usr/bin/true",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\ny\n"),
    );

    assert_eq!(output.status.code(), Some(2), "{}", output.stderr);
    assert!(
        output.stderr.contains("too many grants"),
        "{}",
        output.stderr
    );
    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "a full vault must not send challenge/prove to the daemon"
    );
    assert!(
        !out.exists(),
        "a refused grant must remove the token file it created"
    );
    assert_eq!(
        Vault::open(&fixture.vault, MASTER)
            .expect("vault")
            .grants()
            .len(),
        MAX_GRANTS
    );
}

/// Anything but an explicit yes cancels the creation: exit 2, no token file,
/// an unchanged vault, and no connection to the daemon — even though the
/// summary was printed first. The password comes first now (TODO R.41), so
/// canceling still proves nothing was written after a real unlock.
#[test]
fn grant_create_cancels_without_an_explicit_yes() {
    let _guard = serial();
    let fixture = Fixture::new();
    let paths = fixture.daemon_paths();
    let token = SessionToken::generate().expect("session token");
    passmgr::session::store(&paths, &token).expect("session file");
    let listener = UnixListener::bind(paths.socket()).expect("stub socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");

    let out = fixture.temp_path("cancelled.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "deploy prod",
            "--tag",
            "prod",
            "--command",
            "/usr/bin/true",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\nn\n"),
    );

    assert_eq!(output.status.code(), Some(2), "{}", output.stderr);
    assert!(
        output.stderr.contains("Grant request:"),
        "the human must see what they refused: {}",
        output.stderr
    );
    assert!(
        output.stderr.contains("Approve this grant? [y/N]"),
        "{}",
        output.stderr
    );
    assert!(
        output.stderr.contains("cancelled; nothing was written"),
        "{}",
        output.stderr
    );
    assert!(!out.exists(), "a cancelled grant must write no token file");
    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "a cancelled grant must not contact the daemon"
    );
    assert!(
        Vault::open(&fixture.vault, MASTER)
            .expect("vault")
            .grants()
            .is_empty()
    );
}

/// A command path carrying a hidden character is refused before any summary:
/// the terminal never receives the raw escape, and the rejection names the
/// problem in text instead.
#[test]
fn grant_create_refuses_a_command_with_a_hidden_character_before_the_summary() {
    let _guard = serial();
    let fixture = Fixture::new();
    let runner = fixture.fake_program("gh\u{1b}[2K\rpwn");
    let out = fixture.temp_path("hidden.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "deploy prod",
            "--tag",
            "prod",
            "--command",
            &runner,
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\n"),
    );

    assert_eq!(output.status.code(), Some(2), "{}", output.stderr);
    assert!(
        output.stderr.contains("must not contain control"),
        "{}",
        output.stderr
    );
    assert!(
        !output.stderr.contains('\u{1b}'),
        "the raw escape reached the terminal: {:?}",
        output.stderr
    );
    assert!(
        !output.stderr.contains("Grant request:"),
        "a refused command must not reach the summary: {}",
        output.stderr
    );
    assert!(!output.stderr.contains("Enter Master Password:"));
    assert!(!out.exists());
}

/// A vault write that lands after the human approved but before the CLI saved
/// must not refuse the approved creation, and must not be lost (TODO R.39).
///
/// The CLI used to read the vault, ask the daemon, then compare-and-lock; a
/// run recording its use in that window answered `internal` after the human
/// had already typed the password and the approval was spent. The CLI now
/// opens the vault under the write lock and adds the grant to that state.
#[test]
fn grant_create_keeps_a_concurrent_vault_write_and_still_succeeds() {
    use passmgr::grant::{Grant, GrantSpec, Scope};
    use std::time::Duration;

    let _guard = serial();
    let fixture = Fixture::new();
    fixture.unlock();

    let container = fs::read(&fixture.vault).expect("read vault");
    let key = passmgr::crypto::unlock_key(&container, MASTER).expect("derive key");
    let now = unix_now();

    // A grant to record a use against, added under the same lock the CLI will
    // need, so this test holds a real vault write in flight.
    let seeded = Grant::create(
        GrantSpec {
            label: "an earlier grant".into(),
            scope: Scope::new(vec![], vec!["prod".into()], None).expect("scope"),
            commands: vec![std::path::PathBuf::from("/usr/bin/true")],
            capabilities: Capabilities::RUN,
            expires_at: now + 3_600,
            max_uses: None,
        },
        TokenHash::of(b"seeded grant token"),
        now,
    )
    .expect("seed grant");
    let seeded_id = seeded.id();
    let mut writer =
        Vault::open_with_key_for_update(&fixture.vault, key.as_slice()).expect("lock vault");
    writer.add_grant(seeded).expect("add grant");
    writer.save_with_key(key.as_slice()).expect("save grant");

    let out = fixture.temp_path("raced.token");
    let out_text = out.to_str().expect("path is UTF-8");
    let output = std::thread::scope(|scope| {
        let create = scope.spawn(|| {
            fixture.run_pty(
                &[
                    "--db",
                    fixture.db(),
                    "grant",
                    "create",
                    "--label",
                    "raced create",
                    "--ref",
                    &fixture.reference,
                    "--command",
                    "/usr/bin/true",
                    "--expires",
                    "1h",
                    "--out",
                    out_text,
                ],
                &format!("{MASTER}\ny\n"),
            )
        });
        // Long enough for the approved CLI to be waiting at the lock. If it is
        // still earlier, it reads the new state and the race simply did not
        // happen; either way the creation must succeed and nothing is lost.
        std::thread::sleep(Duration::from_millis(300));
        writer
            .grant_mut(seeded_id)
            .expect("seeded grant")
            .mark_used(now)
            .expect("mark used");
        writer.save_with_key(key.as_slice()).expect("save use");
        drop(writer);
        create.join().expect("create thread")
    });
    assert_ok(&output);

    let vault = Vault::open(&fixture.vault, MASTER).expect("open vault");
    assert_eq!(vault.grants().len(), 2, "the approved grant must be saved");
    assert_eq!(
        vault.grant(seeded_id).expect("seeded grant").uses(),
        1,
        "the creation must keep the concurrent write"
    );
    assert!(
        vault
            .grants()
            .iter()
            .any(|grant| grant.label() == "raced create"),
        "the approved grant must be in the vault"
    );
    assert!(out.exists(), "the token file must have been written");
}
