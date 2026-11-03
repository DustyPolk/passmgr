//! Command implementations that do not touch the unlock daemon.

use std::path::Path;

use passmgr::Error;
use passmgr::agent;
use passmgr::password;
use passmgr::store::{self, Credential};
use passmgr::terminal;
use passmgr::timestamp;
use passmgr::vault::{self, Vault};
use zeroize::Zeroizing;

use super::args::{AddOptions, EditOptions, GenerateOptions};
use super::stdout_write;

pub(crate) fn command_generate(options: GenerateOptions) -> Result<(), Error> {
    let generated = password::generate_password(options.preset, options.length)?;
    stdout_write(format_args!("{}\n", generated.as_str()))
}

pub(crate) fn command_add(options: AddOptions, path: &Path) -> Result<(), Error> {
    store::validate_identity(&options.service, &options.username)?;

    let generated = if options.generate {
        Some(password::generate_password(options.preset, options.length)?)
    } else {
        None
    };

    let creating = !path.exists();
    warn_insecure(path)?;
    let master = prompt_master(creating)?;
    let mut vault = Vault::open_for_add(path, &master)?;

    if vault.get(&options.service).is_some() {
        return Err(Error::DuplicateService(options.service.clone()));
    }

    let credential_password = match generated {
        Some(generated) => generated,
        None => prompt_credential_password(&options.service)?,
    };

    let service = options.service;
    let credential = Credential::new(service.clone(), options.username, credential_password)?
        .with_tags(options.tags)?;
    vault.add(credential)?;
    vault.save(&master)?;

    if options.generate {
        // Never print the generated password: the only way to read it back is
        // the TTY-gated `get --reveal`. Only metadata goes to the terminal.
        eprintln!("Credential '{service}' added successfully with a generated password.");
    } else {
        eprintln!("Credential added successfully.");
    }
    Ok(())
}

pub(crate) fn command_get(
    service: &str,
    reveal: bool,
    agent_mode: bool,
    path: &Path,
) -> Result<(), Error> {
    if reveal {
        // Refuse before touching the vault or prompting for the master
        // password: a pipe or an agent context must never reach the plaintext.
        // `--agent` can only add refusal; it never removes the TTY rule.
        agent::check_reveal(agent_mode).map_err(|refusal| Error::Refused(refusal.message()))?;
    }
    let (vault, _) = unlock(path)?;
    let credential = vault
        .get(service)
        .ok_or_else(|| Error::ServiceNotFound(service.to_owned()))?;
    let name = credential.service();
    let username = credential.username();
    let reference = credential.reference();
    // The reference is metadata (an id, not a secret) and is safe to print in
    // both modes: agents need it to name the entry. Tags are metadata too.
    let tags_line = tags_line(credential.tags());
    if reveal {
        stdout_write(format_args!(
            "Ref: {reference}\nService: {name}\nUsername: {username}\n{tags_line}Password: {}\n",
            credential.password()
        ))
    } else {
        stdout_write(format_args!(
            "Ref: {reference}\nService: {name}\nUsername: {username}\n{tags_line}Password: <redacted>\n"
        ))
    }
}

/// A `Tags:` line for human-readable output, or an empty string when the
/// credential has no tags. Tags are metadata, never secrets.
pub(crate) fn tags_line(tags: &[String]) -> String {
    if tags.is_empty() {
        String::new()
    } else {
        format!("Tags: {}\n", tags.join(", "))
    }
}

/// An edit rotates the password unless it is a metadata-only change
/// (`--username`, `--rename`, `--tag` or `--clear-tags` without
/// `--generate`).
pub(crate) fn edit_rotates_password(options: &EditOptions) -> bool {
    options.generate
        || (options.username.is_none()
            && options.rename.is_none()
            && options.tags.is_none()
            && !options.clear_tags)
}

pub(crate) fn command_edit(options: EditOptions, path: &Path) -> Result<(), Error> {
    // Validate everything that is not a secret before unlocking, so a typo
    // fails without a prompt.
    if let Some(rename) = &options.rename {
        store::validate_service(rename)?;
    }
    if let Some(username) = &options.username {
        store::validate_username(username)?;
    }
    let rotate = edit_rotates_password(&options);

    let (mut vault, master) = unlock_for_update(path)?;
    if vault.get(&options.service).is_none() {
        return Err(Error::ServiceNotFound(options.service.clone()));
    }

    if let Some(rename) = &options.rename {
        vault.rename(&options.service, rename)?;
    }
    let service = options.rename.as_deref().unwrap_or(&options.service);

    if let Some(username) = options.username {
        vault
            .get_mut(service)
            .expect("the credential was just found or renamed")
            .set_username(username)?;
    }

    if options.tags.is_some() || options.clear_tags {
        vault
            .get_mut(service)
            .expect("the credential was just found or renamed")
            .set_tags(options.tags.unwrap_or_default())?;
    }

    if rotate {
        let password = if options.generate {
            password::generate_password(options.preset, options.length)?
        } else {
            prompt_credential_password(service)?
        };
        vault
            .get_mut(service)
            .expect("the credential was just found or renamed")
            .set_password(password)?;
    }

    vault.save(&master)?;

    if options.generate {
        // Never print the generated password; read it back with the
        // TTY-gated `get --reveal`.
        eprintln!("Credential '{service}' updated with a generated password.");
    } else {
        eprintln!("Credential '{service}' updated.");
    }
    Ok(())
}

pub(crate) fn command_delete(service: &str, path: &Path) -> Result<(), Error> {
    let (mut vault, master) = unlock_for_update(path)?;
    vault.delete(service)?;
    vault.save(&master)?;
    eprintln!("Credential deleted successfully.");
    Ok(())
}

pub(crate) fn command_list(json: bool, tags: &[String], path: &Path) -> Result<(), Error> {
    let (vault, _) = unlock(path)?;
    let entries: Vec<&Credential> = vault.list_tagged(tags).collect();

    if json {
        let entries: Vec<_> = entries.iter().map(|entry| entry_metadata(entry)).collect();
        return write_json(&serde_json::json!({ "entries": entries }));
    }
    if entries.is_empty() {
        if tags.is_empty() {
            eprintln!("No credentials stored.");
        } else {
            eprintln!("No credentials match tags: {}.", tags.join(", "));
        }
        return Ok(());
    }

    use std::fmt::Write as _;

    let mut output = String::from("Stored Services:\n");
    for credential in entries {
        writeln!(
            output,
            "- {} ({}) [{}]",
            credential.service(),
            credential.username(),
            credential.reference()
        )
        .expect("writing to a String cannot fail");
        if !credential.tags().is_empty() {
            writeln!(output, "  tags: {}", credential.tags().join(", "))
                .expect("writing to a String cannot fail");
        }
    }
    stdout_write(format_args!("{}", output))
}

/// The JSON form of an entry: references and metadata only. A credential's
/// password has no accessor here, so serializing an entry cannot leak it.
/// Timestamps are RFC 3339 UTC strings, or `null` when the stored value is 0
/// (unknown, which is what entries migrated from a pre-v4 payload carry).
pub(crate) fn entry_metadata(credential: &Credential) -> serde_json::Value {
    serde_json::json!({
        "ref": credential.reference(),
        "service": credential.service(),
        "username": credential.username(),
        "tags": credential.tags(),
        "created": timestamp::to_json(credential.created_unix()),
        "last_rotated": timestamp::to_json(credential.last_rotated_unix()),
    })
}

pub(crate) fn write_json(value: &serde_json::Value) -> Result<(), Error> {
    let mut text = serde_json::to_string(value)
        .map_err(|error| Error::InvalidInput(format!("cannot encode JSON: {error}")))?;
    text.push('\n');
    stdout_write(format_args!("{text}"))
}

pub(crate) fn command_show(reference: &str, json: bool, path: &Path) -> Result<(), Error> {
    // Parse the reference before unlocking: a malformed reference is a usage
    // error and must not cost the user a master-password prompt.
    let id = store::EntryId::parse_ref(reference)?;
    let (vault, _) = unlock(path)?;
    let credential = vault
        .get_by_ref(id)
        .ok_or_else(|| Error::EntryNotFound(reference.to_owned()))?;
    if json {
        write_json(&entry_metadata(credential))
    } else {
        stdout_write(format_args!(
            "Ref: {}\nService: {}\nUsername: {}\n{}",
            credential.reference(),
            credential.service(),
            credential.username(),
            tags_line(credential.tags())
        ))
    }
}
pub(crate) fn unlock(path: &Path) -> Result<(Vault, Zeroizing<String>), Error> {
    warn_insecure(path)?;
    let master = prompt_master(false)?;
    let vault = Vault::open(path, &master)?;
    Ok((vault, master))
}

/// Unlock for a read-modify-write command. The returned vault holds the
/// exclusive write lock until it is dropped (after the save).
pub(crate) fn unlock_for_update(path: &Path) -> Result<(Vault, Zeroizing<String>), Error> {
    warn_insecure(path)?;
    let master = prompt_master(false)?;
    let vault = Vault::open_for_update(path, &master)?;
    Ok((vault, master))
}

pub(crate) fn prompt_master(confirm: bool) -> Result<Zeroizing<String>, Error> {
    let master = terminal::prompt_password("Enter Master Password: ")?;
    if master.is_empty() {
        return Err(Error::InvalidInput(
            "master password cannot be empty".to_owned(),
        ));
    }
    if confirm {
        let confirmation = terminal::prompt_password("Confirm Master Password: ")?;
        if master.as_str() != confirmation.as_str() {
            return Err(Error::InvalidInput(
                "master passwords do not match".to_owned(),
            ));
        }
    }
    Ok(master)
}

pub(crate) fn prompt_credential_password(service: &str) -> Result<Zeroizing<String>, Error> {
    let password = terminal::prompt_password(&format!("Enter password for {service}: "))?;
    if password.is_empty() {
        return Err(Error::InvalidInput(
            "credential password cannot be empty".to_owned(),
        ));
    }
    let confirmation = terminal::prompt_password("Confirm password: ")?;
    if password.as_str() != confirmation.as_str() {
        return Err(Error::InvalidInput("passwords do not match".to_owned()));
    }
    Ok(password)
}

pub(crate) fn warn_insecure(path: &Path) -> Result<(), Error> {
    if let Some(mode) = vault::insecure_permissions(path) {
        eprintln!(
            "warning: '{}' has permissions {mode:04o}; other users may be able to read it",
            path.display()
        );
        eprintln!("         fix with: chmod 600 '{}'", path.display());
    }
    Ok(())
}
