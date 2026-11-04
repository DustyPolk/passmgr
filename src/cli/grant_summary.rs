//! The grant approval summary: the metadata a human reads before saying yes.
//!
//! Everything here is display-only. A reference is resolved against the
//! already-decrypted vault so the human sees the service and username behind
//! it (TODO R.41); values are never read. Untrusted or stored names are
//! escaped, so no label, command path or credential name can drive a
//! terminal.

use std::io::IsTerminal;
use std::path::Path;

use passmgr::Error;
use passmgr::grant::{GrantRequest, Scope, escape_hidden, is_program_runner};
use passmgr::{timestamp, vault};

/// Show the human the request they are about to approve, on stderr.
///
/// Only metadata goes to the terminal: label, the credentials behind the
/// scope, commands, capabilities, expiry and use limit. Untrusted strings (an
/// agent suggested the label and paths) and display-only names from the vault
/// are all escaped, so none can drive the terminal. Every program runner that
/// `--allow-interpreter` let through gets its own warning, because allowing
/// one is allowing whatever it can start (TODO R.25).
pub(super) fn print_approval_prompt(request: &GrantRequest, now: u64, preview: &ScopePreview) {
    eprint!("{}", describe_request(request, now, preview));
    let color = std::io::stderr().is_terminal();
    for warning in runner_warnings(request) {
        eprintln!("{}", render_warning(&warning, color));
    }
}

/// One credential a scope names, reduced to the metadata a human needs to
/// recognize it. The value is never read: only the reference, the service name
/// and the username are ever held here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ScopeEntry {
    pub(super) reference: String,
    pub(super) service: String,
    pub(super) username: String,
}

impl ScopeEntry {
    pub(super) fn of(credential: &passmgr::store::Credential) -> Self {
        Self {
            reference: credential.reference(),
            service: credential.service().to_owned(),
            username: credential.username().to_owned(),
        }
    }

    /// The escaped, human-facing form: `service (username) [pm://ref]`.
    pub(super) fn describe(&self) -> String {
        let username = if self.username.is_empty() {
            "no username".to_owned()
        } else {
            escape_hidden(&self.username)
        };
        format!(
            "{} ({}) [{}]",
            escape_hidden(&self.service),
            username,
            self.reference
        )
    }
}

/// A scope resolved against the vault, ready to show a human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ScopePreview {
    pub(super) refs: Vec<ScopeEntry>,
    pub(super) tags: Vec<String>,
    pub(super) tagged: Vec<ScopeEntry>,
}

/// Resolve every ref and tag in `scope` against the vault.
///
/// A ref the vault does not hold is an error: approving a grant that names
/// nothing would be a lie to the human, and the missing entry cannot be
/// described (TODO R.41). Tags that match nothing are not an error (`--tag`
/// is a selector, not a promise), but the summary says so explicitly.
pub(super) fn preview_scope(scope: &Scope, vault: &vault::Vault) -> Result<ScopePreview, Error> {
    let mut refs = Vec::with_capacity(scope.refs().len());
    for id in scope.refs() {
        let credential = vault
            .get_by_ref(*id)
            .ok_or_else(|| Error::EntryNotFound(id.to_ref()))?;
        refs.push(ScopeEntry::of(credential));
    }
    let tagged = vault
        .list()
        .iter()
        .filter(|credential| scope.matches_tags(credential.tags()))
        .map(ScopeEntry::of)
        .collect();
    Ok(ScopePreview {
        refs,
        tags: scope.tags().to_vec(),
        tagged,
    })
}

/// Write the resolved scope as an indented block a human can check line by
/// line. Every name is escaped; none of it is a secret.
pub(super) fn write_scope(output: &mut String, preview: &ScopePreview, fields: Option<&[String]>) {
    use std::fmt::Write as _;

    writeln!(output, "  scope:").expect("writing to a String cannot fail");
    if !preview.refs.is_empty() {
        writeln!(output, "    refs:").expect("writing to a String cannot fail");
        for entry in &preview.refs {
            writeln!(output, "      {}", entry.describe())
                .expect("writing to a String cannot fail");
        }
    }
    if !preview.tags.is_empty() {
        let rule = if preview.tags.len() > 1 {
            " (a credential must carry all of them)"
        } else {
            ""
        };
        writeln!(
            output,
            "    tags: {}{rule}",
            escape_hidden(&preview.tags.join(", "))
        )
        .expect("writing to a String cannot fail");
        if preview.tagged.is_empty() {
            writeln!(output, "      (no credential currently matches)")
                .expect("writing to a String cannot fail");
        }
        for entry in &preview.tagged {
            writeln!(output, "      {}", entry.describe())
                .expect("writing to a String cannot fail");
        }
    }
    if let Some(fields) = fields {
        writeln!(output, "    fields: {}", fields.join(", "))
            .expect("writing to a String cannot fail");
    }
}

/// The request in the form the human reads before approving it.
pub(super) fn describe_request(request: &GrantRequest, now: u64, preview: &ScopePreview) -> String {
    use std::fmt::Write as _;

    let mut output = String::from("Grant request:\n");
    writeln!(output, "  label: {}", escape_hidden(request.label()))
        .expect("writing to a String cannot fail");
    write_scope(&mut output, preview, request.scope().fields());
    writeln!(output, "  commands:").expect("writing to a String cannot fail");
    for command in request.commands() {
        writeln!(output, "    {}", escape_hidden(command))
            .expect("writing to a String cannot fail");
    }
    writeln!(
        output,
        "  capabilities: {}",
        request.capabilities().names().join(", ")
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  {}",
        describe_expires_at(request.expires_at(), now)
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  max uses: {}",
        request
            .max_uses()
            .map(|uses| uses.to_string())
            .unwrap_or_else(|| "unlimited".to_owned())
    )
    .expect("writing to a String cannot fail");
    output
}

/// A warning line for every command that can run another program.
pub(super) fn runner_warnings(request: &GrantRequest) -> Vec<String> {
    request
        .commands()
        .iter()
        .filter(|command| is_program_runner(Path::new(command)))
        .map(|command| {
            format!(
                "WARNING: '{}' is a shell, interpreter or program runner: \
                 it can run any command with the credentials this grant covers",
                escape_hidden(command)
            )
        })
        .collect()
}

/// Bold red when the human's terminal can show it, plain text otherwise: a
/// piped summary or a captured log must not gain escape sequences.
pub(super) fn render_warning(text: &str, color: bool) -> String {
    if color {
        format!("\x1b[1;31m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

pub(super) fn describe_expires_at(expires_at: u64, now: u64) -> String {
    if expires_at <= now {
        format!("expired: {}", timestamp::format_utc(expires_at))
    } else {
        format!(
            "expires: {} (in {})",
            timestamp::format_utc(expires_at),
            humanize_seconds(expires_at - now)
        )
    }
}

/// A coarse, never-negative duration such as `7d 3h`, `59m` or `12s`.
pub(super) fn humanize_seconds(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
}
