//! Validation of the human-facing strings a grant carries: the label, the
//! command allowlist and field names.
//!
//! Kept apart from the model in `grant.rs` so that file stays readable; every
//! function here is pure and returns `InvalidInput`, which the payload decoder
//! turns into `MalformedVault`. The label table is the one the review notes
//! (TODO R.18) point at.

use std::path::PathBuf;

use super::{MAX_COMMANDS, MAX_FIELD_NAME_BYTES, MAX_LABEL_BYTES};
use crate::error::{Error, Result};
use crate::protocol::MAX_PATH_BYTES;

/// The classes of character a grant label or command path may not contain,
/// spelled the same way in the rejection error, `FORMAT.md` and
/// `DECISIONS.md` (TODO R.18, R.21).
///
/// The error names the whole class rather than echoing the offending code
/// point (or the label), because the label is untrusted text that later gets
/// printed to a terminal. A bad command is echoed back, but escaped (see
/// [`escape_hidden`]) so its own characters cannot forge the error line.
pub const LABEL_FORBIDDEN_CLASSES: &str =
    "control, bidi, zero-width/format, line-separator or variation-selector";

pub(super) fn validate_label(label: &str) -> Result<()> {
    if label.trim().is_empty() {
        return Err(Error::InvalidInput("a grant needs a label".into()));
    }
    if label.len() > MAX_LABEL_BYTES {
        return Err(Error::InvalidInput(format!(
            "a grant label holds at most {MAX_LABEL_BYTES} bytes"
        )));
    }
    if label.chars().any(is_hidden_or_reordering) {
        return Err(Error::InvalidInput(format!(
            "a grant label must not contain {LABEL_FORBIDDEN_CLASSES} characters"
        )));
    }
    Ok(())
}

/// Characters that are invisible, reorder neighbouring text, or can hide part
/// of a string from a human reading it.
///
/// Both callers store the text verbatim and later show it to a human -- the
/// label in `pm grant list`, each command path in the approval prompt -- and
/// from TODO 4.9 the text may come from an agent request, so this module
/// rejects the whole class instead of trusting the renderer. Covered: C0/C1
/// controls;
/// every Unicode **format** character (`Cf`) this build knows, which includes
/// the bidi controls (U+061C, U+200E/U+200F, U+202A-U+202E, U+2066-U+2069),
/// the zero-width set (U+200B-U+200D, U+2060-U+2064), soft hyphen, the tag
/// characters and U+FEFF; the line and paragraph separators (U+2028/U+2029);
/// and every variation selector (U+FE00-U+FE0F, U+E0100-U+E01EF), which are
/// invisible combining marks rather than `Cf`.
///
/// VS15/VS16 (U+FE0E/U+FE0F) are refused on purpose even though they select a
/// visible presentation: the rule is "store exactly what the human saw", and
/// the sequence "heart + VS16" renders as an emoji while the bare heart
/// renders as text. Accepting one variant and refusing the other would also
/// bring back the invisible-mark class this table exists to keep out. A human
/// can drop the selector ("❤ prod") or pick another emoji. Ordinary visible
/// combining marks, emoji without a selector or joiner, accents and non-Latin
/// scripts stay allowed.
///
/// Kept as an explicit table rather than a new dependency: a
/// general-category crate for one check would be a new tree to vet, and a
/// `Cf` character this list misses is rejected by the next review, not by a
/// silent pass.
fn is_hidden_or_reordering(character: char) -> bool {
    if character.is_control() {
        return true;
    }
    matches!(character,
        '\u{00AD}'                       // soft hyphen
        | '\u{0600}'..='\u{0605}'        // Arabic number signs
        | '\u{061C}'                     // Arabic letter mark
        | '\u{06DD}'                     // Arabic end of ayah
        | '\u{070F}'                     // Syriac abbreviation mark
        | '\u{0890}'..='\u{0891}'        // Arabic pound/piastre marks
        | '\u{08E2}'                     // Arabic disputed end of ayah
        | '\u{180E}'                     // Mongolian vowel separator
        | '\u{200B}'..='\u{200F}'        // zero-width + LRM/RLM
        | '\u{202A}'..='\u{202E}'        // bidi embeddings/overrides
        | '\u{2060}'..='\u{2064}'        // word joiner + invisible operators
        | '\u{2066}'..='\u{206F}'        // bidi isolates + deprecated formats
        | '\u{2028}'..='\u{2029}'        // line/paragraph separators
        | '\u{FE00}'..='\u{FE0F}'        // variation selectors
        | '\u{FEFF}'                     // zero-width no-break space (BOM)
        | '\u{FFF9}'..='\u{FFFB}'        // interlinear annotation
        | '\u{110BD}' | '\u{110CD}'      // Kaithi number signs
        | '\u{13430}'..='\u{1343F}'      // Egyptian hieroglyph controls
        | '\u{1BCA0}'..='\u{1BCA3}'      // shorthand format controls
        | '\u{1D173}'..='\u{1D17A}'      // musical symbol format controls
        | '\u{E0001}'                    // language tag
        | '\u{E0020}'..='\u{E007F}'      // tag characters
        | '\u{E0100}'..='\u{E01EF}'      // variation selectors supplement
    )
}

/// Render untrusted path text for an error message.
///
/// Every character [`is_hidden_or_reordering`] refuses is written as its
/// `\u{..}` escape, so a command such as `/usr/bin/gh\u{1b}[2K\r` is named in
/// the error without moving the cursor or erasing the line around it. The
/// quote and backslash are escaped too, so the quoted form cannot be closed
/// early. Everything visible (including non-ASCII scripts) is kept as is.
fn escape_hidden(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if is_hidden_or_reordering(character) || matches!(character, '\\' | '\'') {
            escaped.extend(character.escape_debug());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

pub(super) fn validate_commands(commands: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    // TODO R.21: a command path has the same provenance as a label, so it
    // must not be able to hide or reorder what an approving human reads.
    // Share the label's class table: one rule, one place. Stored grants need
    // no migration; the check is on the create and decode paths.
    if commands.len() > MAX_COMMANDS {
        return Err(Error::InvalidInput(format!(
            "a grant allows at most {MAX_COMMANDS} commands"
        )));
    }
    let mut commands = commands;
    for command in &commands {
        let text = command
            .to_str()
            .ok_or_else(|| Error::InvalidInput("a grant command must be valid UTF-8".into()))?;
        if text.is_empty() {
            return Err(Error::InvalidInput(
                "a grant command must be a non-empty path".into(),
            ));
        }
        if text.chars().any(is_hidden_or_reordering) {
            return Err(Error::InvalidInput(format!(
                "grant command '{}' must not contain {LABEL_FORBIDDEN_CLASSES} \
                 characters",
                escape_hidden(text)
            )));
        }
        if !command.is_absolute() {
            return Err(Error::InvalidInput(format!(
                "grant command '{}' must be an absolute path",
                escape_hidden(text)
            )));
        }
        if text.len() > MAX_PATH_BYTES {
            return Err(Error::InvalidInput(format!(
                "grant command '{}' exceeds {MAX_PATH_BYTES} bytes",
                escape_hidden(text)
            )));
        }
    }
    commands.sort();
    commands.dedup();
    Ok(commands)
}

/// Field names (`password`, `token`, `api_key`, …): 1-32 bytes of
/// `[a-z0-9_-]`, as fixed by TODO 6.1.
pub fn validate_field_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= MAX_FIELD_NAME_BYTES
        && name
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "invalid field name '{name}': expected 1-{MAX_FIELD_NAME_BYTES} characters of [a-z0-9_-]"
        )))
    }
}
