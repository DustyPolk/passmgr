//! Rendering untrusted text for a terminal.
//!
//! Values that reach an error message, a prompt or a confirmation summary may
//! come from an agent (argv, a suggested label, a path). A terminal acts on
//! some of their characters: ESC starts a control sequence (OSC 52 can
//! overwrite the clipboard), BEL ends one, CR returns to column zero, and bidi
//! or zero-width characters reorder or hide text. Every such character is
//! written as its `\u{..}` escape instead, so the value is *named* rather than
//! executed.
//!
//! This module owns the character table and the two renderers. It sits low in
//! the crate graph (no I/O, no other passmgr module) so `store`, `grant`,
//! `error` and the CLI can all use it.

use std::path::Path;

/// Characters that are invisible, reorder neighbouring text, or can hide part
/// of a string from a human reading it.
///
/// Both callers store the text verbatim and later show it to a human -- the
/// label in `pm grant list`, each command path in the approval prompt -- and
/// from TODO 4.9 the text may come from an agent request, so validation
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
/// The classes of character [`is_hidden_or_reordering`] refuses, spelled the
/// same way in every rejection message, `FORMAT.md` and `DECISIONS.md` (TODO
/// R.18, R.48). One string, so the credential and grant validators cannot
/// drift apart in what they claim to refuse.
pub const HIDDEN_FORBIDDEN_CLASSES: &str =
    "control, bidi, zero-width/format, line-separator or variation-selector";

pub fn is_hidden_or_reordering(character: char) -> bool {
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

/// Render untrusted text for a quoted error message or prompt.
///
/// Every character [`is_hidden_or_reordering`] refuses is written as its
/// `\u{..}` escape, so a command such as `/usr/bin/gh\u{1b}[2K\r` is named in
/// the error without moving the cursor or erasing the line around it. The
/// quote and backslash are escaped too, so a value placed inside `'...'`
/// cannot close the quote early. Everything visible (including non-ASCII
/// scripts) is kept as is.
pub fn escape_quoted(text: &str) -> String {
    escape(text, true)
}

/// Render untrusted text for a terminal line, escaping only what the terminal
/// acts on.
///
/// Unlike [`escape_quoted`], visible characters — including quotes and
/// backslashes — are kept exactly as written, so a human approval summary
/// shows `Bob's token` and not `Bob\'s token`, and an error message keeps its
/// own punctuation. A validated label or command cannot contain a hidden
/// character, but escaping here means a caller cannot print one even if that
/// validation is ever loosened.
pub fn escape_hidden(text: &str) -> String {
    escape(text, false)
}

/// Render an argv-supplied path for a quoted message.
///
/// `Path::display()` prints a control character as-is, so a `--db` path could
/// drive the terminal. Every message that names a path quotes it with `'`, so
/// the quoted renderer is the right one: a quote or backslash in the path
/// cannot break out of the quotes.
pub fn escape_path(path: &Path) -> String {
    escape_quoted(&path.to_string_lossy())
}

fn escape(text: &str, quoted: bool) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if is_hidden_or_reordering(character) || (quoted && matches!(character, '\\' | '\'')) {
            escaped.extend(character.escape_debug());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The display form keeps visible text exactly as written — a human must
    /// see the label they approved, quotes and backslashes included — while a
    /// hidden character a terminal would act on is shown as an escape.
    #[test]
    fn display_escaping_keeps_visible_text_and_escapes_hidden_text() {
        assert_eq!(escape_hidden("Bob's token"), "Bob's token");
        assert_eq!(escape_hidden(r"C:\vault"), r"C:\vault");
        assert_eq!(
            escape_hidden("/usr/bin/gh\u{1b}[2K\r"),
            r"/usr/bin/gh\u{1b}[2K\r"
        );
        assert_eq!(escape_hidden("a\u{202e}b"), r"a\u{202e}b");
    }

    /// The quoted form also escapes the quote and backslash, so a value inside
    /// `'...'` cannot close the quote and forge the rest of the line.
    #[test]
    fn quoted_escaping_cannot_close_the_quote() {
        assert_eq!(escape_quoted(r"it's C:\vault"), r"it\'s C:\\vault");
        assert_eq!(
            escape_quoted("\u{1b}]52;c;ZXZpbA==\u{7}"),
            r"\u{1b}]52;c;ZXZpbA==\u{7}"
        );
    }

    /// A path is rendered with the quoted rules, so an escape sequence in a
    /// `--db` value is named rather than executed.
    #[test]
    fn path_escaping_uses_the_quoted_rules() {
        let path = Path::new("/tmp/\u{1b}]52;c;ZXZpbA==\u{7}/v.dat");
        let rendered = escape_path(path);
        assert!(rendered.contains(r"\u{1b}"), "{rendered}");
        assert!(rendered.contains(r"\u{7}"), "{rendered}");
        assert!(!rendered.contains('\u{1b}'), "{rendered}");
        assert!(!rendered.contains('\u{7}'), "{rendered}");
    }
}
