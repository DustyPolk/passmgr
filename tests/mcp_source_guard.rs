//! Source guard: the `mcp` module must not reach reveal or clipboard code.
//!
//! `MCP.md` (Process model) requires a source-level test, not merely a
//! comment, so a future change cannot quietly import a secret-revealing
//! helper into `pm mcp serve`. The check strips comments and string/char
//! literal contents (prose in the tool catalogue and test data must not trip
//! it) and then fails on any remaining identifier containing `reveal` or
//! `clipboard`. That is deliberately broader than the call shapes a reviewer
//! would look for: `use crate::reveal`, `mod reveal`, `reveal::print(...)` and
//! a rename through `use ... as` all still carry the word.

use std::fs;
use std::path::{Path, PathBuf};

/// Words that must never appear as code identifiers under `src/mcp/`.
const BANNED: [&str; 2] = ["reveal", "clipboard"];

/// Lexer state that survives a line boundary, because a Rust string literal
/// may be continued with a trailing `\` and a block or raw string may span
/// several lines.
#[derive(Default)]
struct ScanState {
    block_comment_depth: usize,
    in_string: bool,
    raw_hashes: Option<usize>,
}

impl ScanState {
    /// Return `line` with comments and the contents of literals replaced by
    /// spaces, so only code identifiers remain.
    fn strip(&mut self, line: &str) -> String {
        let chars: Vec<char> = line.chars().collect();
        let mut out = String::with_capacity(line.len());
        let mut i = 0;

        while i < chars.len() {
            if let Some(hashes) = self.raw_hashes {
                let closes = chars[i] == '"'
                    && chars.len() >= i + 1 + hashes
                    && chars[i + 1..i + 1 + hashes].iter().all(|&c| c == '#');
                if closes {
                    i += 1 + hashes;
                    self.raw_hashes = None;
                } else {
                    i += 1;
                }
                out.push(' ');
                continue;
            }

            if self.block_comment_depth > 0 {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    self.block_comment_depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    self.block_comment_depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
                out.push(' ');
                continue;
            }

            if self.in_string {
                if chars[i] == '\\' {
                    i += 1;
                    if i < chars.len() {
                        i += 1;
                    }
                } else {
                    if chars[i] == '"' {
                        self.in_string = false;
                    }
                    i += 1;
                }
                out.push(' ');
                continue;
            }

            if chars[i] == '/' && chars.get(i + 1) == Some(&'/') {
                break;
            }
            if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                self.block_comment_depth = 1;
                i += 2;
                out.push(' ');
                continue;
            }
            if chars[i] == '"' {
                self.in_string = true;
                i += 1;
                out.push(' ');
                continue;
            }
            if chars[i] == '\'' {
                if let Some(length) = char_literal_len(&chars, i) {
                    i += length;
                    out.push(' ');
                    continue;
                }
                // A lifetime or a lone apostrophe is ordinary code.
                out.push(chars[i]);
                i += 1;
                continue;
            }

            let previous_is_identifier = out.chars().last().is_some_and(is_identifier);
            if !previous_is_identifier {
                if let Some((length, hashes)) = raw_string_prefix(&chars, i) {
                    self.raw_hashes = Some(hashes);
                    i += length;
                    out.push(' ');
                    continue;
                }
            }

            out.push(chars[i]);
            i += 1;
        }

        out
    }
}

fn is_identifier(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Length of a character literal starting at `start` (`'\''`, `'a'`,
/// `'\u{1F600}'`), or `None` when the apostrophe begins a lifetime.
fn char_literal_len(chars: &[char], start: usize) -> Option<usize> {
    let next = *chars.get(start + 1)?;
    if next == '\\' {
        let mut end = start + 3;
        while end < chars.len() && end <= start + 16 {
            match chars[end] {
                '\'' => return Some(end - start + 1),
                '\n' => return None,
                _ => end += 1,
            }
        }
        return None;
    }
    if chars.get(start + 2) == Some(&'\'') {
        return Some(3);
    }
    None
}

/// Recognise `r"…"`, `r#"…"#`, `br"…"`, `br#"…"#` and the `c` equivalents.
/// Returns the prefix length (through the opening quote) and the number of
/// `#` delimiters.
fn raw_string_prefix(chars: &[char], start: usize) -> Option<(usize, usize)> {
    let mut i = start;
    if matches!(chars.get(i), Some('b' | 'c')) {
        i += 1;
    }
    if chars.get(i) != Some(&'r') {
        return None;
    }
    i += 1;
    let mut hashes = 0;
    while chars.get(i) == Some(&'#') {
        hashes += 1;
        i += 1;
    }
    if chars.get(i) != Some(&'"') {
        return None;
    }
    Some((i + 1 - start, hashes))
}

/// Every line of `source` whose code contains a banned identifier, with the
/// offending token. Comments and literal contents are ignored.
fn scan_source(source: &str) -> Vec<(usize, String)> {
    let mut state = ScanState::default();
    let mut hits = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let code = state.strip(line);
        for token in code.split(|c: char| !is_identifier(c)) {
            if token.is_empty() {
                continue;
            }
            let lower = token.to_lowercase();
            if BANNED.iter().any(|banned| lower.contains(banned)) {
                hits.push((index + 1, token.to_string()));
            }
        }
    }
    hits
}

fn collect_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display()));
    for entry in entries {
        let path = entry.expect("read directory entry").path();
        if path.is_dir() {
            collect_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

/// The guard recognises every route a future change could take, not only a
/// direct call: an import, a module declaration, a path-qualified call and a
/// similarly named local.
#[test]
fn the_guard_recognises_every_route_to_a_reveal_or_clipboard_helper() {
    let dangerous = r#"
use crate::reveal::print_secret;
fn leak(value: &str) { crate::clipboard::copy(value); }
mod reveal;
let clipboard_handle = 0;
let renamed = crate::human::reveal as only_for_humans;
"#;
    let hits = scan_source(dangerous);
    let lines: Vec<usize> = hits.iter().map(|(line, _)| *line).collect();
    assert_eq!(lines, vec![2, 3, 4, 5, 6], "hits were {hits:?}");
    assert!(hits.iter().any(|(_, token)| token.contains("reveal")));
    assert!(hits.iter().any(|(_, token)| token.contains("clipboard")));
}

/// Prose, comments, lifetimes and literal contents are not code. Without
/// this, the catalogue's own tool description and the module's doc comment
/// would make the guard unusable.
#[test]
fn the_guard_ignores_prose_strings_comments_and_lifetimes() {
    let benign = r##"
//! reveal and clipboard are named in this comment only.
// crate::reveal::print_secret();
/* nested /* clipboard */ crate::reveal::x */
let message = "reveal clipboard crate::reveal::x";
let raw = r#"reveal "quoted" clipboard"#;
let quote = '"';
let escaped = '\'';
let newline = '\n';
let lifetime: &'a str = message;
let total = 1 + 2;
"##;
    assert_eq!(scan_source(benign), Vec::new());
}

/// The real module is clean, and the scan is not vacuous: the expected files
/// must be found before their absence of hits means anything.
#[test]
fn no_mcp_source_reaches_reveal_or_clipboard_code() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mcp = root.join("src/mcp");
    let mut files = Vec::new();
    collect_sources(&mcp, &mut files);
    files.sort();

    let relative: Vec<String> = files
        .iter()
        .map(|path| {
            path.strip_prefix(root)
                .expect("source is under the crate root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    for expected in [
        "src/mcp/call.rs",
        "src/mcp/era.rs",
        "src/mcp/jsonrpc.rs",
        "src/mcp/mod.rs",
        "src/mcp/server.rs",
        "src/mcp/tools.rs",
    ] {
        assert!(
            relative.iter().any(|name| name == expected),
            "guard did not find {expected}; scanned {relative:?}"
        );
    }

    let mut problems = Vec::new();
    for (path, name) in files.iter().zip(&relative) {
        let source =
            fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        for (line, token) in scan_source(&source) {
            problems.push(format!("{name}:{line}: {token}"));
        }
    }

    assert!(
        problems.is_empty(),
        "the mcp module must not reach reveal or clipboard code, but found:\n{}",
        problems.join("\n")
    );
}
