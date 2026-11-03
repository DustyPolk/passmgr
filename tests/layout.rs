//! Layout guard for the ~1,000-line file rule in `PROMPT.md`.
//!
//! A file that grows past the limit is hard to review, and the security-
//! relevant code is exactly where review matters. TODO R.20 splits the files
//! that were already over the limit; each sub-item removes its entry from
//! `PENDING_SPLITS`, and the guard refuses any new offender immediately.

use std::fs;
use std::path::{Path, PathBuf};

/// The rule from `PROMPT.md` ("keep files under ~1,000 lines").
const MAX_LINES: usize = 1_000;

/// Files that TODO R.20b-R.20d still have to split, relative to the crate
/// root with `/` separators. This list only shrinks; the guard fails for every
/// file over the limit that is not named here.
const PENDING_SPLITS: &[&str] = &["src/protocol/mod.rs", "src/vault.rs", "tests/cli.rs"];

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display()));
    for entry in entries {
        let path = entry.expect("read directory entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

fn line_count(path: &Path) -> usize {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
        .lines()
        .count()
}

fn relative_name(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("source file is under the crate root")
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn every_source_file_stays_under_the_line_limit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rust_sources(&root.join("src"), &mut files);
    collect_rust_sources(&root.join("tests"), &mut files);
    assert!(!files.is_empty(), "found no Rust sources to check");

    let mut offenders = Vec::new();
    for path in files {
        let name = relative_name(root, &path);
        let lines = line_count(&path);
        if lines > MAX_LINES && !PENDING_SPLITS.contains(&name.as_str()) {
            offenders.push(format!("{name}: {lines} lines"));
        }
    }
    assert!(
        offenders.is_empty(),
        "these files exceed {MAX_LINES} lines; split them by concern instead of growing them:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_pending_split_allowlist_names_only_oversized_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in PENDING_SPLITS {
        let path = root.join(name);
        assert!(path.is_file(), "allowlisted file {name} does not exist");
        let lines = line_count(&path);
        assert!(
            lines > MAX_LINES,
            "{name} is now {lines} lines, so remove it from PENDING_SPLITS"
        );
    }
}
