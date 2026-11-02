//! Human-versus-agent context detection.
//!
//! The agent-facing surface never returns plaintext. Plaintext reveal
//! (`get --reveal`) is reserved for a human sitting at a terminal, so a reveal
//! must satisfy both conditions:
//!
//! 1. stdin *and* stdout are terminals, and
//! 2. no agent environment marker is present.
//!
//! There is deliberately no flag that bypasses this check. The decision lives
//! here, in one place, so that every future plaintext path (clipboard, export)
//! can reuse it.

use std::env;
use std::io::{self, IsTerminal};

/// Environment variables that indicate the caller is an automated agent.
///
/// Presence alone counts, even with an empty value: an inherited marker is
/// treated as an agent context, which is the conservative choice. The CLI's
/// `--agent` flag (TODO 0.4) will force the same state.
pub const AGENT_MARKERS: [&str; 4] = [
    "PASSMGR_AGENT",
    "CLAUDECODE",
    "CURSOR_AGENT",
    "CODEX_SANDBOX",
];

/// Returns the name of the first agent marker present in the environment.
pub fn agent_marker() -> Option<&'static str> {
    marker_from(|name| env::var_os(name).is_some())
}

/// Testable core of [`agent_marker`]: `is_set` decides whether a marker exists.
fn marker_from(is_set: impl Fn(&str) -> bool) -> Option<&'static str> {
    AGENT_MARKERS.into_iter().find(|name| is_set(name))
}

/// Whether this process is running in an agent context.
pub fn is_agent_context() -> bool {
    agent_marker().is_some()
}

/// Why a plaintext reveal was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealRefusal {
    /// An agent environment marker was found; carries the marker name.
    AgentContext(&'static str),
    /// stdin is not a terminal, so a human cannot be typing here.
    StdinNotTerminal,
    /// stdout is not a terminal, so the value would be captured by a pipe.
    StdoutNotTerminal,
}

impl RevealRefusal {
    /// Human-readable refusal reason. Never contains secret material.
    pub fn message(self) -> String {
        match self {
            Self::AgentContext(marker) => format!(
                "refusing to reveal a secret in an agent context ({marker} is set); \
                 plaintext reveal is reserved for a human at a terminal and has no bypass"
            ),
            Self::StdinNotTerminal => "refusing to reveal a secret: stdin is not a terminal; \
                 plaintext reveal is reserved for a human at a terminal and has no bypass"
                .to_owned(),
            Self::StdoutNotTerminal => "refusing to reveal a secret: stdout is not a terminal; \
                 plaintext reveal is reserved for a human at a terminal and has no bypass"
                .to_owned(),
        }
    }
}

/// Pure decision function for a plaintext reveal.
///
/// Precedence is agent marker first, then stdin, then stdout, so the reported
/// reason names the strongest problem.
pub fn reveal_refusal(
    stdin_is_tty: bool,
    stdout_is_tty: bool,
    marker: Option<&'static str>,
) -> Option<RevealRefusal> {
    if let Some(marker) = marker {
        return Some(RevealRefusal::AgentContext(marker));
    }
    if !stdin_is_tty {
        return Some(RevealRefusal::StdinNotTerminal);
    }
    if !stdout_is_tty {
        return Some(RevealRefusal::StdoutNotTerminal);
    }
    None
}

/// Check the real process: terminals and environment.
pub fn check_reveal() -> Result<(), RevealRefusal> {
    match reveal_refusal(
        io::stdin().is_terminal(),
        io::stdout().is_terminal(),
        agent_marker(),
    ) {
        Some(refusal) => Err(refusal),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker_from_names(names: &[&'static str]) -> Option<&'static str> {
        marker_from(|name| names.contains(&name))
    }

    #[test]
    fn every_known_marker_marks_an_agent_context() {
        for name in AGENT_MARKERS {
            assert_eq!(marker_from_names(&[name]), Some(name));
        }
    }

    #[test]
    fn unrelated_variables_are_not_agent_markers() {
        assert_eq!(marker_from_names(&[]), None);
        assert_eq!(
            marker_from_names(&["PASSMGR_DB", "HOME", "TERM", "CI"]),
            None
        );
    }

    #[test]
    fn reveal_requires_both_terminals() {
        assert_eq!(reveal_refusal(true, true, None), None);
        assert_eq!(
            reveal_refusal(true, false, None),
            Some(RevealRefusal::StdoutNotTerminal)
        );
        assert_eq!(
            reveal_refusal(false, true, None),
            Some(RevealRefusal::StdinNotTerminal)
        );
        assert_eq!(
            reveal_refusal(false, false, None),
            Some(RevealRefusal::StdinNotTerminal)
        );
    }

    #[test]
    fn agent_marker_wins_over_terminals() {
        assert_eq!(
            reveal_refusal(true, true, Some("PASSMGR_AGENT")),
            Some(RevealRefusal::AgentContext("PASSMGR_AGENT"))
        );
        assert_eq!(
            reveal_refusal(false, false, Some("CLAUDECODE")),
            Some(RevealRefusal::AgentContext("CLAUDECODE"))
        );
    }

    #[test]
    fn refusal_messages_name_the_reason_and_offer_no_bypass() {
        let agent = RevealRefusal::AgentContext("CODEX_SANDBOX").message();
        assert!(agent.contains("agent context"));
        assert!(agent.contains("CODEX_SANDBOX"));

        let stdin = RevealRefusal::StdinNotTerminal.message();
        assert!(stdin.contains("stdin is not a terminal"));

        let stdout = RevealRefusal::StdoutNotTerminal.message();
        assert!(stdout.contains("stdout is not a terminal"));

        for message in [agent, stdin, stdout] {
            assert!(message.contains("no bypass"));
            assert!(!message.contains("--force"));
        }
    }
}
