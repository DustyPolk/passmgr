//! Human-versus-agent context detection.
//!
//! The agent-facing surface never returns plaintext. Plaintext reveal
//! (`get --reveal`) is reserved for a human sitting at a terminal, so a reveal
//! must satisfy both conditions:
//!
//! 1. stdin *and* stdout are terminals, and
//! 2. no agent environment marker is present and the global `--agent` flag was
//!    not passed.
//!
//! There is deliberately no flag that bypasses this check. The `--agent` flag
//! can only *add* refusal, never remove it. The decision lives here, in one
//! place, so that every future plaintext path (clipboard, export) can reuse it.

use std::env;
use std::io::{self, IsTerminal};

/// Environment variables that indicate the caller is an automated agent.
///
/// Presence alone counts, even with an empty value: an inherited marker is
/// treated as an agent context, which is the conservative choice. The CLI's
/// global `--agent` flag forces the same state via [`AgentSource::Flag`].
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

/// Where the "this is an agent context" signal came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSource {
    /// An agent environment marker was found; carries the marker name.
    Env(&'static str),
    /// The global `--agent` flag was passed.
    Flag,
}

impl AgentSource {
    /// Human-readable description of the signal. Never contains secret material.
    fn describe(self) -> String {
        match self {
            Self::Env(name) => format!("{name} is set"),
            Self::Flag => "the --agent flag was passed".to_owned(),
        }
    }
}

/// Why a plaintext reveal was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealRefusal {
    /// The process is in an agent context; carries the signal's source.
    AgentContext(AgentSource),
    /// stdin is not a terminal, so a human cannot be typing here.
    StdinNotTerminal,
    /// stdout is not a terminal, so the value would be captured by a pipe.
    StdoutNotTerminal,
}

impl RevealRefusal {
    /// Human-readable refusal reason for a plaintext reveal.
    ///
    /// Never contains secret material.
    pub fn message(self) -> String {
        self.message_for("reveal a secret")
    }

    /// Human-readable refusal reason for any human-only `action` (for example
    /// `"reveal a secret"` or `"start the unlock daemon"`).
    ///
    /// Never contains secret material.
    pub fn message_for(self, action: &str) -> String {
        match self {
            Self::AgentContext(source) => format!(
                "refusing to {action} in an agent context ({}); \
                 this is reserved for a human at a terminal and has no bypass",
                source.describe()
            ),
            Self::StdinNotTerminal => format!(
                "refusing to {action}: stdin is not a terminal; \
                 this is reserved for a human at a terminal and has no bypass"
            ),
            Self::StdoutNotTerminal => format!(
                "refusing to {action}: stdout is not a terminal; \
                 this is reserved for a human at a terminal and has no bypass"
            ),
        }
    }
}

/// Pure decision function for a plaintext reveal.
///
/// Precedence is agent context first, then stdin, then stdout, so the reported
/// reason names the strongest problem. An agent environment marker is reported
/// ahead of `--agent` when both are present, because it can be inherited
/// unintentionally and is the more surprising of the two.
pub fn reveal_refusal(
    stdin_is_tty: bool,
    stdout_is_tty: bool,
    source: Option<AgentSource>,
) -> Option<RevealRefusal> {
    if let Some(source) = source {
        return Some(RevealRefusal::AgentContext(source));
    }
    if !stdin_is_tty {
        return Some(RevealRefusal::StdinNotTerminal);
    }
    if !stdout_is_tty {
        return Some(RevealRefusal::StdoutNotTerminal);
    }
    None
}

/// Resolve the agent signal from the environment and the `--agent` flag.
///
/// The flag can only add refusal: passing `false` changes nothing, passing
/// `true` refuses even when the environment is clean.
pub fn agent_source(agent_flag: bool) -> Option<AgentSource> {
    agent_marker().map(AgentSource::Env).or(if agent_flag {
        Some(AgentSource::Flag)
    } else {
        None
    })
}

/// Check the real process: terminals, environment and the `--agent` flag.
///
/// This is the shared gate for every human-only operation (plaintext reveal,
/// starting the unlock daemon). It cannot be weakened by a flag: `--agent`
/// only adds refusal.
pub fn check_human(agent_flag: bool) -> Result<(), RevealRefusal> {
    match reveal_refusal(
        io::stdin().is_terminal(),
        io::stdout().is_terminal(),
        agent_source(agent_flag),
    ) {
        Some(refusal) => Err(refusal),
        None => Ok(()),
    }
}

/// Check the real process for a plaintext reveal.
pub fn check_reveal(agent_flag: bool) -> Result<(), RevealRefusal> {
    check_human(agent_flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker_from_names(names: &[&'static str]) -> Option<&'static str> {
        marker_from(|name| names.contains(&name))
    }

    fn env_source(marker: &'static str) -> Option<AgentSource> {
        Some(AgentSource::Env(marker))
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
            reveal_refusal(true, true, env_source("PASSMGR_AGENT")),
            Some(RevealRefusal::AgentContext(AgentSource::Env(
                "PASSMGR_AGENT"
            )))
        );
        assert_eq!(
            reveal_refusal(false, false, env_source("CLAUDECODE")),
            Some(RevealRefusal::AgentContext(AgentSource::Env("CLAUDECODE")))
        );
    }

    #[test]
    fn the_agent_flag_refuses_even_with_two_terminals() {
        assert_eq!(
            reveal_refusal(true, true, agent_source(true)),
            Some(RevealRefusal::AgentContext(AgentSource::Flag))
        );
        assert_eq!(
            reveal_refusal(false, true, agent_source(true)),
            Some(RevealRefusal::AgentContext(AgentSource::Flag))
        );
    }

    #[test]
    fn the_agent_flag_cannot_weaken_the_check() {
        // Without the flag, the decision is unchanged.
        assert_eq!(agent_source(false), None);
        assert_eq!(reveal_refusal(true, true, agent_source(false)), None);
        assert_eq!(
            reveal_refusal(false, true, agent_source(false)),
            Some(RevealRefusal::StdinNotTerminal)
        );
    }

    #[test]
    fn an_environment_marker_is_reported_before_the_flag() {
        // Simulated: the environment lookup wins, so the message names the
        // marker a reviewer can inspect and remove.
        let inherited = marker_from(|name| name == "CURSOR_AGENT").map(AgentSource::Env);
        assert_eq!(
            reveal_refusal(true, true, inherited.or(Some(AgentSource::Flag))),
            Some(RevealRefusal::AgentContext(AgentSource::Env(
                "CURSOR_AGENT"
            )))
        );
    }

    #[test]
    fn refusal_messages_name_the_reason_and_offer_no_bypass() {
        let agent = RevealRefusal::AgentContext(AgentSource::Env("CODEX_SANDBOX")).message();
        assert!(agent.contains("agent context"));
        assert!(agent.contains("CODEX_SANDBOX"));

        let flag = RevealRefusal::AgentContext(AgentSource::Flag).message();
        assert!(flag.contains("agent context"));
        assert!(flag.contains("--agent"));

        let stdin = RevealRefusal::StdinNotTerminal.message();
        assert!(stdin.contains("stdin is not a terminal"));

        let stdout = RevealRefusal::StdoutNotTerminal.message();
        assert!(stdout.contains("stdout is not a terminal"));

        for message in [agent, flag, stdin, stdout] {
            assert!(message.contains("no bypass"));
            assert!(!message.contains("--force"));
        }

        // A non-reveal human-only action names itself in the refusal.
        let unlock = RevealRefusal::StdinNotTerminal.message_for("start the unlock daemon");
        assert!(unlock.contains("start the unlock daemon"));
        assert!(unlock.contains("stdin is not a terminal"));
        assert!(unlock.contains("no bypass"));
    }
}
