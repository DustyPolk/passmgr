//! Capability bits a grant can carry.
//!
//! Split out of `src/grant.rs` by TODO 3.4c to keep that file under the
//! ~1,000-line limit. The types and behavior are unchanged.

use std::fmt;

use crate::error::{Error, Result};

/// A single capability an agent may exercise. New capabilities are new
/// variants plus a bit, never a reuse of an existing bit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Capability {
    /// Read names, usernames, tags and field names inside the scope.
    List,
    /// Run a command with secrets injected.
    Run,
}

impl Capability {
    /// The stable name used in JSON, the audit log and error messages.
    pub fn name(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Run => "run",
        }
    }

    /// The single-bit flag this capability needs from a grant.
    pub fn flag(self) -> Capabilities {
        match self {
            Self::List => Capabilities::LIST,
            Self::Run => Capabilities::RUN,
        }
    }
}

/// A set of capabilities, stored as a bit field so the vault format can grow
/// by one bit at a time.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Capabilities(u8);

impl Capabilities {
    pub const NONE: Self = Self(0);
    pub const LIST: Self = Self(0b0001);
    pub const RUN: Self = Self(0b0010);
    /// Every bit this build understands. A stored value with any other bit is
    /// refused rather than silently ignored.
    pub const KNOWN: u8 = Self::LIST.0 | Self::RUN.0;

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// True when every capability in `other` is present.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    /// Rebuild a set from stored bits. Unknown bits and the empty set are
    /// refused, so a corrupt or newer record cannot grant a capability this
    /// build does not implement.
    pub fn from_bits(bits: u8) -> Result<Self> {
        if bits == 0 {
            return Err(Error::InvalidInput(
                "a grant needs at least one capability".into(),
            ));
        }
        if bits & !Self::KNOWN != 0 {
            return Err(Error::InvalidInput(format!(
                "unknown grant capability bits {:#04b}",
                bits & !Self::KNOWN
            )));
        }
        Ok(Self(bits))
    }

    /// The capability names in a stable order, for `--json` and `pm grant show`.
    pub fn names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.contains(Self::LIST) {
            names.push(Capability::List.name());
        }
        if self.contains(Self::RUN) {
            names.push(Capability::Run.name());
        }
        names
    }
}

impl fmt::Debug for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.names()).finish()
    }
}
