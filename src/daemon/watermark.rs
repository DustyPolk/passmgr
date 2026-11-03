//! Monotonic grant progress for the lifetime of one daemon (TODO R.44).
//!
//! `pmd` re-reads the vault for every request and remembers nothing about the
//! previous one. The vault is an ordinary 0600 file, so any process running as
//! the same user can put an older copy back -- a backup, a leftover temp file,
//! or a copy taken before a revocation. That older container still opens with
//! the daemon's hot key (the salt and KDF parameters are kept), so without a
//! memory of what was already spent a rollback would undo `revoked_at` and
//! lower `uses`.
//!
//! This module is that memory: per grant id, the furthest progress the daemon
//! has seen. [`GrantWatermarks::check`] rejects a vault that went backwards and
//! [`GrantWatermarks::record`] only ever raises the mark.
//!
//! It is deliberately **not** persisted. A same-user attacker can roll back a
//! marker file exactly like the vault, so persisting it would not be a
//! boundary, and it would become one more artifact to protect. A daemon
//! restart starts with an empty mark; that residual is documented in
//! `SECURITY.md` limit 7.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use crate::grant::{Grant, GrantId};

/// Where a grant's recorded progress went backwards.
///
/// The grant id is metadata (a random public identifier), never a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regression {
    /// The vault records fewer uses than this daemon has already seen.
    Uses { id: GrantId, seen: u32, found: u32 },
    /// The vault no longer records a revocation this daemon has seen.
    Revocation { id: GrantId },
}

/// The furthest state one grant has reached while this daemon has been serving.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Progress {
    uses: u32,
    revoked: bool,
}

impl Progress {
    fn of(grant: &Grant) -> Self {
        Self {
            uses: grant.uses(),
            revoked: grant.is_revoked(),
        }
    }
}

/// In-memory high-water marks, shared by every connection and run worker.
///
/// All access happens while the caller holds the vault write lock (see
/// `record_use` and `revoke_grants`), which serializes daemon writes; the mutex
/// is still needed because the accept loop and the run workers are different
/// threads.
#[derive(Debug, Default)]
pub struct GrantWatermarks {
    seen: Mutex<HashMap<GrantId, Progress>>,
}

impl GrantWatermarks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Refuse a vault that lost uses or a revocation for a grant this daemon
    /// has already seen.
    ///
    /// A grant that is simply absent is not a regression: `pm grant create`
    /// prunes dead grants (TODO R.42), and its mark is kept so that a later
    /// rollback that resurrects it is still caught. Grants the daemon has
    /// never seen have nothing to compare against; a daemon restart therefore
    /// accepts the file as it finds it.
    pub fn check(&self, grants: &[Grant]) -> Result<(), Regression> {
        let seen = self.lock();
        for grant in grants {
            let Some(previous) = seen.get(&grant.id()) else {
                continue;
            };
            if grant.uses() < previous.uses {
                return Err(Regression::Uses {
                    id: grant.id(),
                    seen: previous.uses,
                    found: grant.uses(),
                });
            }
            if previous.revoked && !grant.is_revoked() {
                return Err(Regression::Revocation { id: grant.id() });
            }
        }
        Ok(())
    }

    /// Raise the mark to whatever the vault now holds. Never lowers it, so
    /// recording a rolled-back vault (a revocation that only removes access)
    /// cannot erase what was already seen.
    pub fn record(&self, grants: &[Grant]) {
        let mut seen = self.lock();
        for grant in grants {
            let entry = seen.entry(grant.id()).or_default();
            let now = Progress::of(grant);
            entry.uses = entry.uses.max(now.uses);
            entry.revoked |= now.revoked;
        }
    }

    /// A panic while the mark is held cannot happen, but it must not turn
    /// every later request into a panic either: the map is a plain value, so
    /// recover it.
    fn lock(&self) -> MutexGuard<'_, HashMap<GrantId, Progress>> {
        self.seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use zeroize::Zeroizing;

    use super::*;
    use crate::grant::{Capabilities, GrantSpec, GrantToken, Scope};
    use crate::store::Credential;

    fn grant() -> Grant {
        let credential = Credential::new(
            "example.test".into(),
            "alice".into(),
            Zeroizing::new("not-a-real-secret".into()),
        )
        .expect("credential");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let scope = Scope::new(vec![credential.id()], Vec::new(), None).expect("scope");
        Grant::create(
            GrantSpec {
                label: "watermark test".into(),
                scope,
                commands: vec![PathBuf::from("/bin/true")],
                capabilities: Capabilities::RUN,
                expires_at: now + 3600,
                max_uses: None,
            },
            GrantToken::generate().expect("token").hash(),
            now,
        )
        .expect("grant")
    }

    fn used(grant: &Grant, uses: u32) -> Grant {
        let mut copy = grant.clone();
        for _ in 0..uses {
            copy.mark_used(copy.created_unix() + 1).expect("mark used");
        }
        copy
    }

    #[test]
    fn progress_that_only_moves_forward_is_accepted() {
        let watermarks = GrantWatermarks::new();
        let first = used(&grant(), 2);
        watermarks.record(std::slice::from_ref(&first));

        assert_eq!(watermarks.check(std::slice::from_ref(&first)), Ok(()));
        let later = used(&first, 1);
        assert_eq!(watermarks.check(std::slice::from_ref(&later)), Ok(()));
    }

    #[test]
    fn losing_a_recorded_use_is_a_regression() {
        let watermarks = GrantWatermarks::new();
        let grant = grant();
        let after = used(&grant, 2);
        watermarks.record(std::slice::from_ref(&after));

        assert_eq!(
            watermarks.check(std::slice::from_ref(&grant)),
            Err(Regression::Uses {
                id: grant.id(),
                seen: 2,
                found: 0,
            })
        );
        // Checking never lowers the mark, so the rolled-back value stays
        // refused until the daemon restarts.
        assert!(watermarks.check(std::slice::from_ref(&grant)).is_err());
    }

    #[test]
    fn clearing_a_recorded_revocation_is_a_regression() {
        let watermarks = GrantWatermarks::new();
        let base = grant();
        let mut revoked = base.clone();
        revoked.revoke(revoked.created_unix() + 1).expect("revoke");
        watermarks.record(std::slice::from_ref(&revoked));

        let rolled_back = base;
        assert_eq!(
            watermarks.check(std::slice::from_ref(&rolled_back)),
            Err(Regression::Revocation { id: revoked.id() })
        );
    }

    #[test]
    fn checking_a_later_state_does_not_advance_the_mark() {
        let watermarks = GrantWatermarks::new();
        let base = grant();
        let first = used(&base, 1);
        watermarks.record(std::slice::from_ref(&first));

        // Seen during a check, but not recorded: a subsequent vault with two
        // uses is still allowed, and one with zero is still refused.
        let two = used(&first, 1);
        assert_eq!(watermarks.check(std::slice::from_ref(&two)), Ok(()));
        assert!(watermarks.check(std::slice::from_ref(&base)).is_err());
    }

    #[test]
    fn an_unseen_grant_has_nothing_to_compare() {
        let watermarks = GrantWatermarks::new();
        let known = used(&grant(), 2);
        watermarks.record(std::slice::from_ref(&known));

        let other = grant();
        assert_eq!(watermarks.check(std::slice::from_ref(&other)), Ok(()));
    }

    #[test]
    fn a_pruned_grant_keeps_its_mark() {
        let watermarks = GrantWatermarks::new();
        let base = grant();
        let known = used(&base, 2);
        watermarks.record(std::slice::from_ref(&known));

        // The grant is gone (pruned), which is not a regression ...
        assert_eq!(watermarks.check(&[]), Ok(()));
        // ... and a rollback that resurrects it is still caught.
        assert_eq!(
            watermarks.check(std::slice::from_ref(&base)),
            Err(Regression::Uses {
                id: known.id(),
                seen: 2,
                found: 0,
            })
        );
    }

    #[test]
    fn recording_a_rolled_back_vault_never_lowers_the_mark() {
        let watermarks = GrantWatermarks::new();
        let grant = grant();
        let mut revoked = used(&grant, 3);
        revoked.revoke(revoked.created_unix() + 1).expect("revoke");
        watermarks.record(std::slice::from_ref(&revoked));

        // A revocation may be written against a rolled-back vault; recording
        // that write must not forget the uses or the revocation.
        watermarks.record(std::slice::from_ref(&grant));
        assert!(watermarks.check(std::slice::from_ref(&grant)).is_err());
    }
}
