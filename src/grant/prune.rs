//! Retention policy for dead grants (TODO R.42).
//!
//! Every grant is one record in the capped vault payload, and the cap is on
//! the whole list, not just the usable part. Without pruning, a vault that has
//! held [`super::MAX_GRANTS`] grants in its lifetime would never accept
//! another one: `store::encode` refuses the write and `pm grant create` fails
//! its pre-check ("too many grants") with no way out from the CLI. `pm grant
//! create` therefore drops dead grants before it writes.
//!
//! A grant is dead once it is revoked or expired. It stays in the vault for
//! [`DEAD_GRANT_RETENTION_SECS`] after that, so `pm grant list`/`show` can
//! still explain a recent denial, and the first write after the window may
//! drop it. An **active** grant is never pruned. Neither is an
//! exhausted-but-unexpired one: it has not expired and is not revoked, and
//! its record is the only explanation why its token stopped working.

use super::{Grant, GrantStatus};

/// How long a dead grant stays in the vault after it died (7 days).
pub const DEAD_GRANT_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;

/// Drop every grant that died at least [`DEAD_GRANT_RETENTION_SECS`] before
/// `now`, and return how many were removed.
///
/// Pure and deterministic: the caller supplies `now`, so the policy is
/// testable without a clock. A deadline in the future (a clock that moved
/// backwards) never makes a grant prunable.
///
/// Revocation wins over expiry, exactly as in [`Grant::status`]: a revoked
/// grant is measured from `revoked_at`, even if its `expires_at` is much
/// older.
pub fn prune_dead(grants: &mut Vec<Grant>, now: u64) -> usize {
    let before = grants.len();
    grants.retain(|grant| !dead_before(grant, now));
    before - grants.len()
}

fn dead_before(grant: &Grant, now: u64) -> bool {
    let died = match grant.status(now) {
        GrantStatus::Revoked => grant.revoked_at_unix(),
        GrantStatus::Expired => Some(grant.expires_at_unix()),
        GrantStatus::Active | GrantStatus::Exhausted => None,
    };
    died.is_some_and(|died| now.saturating_sub(died) >= DEAD_GRANT_RETENTION_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{Capabilities, GrantSpec, Scope, TokenHash};
    use crate::store::EntryId;
    use std::path::PathBuf;

    const NOW: u64 = 1_800_000_000;

    /// A run grant created at `created` that expires `lifetime` seconds later.
    fn grant(label: &str, created: u64, lifetime: u64, max_uses: Option<u32>) -> Grant {
        let entry = EntryId::generate().unwrap();
        Grant::create(
            GrantSpec {
                label: label.to_owned(),
                scope: Scope::new(vec![entry], Vec::new(), None).unwrap(),
                commands: vec![PathBuf::from("/usr/bin/true")],
                capabilities: Capabilities::RUN,
                expires_at: created + lifetime,
                max_uses,
            },
            TokenHash::of(label.as_bytes()),
            created,
        )
        .unwrap()
    }

    /// A grant whose expiry is `died` seconds before `NOW`.
    fn expired(label: &str, died: u64) -> Grant {
        let expires_at = NOW - died;
        grant(label, expires_at - 3_600, 3_600, None)
    }

    fn revoked(label: &str, died: u64) -> Grant {
        let mut grant = grant(label, NOW - 7_200, 3_600, None);
        grant.revoke(NOW - died).unwrap();
        grant
    }

    #[test]
    fn only_dead_grants_past_the_retention_window_are_pruned() {
        let mut grants = vec![
            // Live: never pruned, however old the grant is.
            grant("active", NOW - 100, 3_600, None),
            // Dead but inside the window: still shown by `grant list`.
            expired("expired fresh", DEAD_GRANT_RETENTION_SECS - 1),
            revoked("revoked fresh", 60),
            // Dead past the window: pruned.
            expired("expired old", DEAD_GRANT_RETENTION_SECS),
            revoked("revoked old", DEAD_GRANT_RETENTION_SECS + 86_400),
        ];
        // An exhausted grant has not expired, so it is not prunable.
        let mut exhausted = grant("exhausted", NOW - 100, 3_600, Some(1));
        exhausted.mark_used(NOW - 50).unwrap();
        grants.push(exhausted);

        assert_eq!(prune_dead(&mut grants, NOW), 2);
        let labels: Vec<&str> = grants.iter().map(Grant::label).collect();
        assert_eq!(
            labels,
            ["active", "expired fresh", "revoked fresh", "exhausted"]
        );
    }

    #[test]
    fn a_dead_grant_is_kept_until_the_window_has_fully_passed() {
        let mut grants = vec![expired("boundary", DEAD_GRANT_RETENTION_SECS - 1)];

        // One second short of the window: kept.
        assert_eq!(prune_dead(&mut grants, NOW), 0);
        // Exactly at the window: dropped.
        assert_eq!(prune_dead(&mut grants, NOW + 1), 1);
        assert!(grants.is_empty());
    }

    #[test]
    fn a_deadline_in_the_future_never_prunes() {
        // A clock that moved backwards can leave `revoked_at` (or an expiry
        // that was valid when written) ahead of `now`; the saturating
        // subtraction treats that as "not yet".
        let mut revoked_ahead = grant("revoked ahead", NOW - 7_200, 3_600, None);
        revoked_ahead.revoke(NOW + 3_600).unwrap();
        let expired_ahead = grant("expires ahead", NOW, 3_600, None);
        let mut grants = vec![revoked_ahead, expired_ahead];

        assert_eq!(prune_dead(&mut grants, NOW), 0);
        assert_eq!(grants.len(), 2);
    }
}
