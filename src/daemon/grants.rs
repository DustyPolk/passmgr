use std::path::Path;

use crate::grant::{AccessRequest, Denied, Grant, GrantId, GrantToken, Target};
use crate::protocol::{
    self, DescribeRequest, GrantRevokeRequest, ListRequest, Response, ResponseError,
};
use crate::store::EntryId;
use crate::vault::Vault;

use super::watermark::GrantWatermarks;
use super::{LockedKey, unix_now};

/// Answer a `list` request with the metadata of the entries its grant covers.
///
/// The order is deliberate:
///
/// 1. the grant must be active and carry the `list` capability, so a revoked,
///    expired, exhausted or `run`-only grant is `denied` even when the vault
///    is empty;
/// 2. the grant state must not have gone backwards (TODO R.44), because a
///    rollback must not resurrect a listing the human revoked;
/// 3. every credential is authorized **on its own** with
///    [`Grant::authorizes`], so tags, fields and references scope the answer
///    exactly as they scope `run`, and an out-of-scope entry is skipped rather
///    than reported;
/// 4. the tag and query filters narrow that set. They are applied after the
///    authorization, so no filter can widen access.
///
/// Only [`Entry::from_credential`](protocol::Entry::from_credential) is used to
/// build the answer: it never reads the password. The vault is opened
/// read-only and lock-free, which is safe because a save is an atomic rename
/// of a complete file.
pub(super) fn list_entries(
    vault_path: &Path,
    key: &LockedKey,
    watermarks: &GrantWatermarks,
    request: &ListRequest,
) -> Response {
    let Some(now) = unix_now() else {
        return Response::Error(ResponseError::Internal);
    };
    let vault = match Vault::open_with_key(vault_path, key.as_slice()) {
        Ok(vault) => vault,
        Err(_) => return Response::Error(ResponseError::Internal),
    };
    let grant = match metadata_grant(&vault, &request.grant, watermarks, now) {
        Ok(grant) => grant,
        Err(error) => return Response::Error(error),
    };
    let mut entries = Vec::new();
    for credential in vault.list() {
        let target = Target::new(credential.id(), credential.tags());
        match grant.authorizes(&AccessRequest::list(target, None), now) {
            Ok(()) => {}
            Err(Denied::OutOfScope) => continue,
            // The grant-level checks above already passed; any other denial
            // means the state changed underneath us. Fail closed.
            Err(_) => return Response::Error(ResponseError::Denied),
        }
        if !protocol::entry::matches_filters(credential, &request.tags, request.query.as_deref()) {
            continue;
        }
        entries.push(protocol::Entry::from_credential(credential));
    }
    let (entries, truncated) = protocol::entry::fit_entries(entries);
    Response::Entries { entries, truncated }
}

/// Answer a `describe` request with the metadata of one entry its grant covers.
///
/// The order is the same as [`list_entries`]: grant state and `list`
/// capability, then the rollback watermark, then the per-candidate scope check.
/// A reference outside the grant is answered exactly like one that does not
/// exist (`not_found`), so the response is not an existence oracle. Only
/// [`protocol::Entry::from_credential`] is used to build the answer, and it
/// never reads the password.
pub(super) fn describe_entry(
    vault_path: &Path,
    key: &LockedKey,
    watermarks: &GrantWatermarks,
    request: &DescribeRequest,
) -> Response {
    let Some(now) = unix_now() else {
        return Response::Error(ResponseError::Internal);
    };
    let vault = match Vault::open_with_key(vault_path, key.as_slice()) {
        Ok(vault) => vault,
        Err(_) => return Response::Error(ResponseError::Internal),
    };
    let grant = match metadata_grant(&vault, &request.grant, watermarks, now) {
        Ok(grant) => grant,
        Err(error) => return Response::Error(error),
    };
    // The protocol validates this already; treating a malformed reference as
    // missing keeps the answer free of any parse detail.
    let Ok(id) = EntryId::parse_ref(&request.reference) else {
        return Response::Error(ResponseError::NotFound);
    };
    let Some(credential) = vault.get_by_ref(id) else {
        return Response::Error(ResponseError::NotFound);
    };
    let target = Target::new(credential.id(), credential.tags());
    match grant.authorizes(&AccessRequest::list(target, None), now) {
        Ok(()) => Response::Entry(protocol::Entry::from_credential(credential)),
        // Deliberately identical to the two `not_found` answers above.
        Err(Denied::OutOfScope) => Response::Error(ResponseError::NotFound),
        // The grant-level checks already passed; any other denial means the
        // state changed underneath us. Fail closed.
        Err(_) => Response::Error(ResponseError::Denied),
    }
}

/// The grant-level half of a metadata read (`list`/`describe`).
///
/// Finds the grant by the token's hash, requires it to be active with the
/// `list` capability, and refuses a vault whose grant state went backwards
/// (TODO R.44). No credential is looked at here, so the answer does not depend
/// on which entries exist.
///
/// What was read is recorded first, whatever the answer: a revocation the
/// daemon only ever saw while denying a read is still one it has seen, and
/// recording never lowers a mark.
fn metadata_grant<'v>(
    vault: &'v Vault,
    token: &GrantToken,
    watermarks: &GrantWatermarks,
    now: u64,
) -> Result<&'v Grant, ResponseError> {
    watermarks.record(vault.grants());
    let token_hash = token.hash();
    let grant = vault
        .grants()
        .iter()
        .find(|grant| grant.matches_token(&token_hash))
        .ok_or(ResponseError::Denied)?;
    grant
        .check_grant_for_metadata(now)
        .map_err(|_| ResponseError::Denied)?;
    watermarks
        .check(vault.grants())
        .map_err(|_| ResponseError::Denied)?;
    Ok(grant)
}

/// Revoke one grant or every active grant, returning how many were newly
/// revoked.
///
/// The vault is opened with the daemon's hot key **under the write lock**, so
/// the state it revokes is the state on disk and no concurrent run that records
/// a use can make it answer `internal` (TODO R.39). It is saved with
/// [`Vault::save_with_key`] so the salt and KDF parameters (and therefore the
/// key itself) stay valid. When no grant needs changing, nothing is written at
/// all.
///
/// Revocation is the one write **not** refused on a vault whose grant state
/// regressed (TODO R.44): a rollback must not be able to disable the kill
/// switch, and a revocation only ever removes access. Recording it never
/// lowers the watermark. The state that was read is recorded before any early
/// return, so a revocation made by another process and seen here only as a
/// no-op is remembered too.
pub(super) fn revoke_grants(
    path: &Path,
    key: &LockedKey,
    watermarks: &GrantWatermarks,
    request: GrantRevokeRequest,
    now: u64,
) -> Result<u32, ResponseError> {
    let mut vault = Vault::open_with_key_for_update(path, key.as_slice())
        .map_err(|_| ResponseError::Internal)?;
    watermarks.record(vault.grants());
    let targets: Vec<GrantId> = match request {
        GrantRevokeRequest::Id(id) => {
            if vault.grant(id).is_none() {
                return Err(ResponseError::NotFound);
            }
            vec![id]
        }
        GrantRevokeRequest::All => vault
            .grants()
            .iter()
            .filter(|grant| grant.is_active(now))
            .map(|grant| grant.id())
            .collect(),
    };
    if targets.is_empty() {
        return Ok(0);
    }

    let mut revoked = 0u32;
    for id in targets {
        let grant = vault.grant_mut(id).ok_or(ResponseError::Internal)?;
        if grant.is_revoked() {
            continue;
        }
        grant.revoke(now).map_err(|_| ResponseError::Internal)?;
        revoked = revoked.saturating_add(1);
    }
    if revoked == 0 {
        return Ok(0);
    }
    vault
        .save_with_key(key.as_slice())
        .map_err(|_| ResponseError::Internal)?;
    watermarks.record(vault.grants());
    Ok(revoked)
}
