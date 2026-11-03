//! The canonical form of a grant-creation request.
//!
//! A human approves a grant by proving knowledge of the vault key over a
//! digest of the exact request (TODO 3.3). The CLI and the daemon must
//! therefore agree, byte for byte, on how a request is serialized: a proof for
//! one request must never authorize another. [`GrantRequest`] normalizes every
//! field once, and [`GrantRequest::digest`] hashes a length-prefixed encoding
//! of that normalized form.
//!
//! The digest covers the fields that grant access, plus the token hash. It
//! deliberately does not cover the grant id or the creation time: the writer
//! assigns those at write time, and neither can widen what the human approved.
//!
//! Encoding (all integers big-endian):
//!
//! | field                          | encoding                    |
//! |--------------------------------|-----------------------------|
//! | domain                         | `u32` length + bytes        |
//! | label                          | `u32` length + UTF-8        |
//! | refs                           | `u32` count + 16 raw bytes  |
//! | tags                           | `u32` count + strings       |
//! | fields                         | `0`, or `1` + strings       |
//! | commands                       | `u32` count + strings       |
//! | capabilities                   | one byte of bits            |
//! | expiry                         | `u64` Unix seconds          |
//! | max uses                       | `0`, or `1` + `u32`         |
//! | token hash                     | `u32` length + 32 bytes     |
//!
//! A "string" is a `u32` byte length followed by its UTF-8 bytes. Every
//! variable-length field is length-prefixed, so moving a byte between two
//! fields cannot produce the same digest.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::presence::RequestDigest;
use crate::store::MAX_TIMESTAMP_UNIX;

use super::validate::{validate_commands, validate_label};
use super::{Capabilities, Grant, GrantSpec, Scope, TokenHash};

/// Domain separator and digest version. A change to the encoding must change
/// this string, so approvals minted by a different build never match.
const DIGEST_DOMAIN: &[u8] = b"passmgr-grant-create-v1";

/// A validated, normalized grant-creation request.
///
/// Construction is the only way to make one, and it applies every rule
/// [`Grant::create`] applies that does not need the clock. `create_grant`
/// therefore writes exactly the fields the digest covered.
#[derive(Clone, Debug)]
pub struct GrantRequest {
    label: String,
    scope: Scope,
    /// Canonical absolute UTF-8 paths, sorted and deduplicated.
    commands: Vec<String>,
    capabilities: Capabilities,
    expires_at: u64,
    max_uses: Option<u32>,
    token_hash: TokenHash,
}

impl GrantRequest {
    /// Validate and normalize `spec`, then bind it to `token_hash`.
    ///
    /// Expiry is not checked against the clock here: the daemon does that at
    /// write time with its own clock. This function rejects only shapes that
    /// no moment could make valid, so the CLI and the daemon always normalize
    /// the same input to the same request.
    pub fn new(spec: GrantSpec, token_hash: TokenHash) -> Result<Self> {
        validate_label(&spec.label)?;
        if spec.capabilities.is_empty() {
            return Err(Error::InvalidInput(
                "a grant needs at least one capability".into(),
            ));
        }
        let commands = validate_commands(spec.commands)?;
        if spec.capabilities.contains(Capabilities::RUN) && commands.is_empty() {
            return Err(Error::InvalidInput(
                "a run grant needs at least one allowed command".into(),
            ));
        }
        if spec.max_uses == Some(0) {
            return Err(Error::InvalidInput(
                "max_uses must be at least 1; omit it for no limit".into(),
            ));
        }
        if spec.expires_at > MAX_TIMESTAMP_UNIX {
            return Err(Error::InvalidInput(format!(
                "grant expiry {} exceeds the maximum of {MAX_TIMESTAMP_UNIX} Unix seconds",
                spec.expires_at
            )));
        }
        let commands = commands
            .into_iter()
            .map(|path| {
                path.into_os_string()
                    .into_string()
                    .map_err(|_| Error::InvalidInput("a grant command must be valid UTF-8".into()))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            label: spec.label,
            scope: spec.scope,
            commands,
            capabilities: spec.capabilities,
            expires_at: spec.expires_at,
            max_uses: spec.max_uses,
            token_hash,
        })
    }

    /// The digest a human's presence proof must cover for this exact request.
    pub fn digest(&self) -> RequestDigest {
        let mut encoded = Vec::new();
        write_bytes(&mut encoded, DIGEST_DOMAIN);
        write_bytes(&mut encoded, self.label.as_bytes());

        write_u32(&mut encoded, self.scope.refs().len() as u32);
        for id in self.scope.refs() {
            encoded.extend_from_slice(id.as_bytes());
        }
        write_strings(&mut encoded, self.scope.tags());
        match self.scope.fields() {
            None => encoded.push(0),
            Some(fields) => {
                encoded.push(1);
                write_strings(&mut encoded, fields);
            }
        }
        write_strings(&mut encoded, &self.commands);

        encoded.push(self.capabilities.bits());
        encoded.extend_from_slice(&self.expires_at.to_be_bytes());
        match self.max_uses {
            None => encoded.push(0),
            Some(max_uses) => {
                encoded.push(1);
                write_u32(&mut encoded, max_uses);
            }
        }
        write_bytes(&mut encoded, self.token_hash.as_bytes());

        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        RequestDigest::new(hasher.finalize().into())
    }

    /// Build the grant this request describes, assigning a fresh id and
    /// `now` as the creation time.
    pub fn create_grant(self, now: u64) -> Result<Grant> {
        Grant::create(
            GrantSpec {
                label: self.label,
                scope: self.scope,
                commands: self.commands.into_iter().map(PathBuf::from).collect(),
                capabilities: self.capabilities,
                expires_at: self.expires_at,
                max_uses: self.max_uses,
            },
            self.token_hash,
            now,
        )
    }
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn write_strings(out: &mut Vec<u8>, values: &[String]) {
    write_u32(out, values.len() as u32);
    for value in values {
        write_bytes(out, value.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    use super::*;
    use crate::grant::MAX_GRANT_LIFETIME_SECS;
    use crate::store::EntryId;

    const NOW: u64 = 1_700_000_000;
    const TOKEN: &[u8] = b"canary-grant-request-token-do-not-print";

    fn ref_id(seed: u8) -> EntryId {
        EntryId::from_hex(&format!("{seed:02x}").repeat(16)).expect("valid id")
    }

    fn spec() -> GrantSpec {
        GrantSpec {
            label: "deploy prod".into(),
            scope: Scope::new(vec![ref_id(1)], vec!["prod".into()], None).expect("scope"),
            commands: vec![PathBuf::from("/usr/bin/gh")],
            capabilities: Capabilities::RUN,
            expires_at: NOW + 3_600,
            max_uses: Some(2),
        }
    }

    fn request() -> GrantRequest {
        GrantRequest::new(spec(), TokenHash::of(TOKEN)).expect("request")
    }

    fn digest_of(spec: GrantSpec) -> String {
        GrantRequest::new(spec, TokenHash::of(TOKEN))
            .expect("request")
            .digest()
            .to_hex()
    }

    #[test]
    fn normalization_is_visible_in_the_digest() {
        let mut reordered = spec();
        reordered.scope = Scope::new(
            vec![ref_id(1), ref_id(1)],
            vec!["prod".into(), "prod".into()],
            None,
        )
        .expect("scope");
        reordered.commands = vec![PathBuf::from("/usr/bin/gh"), PathBuf::from("/usr/bin/gh")];
        reordered.max_uses = Some(2);
        assert_eq!(request().digest().to_hex(), digest_of(reordered));

        let grant = GrantRequest::new(
            {
                let mut spec = spec();
                spec.commands = vec![
                    PathBuf::from("/usr/bin/gh"),
                    PathBuf::from("/usr/bin/curl"),
                    PathBuf::from("/usr/bin/gh"),
                ];
                spec
            },
            TokenHash::of(TOKEN),
        )
        .expect("request")
        .create_grant(NOW)
        .expect("grant");
        assert_eq!(
            grant.commands(),
            [PathBuf::from("/usr/bin/curl"), PathBuf::from("/usr/bin/gh")]
        );
    }

    #[test]
    fn every_security_relevant_field_changes_the_digest() {
        let base = request().digest().to_hex();
        let mut seen = std::collections::BTreeSet::new();
        seen.insert(base.clone());

        let mut variants = Vec::new();
        variants.push({
            let mut spec = spec();
            spec.label = "deploy staging".into();
            spec
        });
        variants.push({
            let mut spec = spec();
            spec.scope = Scope::new(vec![ref_id(2), ref_id(1)], Vec::new(), None).unwrap();
            spec
        });
        variants.push({
            let mut spec = spec();
            spec.scope =
                Scope::new(vec![ref_id(1)], vec!["prod".into(), "staging".into()], None).unwrap();
            spec
        });
        variants.push({
            let mut spec = spec();
            spec.scope = Scope::new(
                vec![ref_id(1)],
                vec!["prod".into()],
                Some(vec!["password".into()]),
            )
            .unwrap();
            spec
        });
        variants.push({
            let mut spec = spec();
            spec.commands = vec![PathBuf::from("/usr/bin/curl")];
            spec
        });
        variants.push({
            let mut spec = spec();
            spec.capabilities = Capabilities::RUN.union(Capabilities::LIST);
            spec
        });
        variants.push({
            let mut spec = spec();
            spec.expires_at += 1;
            spec
        });
        variants.push({
            let mut spec = spec();
            spec.max_uses = None;
            spec
        });
        variants.push({
            let mut spec = spec();
            spec.max_uses = Some(3);
            spec
        });
        for spec in variants {
            assert!(
                seen.insert(digest_of(spec)),
                "two different requests produced the same digest"
            );
        }

        let other_token = GrantRequest::new(spec(), TokenHash::of(b"another token"))
            .expect("request")
            .digest()
            .to_hex();
        assert!(seen.insert(other_token));
    }

    #[test]
    fn length_prefixes_keep_field_boundaries() {
        let first = {
            let mut spec = spec();
            spec.label = "ab".into();
            spec.scope = Scope::new(vec![ref_id(1)], vec!["c".into()], None).unwrap();
            spec
        };
        let second = {
            let mut spec = spec();
            spec.label = "a".into();
            spec.scope = Scope::new(vec![ref_id(1)], vec!["bc".into()], None).unwrap();
            spec
        };
        assert_ne!(digest_of(first), digest_of(second));

        let first = {
            let mut spec = spec();
            spec.commands = vec![PathBuf::from("/a"), PathBuf::from("/bc")];
            spec
        };
        let second = {
            let mut spec = spec();
            spec.commands = vec![PathBuf::from("/ab"), PathBuf::from("/c")];
            spec
        };
        assert_ne!(digest_of(first), digest_of(second));
    }

    /// Pins the byte-level encoding. If this fails, the encoding (or its
    /// domain string) changed, and every approval minted by an older build
    /// must be considered invalid. Bump `DIGEST_DOMAIN` deliberately.
    #[test]
    fn canonical_encoding_is_pinned() {
        let mut spec = spec();
        spec.scope = Scope::new(
            vec![ref_id(1)],
            vec!["prod".into()],
            Some(vec!["password".into()]),
        )
        .unwrap();
        spec.commands = vec![PathBuf::from("/usr/bin/gh"), PathBuf::from("/usr/bin/curl")];
        let request = GrantRequest::new(spec, TokenHash::of(TOKEN)).expect("request");
        assert_eq!(
            request.digest().to_hex(),
            "990b4f86e6beb2ba1329987a7abfd511dc4a8b93ba653cf6359a9455fd4f9e1d"
        );
    }

    #[test]
    fn invalid_shapes_are_refused() {
        let mut no_commands = spec();
        no_commands.commands.clear();
        assert!(GrantRequest::new(no_commands, TokenHash::of(TOKEN)).is_err());

        let mut no_capabilities = spec();
        no_capabilities.capabilities = Capabilities::NONE;
        assert!(GrantRequest::new(no_capabilities, TokenHash::of(TOKEN)).is_err());

        let mut zero_uses = spec();
        zero_uses.max_uses = Some(0);
        assert!(GrantRequest::new(zero_uses, TokenHash::of(TOKEN)).is_err());

        let mut too_late = spec();
        too_late.expires_at = MAX_TIMESTAMP_UNIX + 1;
        assert!(GrantRequest::new(too_late, TokenHash::of(TOKEN)).is_err());

        let mut bad_label = spec();
        bad_label.label = "deploy\u{202e}prod".into();
        assert!(GrantRequest::new(bad_label, TokenHash::of(TOKEN)).is_err());

        let mut bad_command = spec();
        bad_command.commands = vec![PathBuf::from(OsStr::from_bytes(b"/bad\xff"))];
        assert!(GrantRequest::new(bad_command, TokenHash::of(TOKEN)).is_err());
    }

    #[test]
    fn create_grant_writes_exactly_the_requested_fields() {
        let token_hash = TokenHash::of(TOKEN);
        let grant = GrantRequest::new(spec(), token_hash)
            .expect("request")
            .create_grant(NOW)
            .expect("grant");
        assert_eq!(grant.label(), "deploy prod");
        assert_eq!(grant.scope().refs(), [ref_id(1)]);
        assert_eq!(grant.scope().tags(), ["prod"]);
        assert_eq!(grant.scope().fields(), None);
        assert_eq!(grant.commands(), [PathBuf::from("/usr/bin/gh")]);
        assert_eq!(grant.capabilities(), Capabilities::RUN);
        assert_eq!(grant.expires_at_unix(), NOW + 3_600);
        assert_eq!(grant.max_uses(), Some(2));
        assert_eq!(grant.uses(), 0);
        assert_eq!(grant.created_unix(), NOW);
        assert!(grant.token_hash().matches(&token_hash));

        let mut past = spec();
        past.expires_at = NOW;
        assert!(
            GrantRequest::new(past, token_hash)
                .expect("request")
                .create_grant(NOW)
                .is_err()
        );

        let mut too_long = spec();
        too_long.expires_at = NOW + MAX_GRANT_LIFETIME_SECS + 1;
        assert!(
            GrantRequest::new(too_long, token_hash)
                .expect("request")
                .create_grant(NOW)
                .is_err()
        );
    }

    #[test]
    fn debug_never_prints_the_token_hash() {
        let hash = TokenHash::of(TOKEN);
        let hex: String = hash.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let debug = format!("{:?}", request());
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains(&hex), "{debug}");
        assert!(!debug.contains(std::str::from_utf8(TOKEN).unwrap()));
    }
}
