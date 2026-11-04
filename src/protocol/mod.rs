//! Wire protocol between `pm` and the unlock daemon (`pmd`).
//!
//! The transport is a Unix socket (TODO 2.2), so the protocol has to frame
//! messages itself. Every frame is a 4-byte big-endian length followed by that
//! many bytes of UTF-8 JSON:
//!
//! ```text
//! u32 length | length bytes of JSON
//! ```
//!
//! The JSON envelope is `{"version":4,"token":"<64 hex>","request":{...}}`.
//! The `token` is the unlock session token (see [`crate::token`]) and is
//! required on every request; the daemon rejects a missing or mismatched one
//! with `unauthorized`. The `request` object always has a `"type"` field; the
//! types this version knows are `ping`, `lock`, `run`, `list`, `describe`,
//! `challenge`, `prove`, `grant_create` and `grant_revoke`:
//!
//! ```json
//! {"version":4,"token":"...","request":{"type":"ping"}}
//! {"version":4,"token":"...","request":{"type":"lock"}}
//! {"version":4,"token":"...","request":{"type":"run","env":"API_KEY",
//!                         "ref":"pm://00112233445566778899aabbccddeeff",
//!                         "grant":"<64 lowercase hex>",
//!                         "command":["/usr/bin/curl","-s","https://example.test"],
//!                         "cwd":"/home/alice/project"}}
//! {"version":4,"token":"...","request":{"type":"list","tags":["prod"],
//!                         "query":"gh","grant":"<64 lowercase hex>"}}
//! {"version":4,"token":"...","request":{"type":"describe",
//!                         "ref":"pm://00112233445566778899aabbccddeeff",
//!                         "grant":"<64 lowercase hex>"}}
//! {"version":4,"token":"...","request":{"type":"challenge"}}
//! {"version":4,"token":"...","request":{"type":"prove","nonce":"<64 hex>",
//!                         "digest":"<64 hex>","proof":"<64 hex>"}}
//! {"version":4,"token":"...","request":{"type":"grant_create",
//!                         "label":"deploy","refs":["pm://..."],"tags":[],
//!                         "fields":["password"],"commands":["/usr/bin/gh"],
//!                         "capabilities":2,"expires_at":1700003600,
//!                         "max_uses":2,"token_hash":"<64 hex>"}}
//! {"version":4,"token":"...","request":{"type":"grant_revoke",
//!                         "id":"<32 hex>"}}
//! {"version":4,"token":"...","request":{"type":"grant_revoke",
//!                         "all":true}}
//! ```
//!
//! The sketch above is illustrative; the exact `grant_create` body, byte for
//! byte, is pinned in `MCP.md` ("The daemon never writes a grant").
//!
//! `grant_create` asks the daemon to accept a grant a human just approved. It
//! carries no secret value, only the token's SHA-256, and the daemon answers
//! `grant_approved` without touching the vault: the CLI that holds the raw
//! token assigns the id and writes the grant. The daemon re-normalizes the
//! payload and requires that its digest matches the one-shot approval, so it
//! can never mint or widen a grant on its own.
//!
//! `grant_revoke` marks exactly one grant (`id`) or every grant (`all: true`)
//! revoked. It needs no human-presence proof because it only removes access,
//! and an already-revoked id is a successful no-op. It is one of the two
//! requests for which `pmd` writes the vault: `grant_revoke` sets
//! `revoked_at`, and `run` records the use (`uses`, `last_used`) before it
//! injects. Neither creates or widens a grant.
//!
//! `challenge`/`prove` are the human-presence proof (TODO 3.3): the daemon
//! issues a single-use nonce and accepts a key-derived MAC over it exactly
//! once. Neither request carries a secret value; see [`crate::presence`].
//!
//! Version 2 added the required `token` field, so it is not backward
//! compatible with version 1 (a version-1 peer would be treated as an
//! unsigned request). Version 3 added the required `run.cwd` field and
//! requires `run.command[0]` to be an absolute path, so a version-2 daemon
//! would run the child in the wrong directory. Older versions are refused
//! with `unsupported_version`.
//!
//! `list` was added inside version 4 without a bump: an older daemon answers
//! it with `unknown request type`, which is a refusal, not a silently widened
//! grant. Like `run`, it presents a grant token in addition to the session
//! token and answers only with metadata the grant covers.
//!
//! `describe` was added the same way. It names one `pm://` reference and
//! presents a grant token; the daemon applies the same per-candidate
//! authorization as `list` and answers one [`Entry`](crate::protocol::Entry).
//! A reference outside the grant and a reference that does not exist are
//! answered with the identical `not_found` error, so one token cannot probe
//! the vault for entries it was not granted.
//!
//! # There is no plaintext request type
//!
//! The daemon holds the vault key, and any same-user process can connect to
//! the socket, so a client-side check would protect nothing. Consequently no
//! request type returns a secret value: the daemon injects the secret into a
//! child process for `run` and relays only redacted output, and `list`
//! answers references, names, tags, field *names* and timestamps. This module
//! never carries a secret in either direction; unknown request types are
//! rejected.
//!
//! # The `run` response stream
//!
//! `run` is answered with a stream of [`RunFrame`]s rather than one response:
//! zero or more `stdout`/`stderr` chunks, then exactly one terminal frame —
//! either `exit` (`code` or `signal`) or `error` (one of `not_found`,
//! `spawn_failed`, `bad_request`, `denied`, `internal` or `busy`). A request
//! that fails authentication or decoding never starts a stream at all: `pmd`
//! answers it with a one-shot `error` response (`unauthorized`,
//! `bad_request`). Chunk payloads are hex-encoded so arbitrary
//! child bytes survive JSON, and each chunk is capped at [`MAX_CHUNK_BYTES`]
//! so one frame always fits in [`MAX_MESSAGE_BYTES`].
//!
//! The stream is a **separate type** ([`RunFrame`]) from the one-shot
//! [`Response`]: a `ping` can never answer with child output, and a `run`
//! stream can never answer with `pong`. [`RunStream`] enforces the ordering
//! rule (nothing after a terminal frame) for the reader.
//!
//! What travels in `stdout`/`stderr` is ordinary child output that `pmd` has
//! already passed through [`crate::redact::Redactor`]; the daemon redacts
//! before encoding, and nothing in this module can tell whether a byte is a
//! secret. A chunk is therefore *not* zeroized or treated as secret here (it
//! is the redacted, agent-visible text), but it is still never rendered by
//! `Debug`.
//!
//! # Untrusted input
//!
//! Every function here is pure (it performs no I/O) and treats its input as
//! attacker-controlled: the declared length is range-checked *before* any
//! slice or allocation is made from it, the message body is capped at
//! [`MAX_MESSAGE_BYTES`], and JSON is parsed with a fixed schema. Malformed
//! input yields [`ProtocolError`], never a panic.
//!
//! # Forward compatibility
//!
//! Unknown *fields* are ignored (a later version may add a field without
//! breaking older peers). Unknown request *types* and unknown envelope
//! *versions* are hard errors, because guessing at semantics is not safe.
//! Adding the required `token` field bumped the version, so a version-1 peer
//! is refused instead of silently being served as if it were authenticated.

use std::fmt;
use std::path::PathBuf;

use crate::grant::{Capabilities, GrantId, GrantRequest, GrantSpec, GrantToken, Scope, TokenHash};
use crate::presence::{ChallengeNonce, Proof, RequestDigest};
use crate::store::EntryId;
use crate::token::SessionToken;

mod codec;
pub(crate) mod entry;
mod response;

/// Frame splitting is shared with [`response`], which decodes its own bodies.
use codec::split_frame;
pub use codec::{FrameDecoder, decode, encode};
pub use entry::Entry;
pub use response::{
    Response, ResponseError, RunExit, RunFinished, RunFrame, RunStream, decode_response,
    decode_run_frame, encode_response, encode_run_frame,
};

/// The protocol version carried in every envelope. Bump it when a change is
/// not backward compatible.
///
/// Version 3 added the required `run.cwd` field and requires `run.command[0]`
/// to be an absolute path. A version-2 daemon would ignore `cwd` and execute
/// the program in its own working directory, so the bump turns a silent
/// mismatch into a refusal that tells the human to restart the daemon.
///
/// Version 4 added the required `run.grant` field. A version-3 daemon would
/// ignore it and authorize `run` with the session token alone, silently
/// skipping the grant check, so the bump forces a restart instead.
pub const PROTOCOL_VERSION: u32 = 4;

/// Largest accepted frame body. 64 KiB is far more than any request needs and
/// bounds the memory a peer can make the daemon allocate.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Size of the big-endian length prefix in bytes.
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// Upper bound on what a [`FrameDecoder`] will buffer before the caller drains
/// it: two maximum-size frames, so a read may legitimately contain more than
/// one frame.
pub const MAX_BUFFERED_BYTES: usize = 2 * (LENGTH_PREFIX_BYTES + MAX_MESSAGE_BYTES);

/// Longest accepted `list.query` (a service-name substring). Matches the
/// `maxLength` of the MCP `list_credentials` input schema.
pub const MAX_QUERY_BYTES: usize = 256;

/// Longest accepted environment variable name.
pub const MAX_ENV_NAME_BYTES: usize = 128;
/// Most secret bindings one `run` may inject. Also keeps the redactor's marker
/// search well below the point where no safe marker exists (TODO 4.5a).
pub const MAX_ENV_BINDINGS: usize = 32;
/// Longest accepted value in `run.plain_env`.
pub const MAX_ENV_VALUE_BYTES: usize = 4096;
/// Longest accepted `pm://` reference.
pub const MAX_REFERENCE_BYTES: usize = 128;
/// Longest accepted single argument in a `run` command.
pub const MAX_ARG_BYTES: usize = 4096;
/// Longest accepted `run.cwd` (the caller's absolute working directory).
pub const MAX_PATH_BYTES: usize = 4096;
/// Most arguments accepted in a `run` command (including `argv[0]`).
pub const MAX_ARGS: usize = 256;
/// Largest raw payload carried by one `stdout`/`stderr` frame. Hex encoding
/// doubles it, and the JSON envelope adds only a few dozen bytes, so a
/// maximum chunk stays far below [`MAX_MESSAGE_BYTES`].
pub const MAX_CHUNK_BYTES: usize = 16 * 1024;
/// Largest signal number accepted in an `exit` frame. Real Unix signals are
/// below this on every supported platform; anything else is refused rather
/// than passed to a caller that may use it as an exit status.
pub const MAX_SIGNAL: u8 = 127;

/// Default deadline for one `run`, in seconds (ten minutes).
pub const DEFAULT_RUN_TIMEOUT_SECS: u32 = 600;
/// Largest accepted `run.timeout_secs`. A request can never make the daemon
/// keep a child alive longer than this.
pub const MAX_RUN_TIMEOUT_SECS: u32 = 600;
/// Default per-stream cap on relayed (already redacted) output: 256 KiB.
pub const DEFAULT_RUN_OUTPUT_BYTES: u32 = 256 * 1024;
/// Largest accepted per-stream output cap: 1 MiB.
pub const MAX_RUN_OUTPUT_BYTES: u32 = 1024 * 1024;

/// How much of an unknown request type is echoed back in an error message.
pub(super) const MAX_TYPE_CHARS: usize = 32;

/// A request from a `pm` client to the daemon.
///
/// None of these variants carries a secret value; `run` names the reference to
/// inject and the command to run, and the daemon resolves the value itself.
/// `challenge`/`prove` carry only a public nonce, a public digest and a MAC;
/// see [`crate::presence`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Liveness check. The daemon answers without touching the vault.
    Ping,
    /// Wipe the key and shut down.
    Lock,
    /// Spawn `command` with `env` set to the value of `reference`.
    Run(RunRequest),
    /// List the metadata of the credentials `grant` covers.
    ///
    /// Every candidate is authorized on its own with
    /// [`Grant::authorizes`](crate::grant::Grant::authorizes) and an
    /// out-of-scope credential is simply absent, so `list` is not an
    /// existence oracle. The answer is a [`Response::Entries`](crate::protocol::Response::Entries)
    /// of references, names, tags, field *names* and timestamps — never a
    /// value. Tags and `query` only narrow the result; they cannot widen the
    /// grant's scope.
    List(ListRequest),
    /// Describe one credential the grant covers.
    ///
    /// Like [`Request::List`], the caller must present a grant with the `list`
    /// capability and the credential must be in its scope. A reference the
    /// grant does not cover and a reference that does not exist are answered
    /// identically with `not_found`, so `describe` is not an existence oracle
    /// either. The answer is a [`Response::Entry`](crate::protocol::Response::Entry)
    /// of metadata only; the password is never read.
    Describe(DescribeRequest),
    /// Issue a single-use nonce for a human-presence proof. Answer: [`Response::Challenge`](crate::protocol::Response::Challenge).
    Challenge,
    /// Present a proof of vault-key knowledge for a challenge.
    ///
    /// Answer: `proven` only after the daemon has recorded `digest` as a
    /// one-shot approval, or `denied` for every bad nonce or MAC. `proven`
    /// authorizes nothing by itself; the write for that request must present
    /// the same digest and consumes the approval exactly once.
    Prove(ProveRequest),
    /// Accept the grant a human approved with a `prove` over its digest.
    ///
    /// The daemon re-normalizes the payload, checks it against the clock and
    /// spends the one-shot approval. Answer: `grant_approved`, or `denied`
    /// when the digest was not approved or the approval was already spent.
    /// The daemon never opens the vault here and the answer carries no token,
    /// hash or grant id; the CLI that holds the raw token writes the grant.
    GrantCreate(GrantCreateRequest),
    /// Mark one grant, or every grant, revoked.
    ///
    /// Along with `run` (which records the use), this is one of the two
    /// requests for which the daemon writes the vault; its only write is
    /// setting `revoked_at` on grants that already exist. It needs no
    /// human-presence proof because it only removes access: an agent may
    /// revoke for itself. Answer:
    /// [`Response::GrantRevoked`](crate::protocol::Response::GrantRevoked)
    /// with the number of grants newly revoked, or `not_found` for an
    /// unknown id. An already-revoked id is a successful no-op.
    GrantRevoke(GrantRevokeRequest),
}

/// The `"type"` of every [`Request`] variant, in declaration order.
///
/// Published so documentation and tests can derive the request-type list
/// instead of hardcoding it (TODO R.51). Adding a variant must add its name
/// here as well; [`Request::wire_name`] is an exhaustive match, so the
/// compiler points at it.
pub const REQUEST_WIRE_NAMES: &[&str] = &[
    "ping",
    "lock",
    "run",
    "list",
    "describe",
    "challenge",
    "prove",
    "grant_create",
    "grant_revoke",
];

impl Request {
    /// The wire `"type"` this request is encoded with.
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Lock => "lock",
            Self::Run(_) => "run",
            Self::List(_) => "list",
            Self::Describe(_) => "describe",
            Self::Challenge => "challenge",
            Self::Prove(_) => "prove",
            Self::GrantCreate(_) => "grant_create",
            Self::GrantRevoke(_) => "grant_revoke",
        }
    }
}

/// The target of a `grant_revoke` request: exactly one id or every grant.
///
/// An enum rather than two optional fields, so "one" and "all" cannot be
/// sent together or both omitted, and so an id is parsed at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRevokeRequest {
    /// Revoke the grant with this id. Unknown ids answer `not_found`.
    Id(GrantId),
    /// Revoke every grant that is not already revoked.
    All,
}

/// The `prove` payload: a MAC over a nonce and the digest of the request the
/// human is approving.
///
/// The proof is key-derived, so its `Debug` is redacted and equality is
/// constant-time (see [`crate::presence::Proof`]). The nonce and digest are
/// public values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProveRequest {
    /// The nonce the daemon issued and has not yet spent.
    pub nonce: ChallengeNonce,
    /// Digest of the request the human is approving.
    pub digest: RequestDigest,
    /// `HMAC-SHA256(vault_key, DOMAIN || nonce || digest)`.
    pub proof: Proof,
}

/// One secret environment variable a `run` injects.
///
/// `name` is a validated environment variable name and `reference` is a
/// canonical `pm://` reference. Neither carries a value: the daemon resolves
/// the reference from its own vault after authorizing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvBinding {
    /// Environment variable name in the child process.
    pub name: String,
    /// `pm://<32 hex chars>` reference of the credential to inject.
    pub reference: String,
}

/// The `run` payload: inject each binding's value for `command`.
///
/// `cwd` is the **caller's** working directory, not the daemon's. The daemon
/// runs the child there, so relative arguments mean what the caller meant.
/// `command[0]` must be an absolute path: the daemon never resolves a program
/// through its own `PATH`, which belongs to the shell that ran `unlock`.
///
/// The session token in the envelope only gets the request this far. The
/// daemon authorizes every binding against `grant`: the raw token the human
/// handed the agent, matched by its SHA-256 against the grant stored in the
/// vault. Holding the session file is therefore not enough to use a secret.
#[derive(Debug, Clone)]
pub struct RunRequest {
    /// Ordered secret bindings, one environment variable each. Order is
    /// preserved on the wire and at least one binding is required.
    pub env: Vec<EnvBinding>,
    /// Deadline and per-stream output cap for this run.
    pub limits: RunLimits,
    /// Non-secret variables set after the inherited allowlist and before the
    /// secret bindings. Never redacted, because the agent supplied them.
    pub plain_env: Vec<(String, String)>,
    /// Argument vector; `command[0]` is an absolute path to the program.
    pub command: Vec<String>,
    /// Absolute working directory the child starts in (the caller's cwd).
    pub cwd: String,
    /// The grant token this run presents. Never rendered; see [`GrantToken`].
    pub grant: GrantToken,
}

// A manual implementation because [`GrantToken`] deliberately has no
// `PartialEq`: compare the hashes, which is what authorization does anyway.
// `Request` derives `PartialEq` for protocol tests and for callers that need
// to compare two decoded requests.
impl PartialEq for RunRequest {
    fn eq(&self, other: &Self) -> bool {
        self.env == other.env
            && self.limits == other.limits
            && self.plain_env == other.plain_env
            && self.command == other.command
            && self.cwd == other.cwd
            && self.grant.hash().matches(&other.grant.hash())
    }
}

impl Eq for RunRequest {}

/// Per-run resource limits. Both are policy, never secret data; the daemon
/// re-clamps them before it spawns anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    /// Wall-clock deadline for the child and everything it starts.
    pub timeout_secs: u32,
    /// Cap on relayed bytes per output stream, applied after redaction.
    pub max_output_bytes: u32,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_RUN_TIMEOUT_SECS,
            max_output_bytes: DEFAULT_RUN_OUTPUT_BYTES,
        }
    }
}

/// The `list` payload: which metadata to return, and the grant that allows it.
///
/// Both filters are optional and only ever narrow the answer. An empty `tags`
/// means "no tag filter" and `query` is matched as a case-insensitive
/// substring of the service name. Scope is never derived from them: the daemon
/// authorizes each candidate against the grant's references and tags first.
#[derive(Debug, Clone)]
pub struct ListRequest {
    /// Tags the credential must all carry; empty means no tag filter.
    pub tags: Vec<String>,
    /// Case-insensitive substring of the service name; `None` means no filter.
    pub query: Option<String>,
    /// The grant token this list presents. Never rendered; see [`GrantToken`].
    pub grant: GrantToken,
}

// A manual implementation for the same reason as [`RunRequest`]: compare the
// grant hashes, which is what authorization does anyway.
impl PartialEq for ListRequest {
    fn eq(&self, other: &Self) -> bool {
        self.tags == other.tags
            && self.query == other.query
            && self.grant.hash().matches(&other.grant.hash())
    }
}

impl Eq for ListRequest {}

/// The `describe` payload: one reference and the grant that allows reading it.
///
/// The reference is canonicalized at the boundary, so an upper-case or
/// non-canonical spelling cannot name a different entry. Scope comes from the
/// grant alone; the reference only selects one candidate, exactly as `list`
/// selects its candidates.
#[derive(Debug, Clone)]
pub struct DescribeRequest {
    /// `pm://<32 hex chars>` reference of the credential to describe.
    pub reference: String,
    /// The grant token this describe presents. Never rendered; see [`GrantToken`].
    pub grant: GrantToken,
}

// A manual implementation for the same reason as [`RunRequest`]: compare the
// grant hashes, which is what authorization does anyway.
impl PartialEq for DescribeRequest {
    fn eq(&self, other: &Self) -> bool {
        self.reference == other.reference && self.grant.hash().matches(&other.grant.hash())
    }
}

impl Eq for DescribeRequest {}

/// The `grant_create` payload: the exact grant a human approved.
///
/// A caller can only build one from an already normalized
/// [`crate::grant::GrantRequest`]; the decoder builds one from untrusted JSON
/// and [`validate_request`] re-normalizes it before anything else sees it.
///
/// The wire form carries no secret value: a label, entry references, tag and
/// field names, command paths, capability bits, an expiry, an optional use
/// limit and the SHA-256 of the grant token. The raw token never crosses the
/// socket; the daemon re-derives the digest the human proved and spends that
/// one-shot approval.
#[derive(Clone, Debug)]
pub struct GrantCreateRequest {
    label: String,
    references: Vec<EntryId>,
    tags: Vec<String>,
    fields: Option<Vec<String>>,
    commands: Vec<String>,
    capabilities: Capabilities,
    expires_at: u64,
    max_uses: Option<u32>,
    token_hash: TokenHash,
}

impl GrantCreateRequest {
    /// The wire payload for an already validated request.
    pub fn from_grant_request(request: &GrantRequest) -> Self {
        Self {
            label: request.label().to_owned(),
            references: request.scope().refs().to_vec(),
            tags: request.scope().tags().to_vec(),
            fields: request.scope().fields().map(<[String]>::to_vec),
            commands: request.commands().to_vec(),
            capabilities: request.capabilities(),
            expires_at: request.expires_at(),
            max_uses: request.max_uses(),
            token_hash: *request.token_hash(),
        }
    }

    /// Re-normalize the decoded payload exactly as the approving CLI did.
    ///
    /// Returns the canonical [`GrantRequest`], whose
    /// [`GrantRequest::digest`] is the digest a `prove` must have covered. A
    /// payload the vault writer would refuse is an
    /// [`ProtocolError::InvalidRequest`].
    pub fn into_grant_request(self) -> Result<GrantRequest, ProtocolError> {
        let scope = Scope::new(self.references, self.tags, self.fields)
            .map_err(|err| ProtocolError::InvalidRequest(err.to_string()))?;
        GrantRequest::new(
            GrantSpec {
                label: self.label,
                scope,
                commands: self.commands.into_iter().map(PathBuf::from).collect(),
                capabilities: self.capabilities,
                expires_at: self.expires_at,
                max_uses: self.max_uses,
            },
            self.token_hash,
        )
        .map_err(|err| ProtocolError::InvalidRequest(err.to_string()))
    }
}

impl PartialEq for GrantCreateRequest {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label
            && self.references == other.references
            && self.tags == other.tags
            && self.fields == other.fields
            && self.commands == other.commands
            && self.capabilities == other.capabilities
            && self.expires_at == other.expires_at
            && self.max_uses == other.max_uses
            && self.token_hash.matches(&other.token_hash)
    }
}

impl Eq for GrantCreateRequest {}

/// A request together with the session token that authorized it.
///
/// [`decode`] only produces this after the envelope's `token` field parsed as
/// a [`SessionToken`]; the daemon then compares it with its own token before
/// looking at the request. The token's `Debug` is redacted, so deriving
/// `Debug` here cannot leak it.
#[derive(Clone, Debug)]
pub struct AuthenticatedRequest {
    token: SessionToken,
    request: Request,
}

impl AuthenticatedRequest {
    /// Pair a token with a request (used by clients before encoding).
    pub fn new(token: SessionToken, request: Request) -> Self {
        Self { token, request }
    }

    /// The session token the peer presented.
    pub fn token(&self) -> &SessionToken {
        &self.token
    }

    /// The request the peer wants served.
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// Consume the pair, keeping only the request.
    pub fn into_request(self) -> Request {
        self.request
    }
}

/// Why a frame or request was rejected.
///
/// The messages contain only structural information (lengths, a truncated
/// request type), never request payload bytes, so they are safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The frame ended before the declared number of bytes arrived.
    TruncatedFrame { expected: usize, actual: usize },
    /// Bytes followed a complete frame; one call decodes exactly one frame.
    TrailingBytes { trailing: usize },
    /// The declared length exceeds [`MAX_MESSAGE_BYTES`].
    MessageTooLarge { length: usize, max: usize },
    /// A zero-length frame body.
    EmptyMessage,
    /// The body is not valid JSON, or not the expected JSON shape.
    MalformedJson(String),
    /// The envelope version is not [`PROTOCOL_VERSION`].
    UnsupportedVersion(u64),
    /// The `request.type` is not a request this version implements.
    UnknownRequest(String),
    /// The `response.type` (or its error code) is not one this version knows.
    UnknownResponse(String),
    /// The request is structurally valid JSON but fails validation.
    InvalidRequest(String),
    /// The envelope has no usable session token.
    InvalidToken,
    /// A [`FrameDecoder`] was given more bytes than it will buffer.
    BufferFull { buffered: usize, max: usize },
    /// A `stdout`/`stderr` chunk exceeds [`MAX_CHUNK_BYTES`].
    ChunkTooLarge { length: usize, max: usize },
    /// A response frame is valid JSON but its fields violate the protocol.
    InvalidResponse(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedFrame { expected, actual } => {
                write!(
                    f,
                    "truncated frame: expected {expected} bytes, got {actual}"
                )
            }
            Self::TrailingBytes { trailing } => {
                write!(f, "trailing bytes after frame: {trailing}")
            }
            Self::MessageTooLarge { length, max } => {
                write!(
                    f,
                    "message too large: {length} bytes exceeds the {max}-byte limit"
                )
            }
            Self::EmptyMessage => f.write_str("empty message"),
            Self::MalformedJson(detail) => write!(f, "malformed protocol message: {detail}"),
            Self::UnsupportedVersion(version) => write!(
                f,
                "unsupported protocol version {version} (this build speaks version {PROTOCOL_VERSION})"
            ),
            Self::UnknownRequest(kind) => write!(f, "unknown request type {kind:?}"),
            Self::UnknownResponse(kind) => write!(f, "unknown response type or code {kind:?}"),
            Self::InvalidRequest(detail) => write!(f, "invalid request: {detail}"),
            Self::InvalidToken => write!(
                f,
                "invalid session token (expected {} lowercase hex characters)",
                crate::token::TOKEN_HEX_CHARS
            ),
            Self::BufferFull { buffered, max } => {
                write!(
                    f,
                    "protocol buffer full: {buffered} bytes buffered, limit {max}"
                )
            }
            Self::ChunkTooLarge { length, max } => {
                write!(
                    f,
                    "output chunk too large: {length} bytes exceeds the {max}-byte limit"
                )
            }
            Self::InvalidResponse(detail) => write!(f, "invalid response: {detail}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Validate field bounds for a request. Applied on both encode and decode:
/// locally generated requests and peer-supplied ones must meet the same
/// contract.
fn validate_request(request: &Request) -> Result<(), ProtocolError> {
    if let Request::GrantCreate(create) = request {
        // Normalizing here means a payload the daemon could not turn into the
        // same digest the human approved is rejected at the boundary, before
        // it reaches the approval store.
        create.clone().into_grant_request()?;
        return Ok(());
    }
    if let Request::List(list) = request {
        return validate_list(list);
    }
    if let Request::Describe(describe) = request {
        return validate_reference("describe.ref", &describe.reference);
    }
    let Request::Run(run) = request else {
        return Ok(());
    };
    validate_run_limits(&run.limits)?;
    validate_run_env(run)?;
    validate_absolute_path("run.cwd", &run.cwd)?;
    if run.command.is_empty() {
        return Err(ProtocolError::InvalidRequest(
            "run.command must not be empty".into(),
        ));
    }
    if run.command.len() > MAX_ARGS {
        return Err(ProtocolError::InvalidRequest(format!(
            "run.command has more than {MAX_ARGS} arguments"
        )));
    }
    for (index, argument) in run.command.iter().enumerate() {
        if argument.len() > MAX_ARG_BYTES {
            return Err(ProtocolError::InvalidRequest(format!(
                "run.command[{index}] exceeds {MAX_ARG_BYTES} bytes"
            )));
        }
        if index == 0 {
            // Never let the daemon resolve a program through its own PATH:
            // that PATH belongs to the shell that started `unlock`, not to the
            // caller that named the command.
            validate_absolute_path("run.command[0]", argument)?;
        }
    }
    Ok(())
}

/// Require a bounded, canonical `pm://` reference.
///
/// The daemon still has to check that the entry exists and is in scope; this
/// only rejects input no `EntryId` could have produced.
fn validate_reference(field: &str, reference: &str) -> Result<(), ProtocolError> {
    if reference.is_empty() {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    if reference.len() > MAX_REFERENCE_BYTES {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} exceeds {MAX_REFERENCE_BYTES} bytes"
        )));
    }
    // Reuse the canonical parser instead of duplicating the reference syntax.
    if EntryId::parse_ref(reference).is_err() {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} is not a valid pm:// reference"
        )));
    }
    Ok(())
}

/// Validate the `list` filters. They are agent-supplied text, so each tag
/// must be a real tag and `query` is bounded and control-free before the
/// daemon or the CLI ever renders it.
fn validate_list(list: &ListRequest) -> Result<(), ProtocolError> {
    if list.tags.len() > crate::store::MAX_TAGS_PER_CREDENTIAL {
        return Err(ProtocolError::InvalidRequest(format!(
            "list.tags accepts at most {} tags",
            crate::store::MAX_TAGS_PER_CREDENTIAL
        )));
    }
    for (index, tag) in list.tags.iter().enumerate() {
        crate::store::validate_tag(tag).map_err(|_| {
            ProtocolError::InvalidRequest(format!("list.tags[{index}] is not a valid tag"))
        })?;
    }
    if let Some(query) = &list.query {
        if query.len() > MAX_QUERY_BYTES {
            return Err(ProtocolError::InvalidRequest(format!(
                "list.query exceeds {MAX_QUERY_BYTES} bytes"
            )));
        }
        if query.chars().any(char::is_control) {
            return Err(ProtocolError::InvalidRequest(
                "list.query must not contain control characters".into(),
            ));
        }
    }
    Ok(())
}

/// Require a non-empty, NUL-free absolute path within [`MAX_PATH_BYTES`].
fn validate_absolute_path(field: &str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    if value.len() > MAX_PATH_BYTES {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} exceeds {MAX_PATH_BYTES} bytes"
        )));
    }
    if value.contains('\0') {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must not contain a NUL byte"
        )));
    }
    if !value.starts_with('/') {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must be an absolute path"
        )));
    }
    Ok(())
}

/// Whether `env` is a syntactically valid environment variable name.
///
/// This is syntax only: the daemon additionally refuses names that would let
/// an agent hijack the child (see [`crate::runner::denied_env_name`]). It is
/// public so the CLI can reject a malformed `--env` before it connects, with a
/// usage exit code instead of a daemon round-trip.
pub fn valid_env_name(env: &str) -> bool {
    if env.is_empty() || env.len() > MAX_ENV_NAME_BYTES {
        return false;
    }
    let mut bytes = env.bytes();
    let first = bytes.next().expect("checked non-empty");
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Validate the `run` resource limits. Both are required to be non-zero and
/// bounded; the defaults are inside these ranges.
fn validate_run_limits(limits: &RunLimits) -> Result<(), ProtocolError> {
    if !(1..=MAX_RUN_TIMEOUT_SECS).contains(&limits.timeout_secs) {
        return Err(ProtocolError::InvalidRequest(format!(
            "run.timeout_secs must be between 1 and {MAX_RUN_TIMEOUT_SECS}"
        )));
    }
    if !(1..=MAX_RUN_OUTPUT_BYTES).contains(&limits.max_output_bytes) {
        return Err(ProtocolError::InvalidRequest(format!(
            "run.max_output_bytes must be between 1 and {MAX_RUN_OUTPUT_BYTES}"
        )));
    }
    Ok(())
}

/// Validate the whole `run` environment: at least one secret binding, bounded
/// count, valid names, canonical references, and no name used twice (including
/// across `env` and `plain_env`).
fn validate_run_env(run: &RunRequest) -> Result<(), ProtocolError> {
    if run.env.is_empty() {
        return Err(ProtocolError::InvalidRequest(
            "run.env must contain at least one binding".into(),
        ));
    }
    if run.env.len() > MAX_ENV_BINDINGS {
        return Err(ProtocolError::InvalidRequest(format!(
            "run.env has more than {MAX_ENV_BINDINGS} bindings"
        )));
    }
    let mut names = std::collections::HashSet::with_capacity(run.env.len() + run.plain_env.len());
    for (index, binding) in run.env.iter().enumerate() {
        let field = format!("run.env[{index}].name");
        validate_env_name_field(&field, &binding.name)?;
        validate_reference(&format!("run.env[{index}].ref"), &binding.reference)?;
        if !names.insert(binding.name.as_str()) {
            return Err(ProtocolError::InvalidRequest(format!(
                "run.env[{index}].name duplicates another environment name"
            )));
        }
    }
    for (index, (name, value)) in run.plain_env.iter().enumerate() {
        validate_env_name_field(&format!("run.plain_env[{index}].name"), name)?;
        if value.len() > MAX_ENV_VALUE_BYTES {
            return Err(ProtocolError::InvalidRequest(format!(
                "run.plain_env[{index}] exceeds {MAX_ENV_VALUE_BYTES} bytes"
            )));
        }
        if value.contains('\0') {
            return Err(ProtocolError::InvalidRequest(format!(
                "run.plain_env[{index}] must not contain a NUL byte"
            )));
        }
        if !names.insert(name.as_str()) {
            return Err(ProtocolError::InvalidRequest(format!(
                "run.plain_env[{index}].name duplicates another environment name"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
fn validate_env_name(env: &str) -> Result<(), ProtocolError> {
    validate_env_name_field("run.env", env)
}

fn validate_env_name_field(field: &str, env: &str) -> Result<(), ProtocolError> {
    if env.is_empty() {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    if env.len() > MAX_ENV_NAME_BYTES {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} exceeds {MAX_ENV_NAME_BYTES} bytes"
        )));
    }
    let mut bytes = env.bytes();
    let first = bytes.next().expect("checked non-empty");
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must start with an ASCII letter or underscore"
        )));
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} may contain only ASCII letters, digits and underscores"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
