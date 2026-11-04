//! Validation and result mapping for `tools/call`.
//!
//! This module is the trust boundary between an agent-supplied JSON argument
//! object and a daemon request. It owns three jobs, all of them pure where
//! possible:
//!
//! - pull `name`/`arguments` out of `tools/call` params, rejecting anything
//!   that is not the contract's shape;
//! - validate `list_credentials` and `describe_credential` arguments against
//!   the same bounds as the hand-written schema, so a request never reaches
//!   `pmd` with a filter or reference the daemon would refuse;
//! - map a daemon answer to an MCP tool result (or an `isError` result).
//!
//! It can build a request, but it cannot decrypt anything: the daemon owns the
//! vault, and an [`Entry`] carries metadata only. No function here names a
//! plaintext-bearing type, and a tool result can only be built from an
//! `entries` response.

use serde_json::{Value, json};

use crate::client;
use crate::grant::GrantToken;
use crate::protocol::{
    DescribeRequest, Entry, ListRequest, MAX_QUERY_BYTES, MAX_REFERENCE_BYTES, Request, Response,
    ResponseError,
};
use crate::session;
use crate::socket::RuntimePaths;
use crate::store::{EntryId, MAX_TAGS_PER_CREDENTIAL, validate_tag};
use crate::timestamp;
use crate::token::SessionToken;

mod run;

pub use run::{RunArgs, RunSink, request_run, resolve_command, run_args, run_output, run_response};

/// The metadata tools this module implements (TODO 4.4d, 4.4e).
pub const LIST_CREDENTIALS: &str = "list_credentials";
pub const DESCRIBE_CREDENTIAL: &str = "describe_credential";
/// The one tool that makes `pmd` run a command (TODO 4.5d).
pub const RUN_WITH_CREDENTIALS: &str = "run_with_credentials";

/// The one refusal shared by every non-canonical reference, so a bad
/// reference can never be echoed back and no parse detail reaches the agent.
const INVALID_REF: &str = "'ref' must be a canonical pm:// reference from list_credentials";

/// The exact message `MCP.md` requires when the session has no grant.
pub const NO_GRANT: &str = "no active grant; call request_access";

/// The bounded, purely advisory filters of a list call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListFilters {
    pub tags: Vec<String>,
    pub query: Option<String>,
}

/// Split `tools/call` params into a tool name and its optional argument object.
///
/// `_meta` is admitted because the modern era attaches it to every request's
/// params. Everything else is closed: an unknown member would otherwise be a
/// silent spelling mistake in a security-sensitive call.
pub fn call_parts(params: Option<&Value>) -> Result<(&str, Option<&Value>), String> {
    let params = params.ok_or_else(|| "tools/call requires params".to_owned())?;
    let object = params
        .as_object()
        .ok_or_else(|| "tools/call params must be an object".to_owned())?;
    if let Some(unknown) = object
        .keys()
        .find(|key| !matches!(key.as_str(), "name" | "arguments" | "_meta"))
    {
        return Err(format!(
            "unknown tools/call parameter '{}'",
            clipped(unknown)
        ));
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "tools/call requires a string 'name'".to_owned())?;
    if name.is_empty() {
        return Err("tools/call 'name' must not be empty".to_owned());
    }
    if name.len() > 64 {
        return Err("tools/call 'name' is too long".to_owned());
    }
    let arguments = match object.get("arguments") {
        None | Some(Value::Null) => None,
        Some(value) => {
            if !value.is_object() {
                return Err("tools/call 'arguments' must be an object".to_owned());
            }
            Some(value)
        }
    };
    Ok((name, arguments))
}

/// Validate the `list_credentials` argument object.
///
/// Absent arguments mean "no filters". A provided member must have exactly the
/// schema's type, so `null` is refused rather than treated as absent. Tags go
/// through the store's own validator and are bounded like the daemon's list
/// request; the query is non-empty, control-free and at most
/// [`MAX_QUERY_BYTES`]. Filters only narrow, so forwarding them verbatim is
/// safe: authorization stays entirely in `pmd`.
pub fn list_filters(arguments: Option<&Value>) -> Result<ListFilters, String> {
    let Some(value) = arguments else {
        return Ok(ListFilters::default());
    };
    let object = value
        .as_object()
        .ok_or_else(|| "arguments must be an object".to_owned())?;
    if let Some(unknown) = object
        .keys()
        .find(|key| !matches!(key.as_str(), "tags" | "query"))
    {
        return Err(format!(
            "unknown list_credentials argument '{}'",
            clipped(unknown)
        ));
    }

    let tags = match object.get("tags") {
        None => Vec::new(),
        Some(value) => {
            let values = value
                .as_array()
                .ok_or_else(|| "'tags' must be an array".to_owned())?;
            if values.len() > MAX_TAGS_PER_CREDENTIAL {
                return Err(format!(
                    "'tags' accepts at most {MAX_TAGS_PER_CREDENTIAL} tags"
                ));
            }
            values
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    let tag = value
                        .as_str()
                        .ok_or_else(|| format!("'tags[{index}]' must be a string"))?;
                    validate_tag(tag)
                        .map(|()| tag.to_owned())
                        .map_err(|_| format!("'tags[{index}]' is not a valid tag"))
                })
                .collect::<Result<Vec<_>, _>>()?
        }
    };

    let query = match object.get("query") {
        None => None,
        Some(value) => {
            let query = value
                .as_str()
                .ok_or_else(|| "'query' must be a string".to_owned())?;
            if query.is_empty() {
                return Err("'query' must not be empty".to_owned());
            }
            if query.len() > MAX_QUERY_BYTES {
                return Err(format!("'query' exceeds {MAX_QUERY_BYTES} bytes"));
            }
            if query.chars().any(char::is_control) {
                return Err("'query' must not contain control characters".to_owned());
            }
            Some(query.to_owned())
        }
    };

    Ok(ListFilters { tags, query })
}

/// Build the daemon request for a validated list call.
pub fn list_request(grant: GrantToken, filters: ListFilters) -> Request {
    Request::List(ListRequest {
        tags: filters.tags,
        query: filters.query,
        grant,
    })
}

/// Validate the `describe_credential` argument object.
///
/// Exactly one member, `ref`, is required and must be a string. The value has
/// to be the canonical `pm://<32 lowercase hex>` form the store emits: parsing
/// it to an [`EntryId`] and re-rendering it rejects upper-case hex (which the
/// parser would accept) and any field suffix, so the reference forwarded to
/// `pmd` is exactly the one the tool schema promises. Nothing here decides
/// authorization; the daemon still checks scope.
///
/// The error text never contains the supplied value: an agent-supplied
/// reference is untrusted, and a parse error could otherwise echo it.
pub fn describe_ref(arguments: Option<&Value>) -> Result<String, String> {
    let Some(value) = arguments else {
        return Err("describe_credential requires a 'ref'".to_owned());
    };
    let object = value
        .as_object()
        .ok_or_else(|| "arguments must be an object".to_owned())?;
    if let Some(unknown) = object.keys().find(|key| key.as_str() != "ref") {
        return Err(format!(
            "unknown describe_credential argument '{}'",
            clipped(unknown)
        ));
    }
    let reference = object
        .get("ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "'ref' is required and must be a string".to_owned())?;
    if reference.len() > MAX_REFERENCE_BYTES {
        return Err(format!("'ref' exceeds {MAX_REFERENCE_BYTES} bytes"));
    }
    let id = EntryId::parse_ref(reference).map_err(|_| INVALID_REF.to_owned())?;
    if id.to_ref() != reference {
        return Err(INVALID_REF.to_owned());
    }
    Ok(reference.to_owned())
}

/// Build the daemon request for a validated describe call.
pub fn describe_request(grant: GrantToken, reference: String) -> Request {
    Request::Describe(DescribeRequest { reference, grant })
}

/// Ask `pmd` for the entries this grant covers.
///
/// The session token comes from the runtime directory, never from the agent.
/// A missing or unusable token is reported as an actionable `isError` result,
/// not as an empty list: an agent must not mistake "no daemon" for "no
/// credentials".
pub fn request_list(grant: &GrantToken, filters: ListFilters) -> Result<Response, String> {
    send(&list_request(grant.clone(), filters))
}

/// Ask `pmd` to describe one entry the grant covers.
///
/// Loads and checks the session token exactly as [`request_list`] does. The
/// daemon owns every authorization decision and collapses an out-of-scope
/// reference into the same `not_found` as a missing one.
pub fn request_describe(grant: &GrantToken, reference: String) -> Result<Response, String> {
    send(&describe_request(grant.clone(), reference))
}

/// Send one already-validated request to the session's daemon.
fn send(request: &Request) -> Result<Response, String> {
    let paths = RuntimePaths::resolve();
    let token = session_token(&paths)?;
    client::request(&paths, &token, request).map_err(|error| {
        format!("cannot reach the passmgr daemon ({error}); ask the human to run `pm unlock`")
    })
}

/// The session token this process presents to `pmd`.
///
/// The token comes from the runtime directory, never from the agent, and the
/// error text distinguishes "nothing is running" from "a daemon is running
/// but this process cannot authenticate to it" exactly as `pm lock` does. A
/// probe connection carries no request.
fn session_token(paths: &RuntimePaths) -> Result<SessionToken, String> {
    match session::load(paths) {
        Ok(token) => Ok(token),
        Err(error) => {
            // Distinguish "nothing is running" from "a daemon is running but
            // this process cannot authenticate to it". A probe connection
            // carries no request.
            Err(if crate::socket::connect_at(paths).is_ok() {
                format!(
                    "cannot authenticate to the passmgr daemon ({error}); \
                     ask the human to run `pm unlock` again"
                )
            } else {
                "the passmgr daemon is not running; ask the human to run `pm unlock`".to_owned()
            })
        }
    }
}

/// One `Entry` in the MCP shape, with RFC 3339 timestamps.
///
/// This is a projection of metadata that already left the daemon; it has no
/// access to a password. Writing the shape here, instead of serializing the
/// protocol's private wire form, keeps timestamps in the format the tool
/// schema promises.
pub fn entry_json(entry: &Entry) -> Value {
    json!({
        "ref": entry.reference,
        "service": entry.service,
        "username": entry.username,
        "tags": entry.tags,
        "fields": entry.fields,
        "url": entry.url,
        "created": entry.created.map(timestamp::format_utc),
        "last_rotated": entry.last_rotated.map(timestamp::format_utc),
    })
}

/// A successful list result: short text plus the schema's structured content.
pub fn list_output(entries: &[Entry], truncated: bool) -> Value {
    let count = entries.len();
    let mut summary = format!("{count} credential entries");
    if truncated {
        summary.push_str("; the answer was truncated, narrow it with tags or query");
    }
    json!({
        "content": [{"type": "text", "text": summary}],
        "structuredContent": {
            "entries": entries.iter().map(entry_json).collect::<Vec<_>>(),
            "truncated": truncated,
        },
        "isError": false,
    })
}

/// An `isError` tool result. The caller supplies a short, secret-free message.
pub fn error_result(message: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": message}],
        "isError": true,
    })
}

/// A successful describe result: the `Entry` object is the structured content
/// itself, because that is what the tool's `outputSchema` declares.
pub fn describe_output(entry: &Entry) -> Value {
    json!({
        "content": [{"type": "text", "text": format!("credential {}", entry.reference)}],
        "structuredContent": entry_json(entry),
        "isError": false,
    })
}

/// Map a daemon describe answer to a tool result.
///
/// A `not_found` is rendered exactly like an out-of-scope reference, because
/// the daemon already collapsed the two; this layer cannot and must not try to
/// tell them apart.
pub fn describe_response(response: Response) -> Value {
    match response {
        Response::Entry(entry) => describe_output(&entry),
        Response::Error(error) => error_result(&daemon_error(error)),
        _ => error_result("the passmgr daemon answered with an unexpected response"),
    }
}

/// Map a daemon list answer to a tool result.
///
/// The daemon decides every authorization question; this only chooses an
/// actionable message. It never renders a `Response` with `Debug`, which could
/// expose an internal shape, and it never includes agent-supplied text beyond
/// what the caller already sent.
pub fn list_response(response: Response) -> Value {
    match response {
        Response::Entries { entries, truncated } => list_output(&entries, truncated),
        Response::Error(error) => error_result(&daemon_error(error)),
        _ => error_result("the passmgr daemon answered with an unexpected response"),
    }
}

/// A short, stable message for each daemon refusal.
fn daemon_error(error: ResponseError) -> String {
    let message = match error {
        ResponseError::Denied => {
            "the daemon denied this request: the grant is not active \
             (it may be expired, revoked or used up); ask the human for a new grant"
        }
        ResponseError::NotFound => "not found or not granted",
        ResponseError::Unauthorized => {
            "the daemon rejected this session; ask the human to run `pm unlock` again"
        }
        ResponseError::Busy => "the daemon is busy; retry after a running command finishes",
        ResponseError::Internal => "the daemon could not read its vault; ask the human to check it",
        ResponseError::BadRequest => "the daemon rejected the request as malformed",
        ResponseError::Unsupported => {
            "the daemon does not support this credential metadata request in this build"
        }
        ResponseError::SpawnFailed => {
            "the daemon could not start a process; this should not happen for a metadata request"
        }
    };
    message.to_owned()
}

/// Bound an agent-supplied member name before putting it in an error.
///
/// Only printable ASCII survives: a member name is never rendered as prose, so
/// dropping bidi, zero-width and other non-ASCII characters costs nothing and
/// keeps a hostile name from reordering an error line.
fn clipped(text: &str) -> String {
    let clipped: String = text
        .chars()
        .filter(|character| character.is_ascii_graphic())
        .take(32)
        .collect();
    if clipped.is_empty() {
        "?".to_owned()
    } else {
        clipped
    }
}

#[cfg(test)]
mod tests;
