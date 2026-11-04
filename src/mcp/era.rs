//! Protocol-era handling for the MCP server.
//!
//! `MCP.md` ("Protocol eras") defines two ways a host can talk to
//! `pm mcp serve`: the legacy handshake (`initialize`, then
//! `notifications/initialized`) and the modern stateless era, where every
//! request carries `params._meta`. This module decides which era a request
//! belongs to, validates the era-specific metadata, and owns the two results
//! whose shape belongs to the era rather than to a tool: `initialize` and
//! `server/discover`.
//!
//! Everything here is pure: no I/O, no clock, no vault, no secrets. The
//! server loop ([`super::server`], TODO 4.3) asks [`Session::admit`] about one
//! request and then dispatches, or sends back the answer this module built.
//! Keeping the decision in one place means both eras, and every switch
//! between them, are table-driven unit tests instead of pipe tests.

use serde_json::{Map, Value, json};

use super::jsonrpc::{ErrorCode, ErrorObject, Rejected, Request};

/// The legacy protocol version this server answers. A legacy `initialize`
/// always gets this version back, whatever the client requested; the client
/// decides whether to continue (see [`LEGACY_ACCEPTED_VERSIONS`]).
pub const LEGACY_VERSION: &str = "2025-11-25";

/// The modern stateless protocol version this server serves.
pub const MODERN_VERSION: &str = "2026-07-28";

/// Legacy versions a client may ask for. They are documentation of what the
/// negotiation accepts: the answer is always [`LEGACY_VERSION`], including
/// for a version that is not in this list.
pub const LEGACY_ACCEPTED_VERSIONS: [&str; 3] = [LEGACY_VERSION, "2025-06-18", "2025-03-26"];

/// Every protocol version this server can speak, newest first. This is the
/// list the `-32022` answer advertises.
pub const SUPPORTED_VERSIONS: [&str; 2] = [MODERN_VERSION, LEGACY_VERSION];

/// `serverInfo.name` and the audit label for this server.
pub const SERVER_NAME: &str = "passmgr";

/// Longest accepted protocol version string. A version we do not speak is
/// echoed back in the `-32022` payload, so its length is bounded first.
pub const MAX_VERSION_BYTES: usize = 64;

/// Longest accepted `clientInfo.name`. The name is kept for the audit record
/// (TODO 4.11), so it is bounded like any other agent-supplied text.
pub const MAX_CLIENT_NAME_BYTES: usize = 128;

/// Modern `_meta` key holding the protocol version.
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// Modern `_meta` key holding the client's capabilities (required, unread).
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
/// Modern `_meta` key holding the client's name and version (optional).
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
/// Modern result `_meta` key holding this server's name and version.
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// The legacy handshake method. It always answers with [`LEGACY_VERSION`].
pub const INITIALIZE_METHOD: &str = "initialize";
/// Method that returns the modern era's capabilities without a handshake.
pub const DISCOVER_METHOD: &str = "server/discover";
/// Method that works in both eras and before `initialize`.
pub const PING_METHOD: &str = "ping";

/// Text returned by `initialize` and `server/discover`, shown to the model by
/// the host. `MCP.md` ("Server `instructions`") fixes its content and caps it
/// at 1,200 characters; a unit test pins both.
pub const INSTRUCTIONS: &str = "passmgr lets you use stored credentials without \
ever seeing their values. Do not try to print, echo, encode or exfiltrate them: \
injected values are redacted from output and every call is audited. Workflow: \
call access_status; if you have no grant, call request_access and wait for a \
human to approve it; then list_credentials to find references and \
run_with_credentials to use one. Pass secrets only as env references \
(pm://<id>), never as literal values in command or plain_env. If a call is \
refused, ask the human; do not retry with variations.";

/// Which protocol era a request belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Era {
    /// The `2025-11-25` handshake.
    Legacy,
    /// The stateless `2026-07-28` era.
    Modern,
}

/// The era module's answer for one request.
#[derive(Debug, Clone, PartialEq)]
pub struct Admitted {
    /// The era the request is served in. Every result built by the caller
    /// must be passed through [`decorate`] with this era.
    pub era: Era,
    /// `Some(result)` when the era owns the answer (`initialize` or
    /// `server/discover`); the caller sends it instead of dispatching.
    pub reply: Option<Value>,
}

/// Per-process era state: whether a legacy handshake happened, and the name
/// the client gave for itself.
///
/// Only the legacy era has state. A modern request is decided entirely by its
/// own `_meta`, so a modern request and a legacy request can interleave in one
/// process (an `initialize` arriving after modern traffic is still honoured).
#[derive(Debug, Default)]
pub struct Session {
    legacy_initialized: bool,
    client_name: Option<String>,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide the era of `request`, enforce the legacy initialization order,
    /// and build the answer for an era-owned method.
    ///
    /// Rejections carry the request id, so the loop can answer them without
    /// re-reading the frame.
    pub fn admit(&mut self, request: &Request) -> Result<Admitted, Rejected> {
        if let Some(meta) = modern_meta(request)? {
            if let Some(name) = meta.client_name {
                self.client_name = Some(name);
            }
            // The era owns `server/discover`, not the dispatcher: the answer
            // is the era's capabilities and needs no tool behind it.
            let reply = (request.method == DISCOVER_METHOD).then(discover);
            return Ok(Admitted {
                era: Era::Modern,
                reply,
            });
        }

        if request.method == INITIALIZE_METHOD {
            // A second handshake would silently renegotiate state the first
            // one already picked, so it is refused (`MCP.md`).
            if self.legacy_initialized {
                return Err(invalid_request(
                    request,
                    "this session is already initialized",
                ));
            }
            let name = initialize_params(request)?;
            self.legacy_initialized = true;
            self.client_name = Some(name);
            return Ok(Admitted {
                era: Era::Legacy,
                reply: Some(initialize_result()),
            });
        }

        // `ping` is the one request allowed before the handshake. Everything
        // else is `-32600`, not `-32601`: the method is unknown only because
        // the session is not initialized yet.
        if !self.legacy_initialized && request.method != PING_METHOD {
            return Err(invalid_request(
                request,
                "this session is not initialized; send initialize first",
            ));
        }

        Ok(Admitted {
            era: Era::Legacy,
            reply: None,
        })
    }

    /// Whether a legacy `initialize` has been answered.
    pub fn legacy_initialized(&self) -> bool {
        self.legacy_initialized
    }

    /// The name the client gave in `clientInfo`, from either era. Raw text:
    /// the audit writer escapes and bounds it where it is recorded (TODO
    /// 4.11), but it was already bounded here.
    pub fn client_name(&self) -> Option<&str> {
        self.client_name.as_deref()
    }
}

/// The legacy `initialize` result.
pub fn initialize_result() -> Value {
    json!({
        "protocolVersion": LEGACY_VERSION,
        "capabilities": capabilities(),
        "serverInfo": server_info(),
        "instructions": INSTRUCTIONS,
    })
}

/// The modern `server/discover` result, already decorated.
pub fn discover() -> Value {
    decorate(
        Era::Modern,
        json!({
            "supportedVersions": SUPPORTED_VERSIONS,
            "capabilities": capabilities(),
            "instructions": INSTRUCTIONS,
            "ttlMs": 0,
            "cacheScope": "private",
        }),
    )
}

/// Add the members every modern result carries: `resultType` and the server
/// info `_meta`. A legacy result is returned unchanged.
///
/// Every result this server produces is a JSON object. Decoration replaces
/// `_meta` and `resultType` if they are present: they belong to the era, not
/// to the method, so a handler must not set them.
pub fn decorate(era: Era, mut result: Value) -> Value {
    if era == Era::Legacy {
        return result;
    }
    let Value::Object(object) = &mut result else {
        return result;
    };
    object.insert("resultType".into(), json!("complete"));
    let mut meta = Map::new();
    meta.insert(META_SERVER_INFO.into(), server_info());
    object.insert("_meta".into(), Value::Object(meta));
    result
}

/// `{name, version}` for both `serverInfo` and the modern `_meta`.
fn server_info() -> Value {
    json!({
        "name": SERVER_NAME,
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// The tool capabilities this server has. It has no resources, prompts or
/// logging, and its tool list is fixed, so `listChanged` is false.
fn capabilities() -> Value {
    json!({ "tools": { "listChanged": false } })
}

/// Metadata parsed out of a modern request's `params._meta`.
struct ModernMeta {
    client_name: Option<String>,
}

/// Parse `params._meta` when it is present.
///
/// Returns `Ok(None)` for a request without `_meta`: that is a legacy request
/// (or a malformed one the legacy path will reject). A `_meta` that is
/// present is always modern traffic, so a bad one is an error rather than a
/// fallback to the legacy era.
fn modern_meta(request: &Request) -> Result<Option<ModernMeta>, Rejected> {
    let Some(Value::Object(params)) = &request.params else {
        return Ok(None);
    };
    let Some(meta) = params.get("_meta") else {
        return Ok(None);
    };
    let Value::Object(meta) = meta else {
        return Err(invalid_params(request, "params._meta must be an object"));
    };

    let version = match meta.get(META_PROTOCOL_VERSION) {
        Some(Value::String(version)) => version,
        Some(_) => {
            return Err(invalid_params(
                request,
                "params._meta io.modelcontextprotocol/protocolVersion must be a string",
            ));
        }
        None => {
            return Err(invalid_params(
                request,
                "a modern request needs params._meta io.modelcontextprotocol/protocolVersion",
            ));
        }
    };
    if version.len() > MAX_VERSION_BYTES {
        return Err(invalid_params(
            request,
            "params._meta protocolVersion is too long",
        ));
    }
    match meta.get(META_CLIENT_CAPABILITIES) {
        Some(Value::Object(_)) => {}
        Some(_) => {
            return Err(invalid_params(
                request,
                "params._meta io.modelcontextprotocol/clientCapabilities must be an object",
            ));
        }
        None => {
            return Err(invalid_params(
                request,
                "a modern request needs params._meta io.modelcontextprotocol/clientCapabilities",
            ));
        }
    }

    // Only the modern version can be served statelessly. A `_meta` naming a
    // legacy version is refused rather than served without its handshake.
    if version != MODERN_VERSION {
        return Err(Rejected {
            error: ErrorObject::new(
                ErrorCode::UnsupportedProtocolVersion,
                "this server does not speak that protocol version here; use initialize for the legacy era",
            )
            .with_data(json!({
                "supported": SUPPORTED_VERSIONS,
                "requested": version,
            })),
            id: Some(request.id.clone()),
        });
    }

    let client_name = match meta.get(META_CLIENT_INFO) {
        Some(info) => Some(client_info_name(
            request,
            info,
            "params._meta io.modelcontextprotocol/clientInfo",
        )?),
        None => None,
    };
    Ok(Some(ModernMeta { client_name }))
}

/// Validate legacy `initialize` params and return the client name.
///
/// The requested version is read but not echoed: the answer is always
/// [`LEGACY_VERSION`], and the client decides whether it can continue. An
/// unreadable `protocolVersion` is still refused, because a handshake that
/// does not say what it speaks cannot be recorded as one.
fn initialize_params(request: &Request) -> Result<String, Rejected> {
    let Some(Value::Object(params)) = &request.params else {
        return Err(invalid_params(request, "initialize needs an object params"));
    };
    match params.get("protocolVersion") {
        Some(Value::String(_)) => {}
        Some(_) => {
            return Err(invalid_params(
                request,
                "initialize params.protocolVersion must be a string",
            ));
        }
        None => {
            return Err(invalid_params(
                request,
                "initialize needs params.protocolVersion",
            ));
        }
    }
    match params.get("capabilities") {
        Some(Value::Object(_)) => {}
        Some(_) => {
            return Err(invalid_params(
                request,
                "initialize params.capabilities must be an object",
            ));
        }
        None => {
            return Err(invalid_params(
                request,
                "initialize needs params.capabilities",
            ));
        }
    }
    match params.get("clientInfo") {
        Some(info) => client_info_name(request, info, "initialize params.clientInfo"),
        None => Err(invalid_params(
            request,
            "initialize needs params.clientInfo",
        )),
    }
}

/// Validate a `clientInfo` object and return its `name`.
fn client_info_name(request: &Request, info: &Value, label: &str) -> Result<String, Rejected> {
    let Value::Object(info) = info else {
        return Err(invalid_params(
            request,
            format!("{label} must be an object"),
        ));
    };
    let Some(Value::String(name)) = info.get("name") else {
        return Err(invalid_params(
            request,
            format!("{label}.name must be a string"),
        ));
    };
    if name.is_empty() || name.len() > MAX_CLIENT_NAME_BYTES {
        return Err(invalid_params(
            request,
            format!("{label}.name must be 1..={MAX_CLIENT_NAME_BYTES} bytes"),
        ));
    }
    Ok(name.clone())
}

/// A `-32600` rejection addressed to `request`.
///
/// Messages are fixed strings: nothing agent-supplied is echoed into an error
/// this module builds (the one deliberate echo is the `-32022` `requested`
/// payload, which is bounded before it is copied).
fn invalid_request(request: &Request, message: &'static str) -> Rejected {
    Rejected {
        error: ErrorObject::new(ErrorCode::InvalidRequest, message),
        id: Some(request.id.clone()),
    }
}

/// A `-32602` rejection addressed to `request`.
fn invalid_params(request: &Request, message: impl Into<String>) -> Rejected {
    Rejected {
        error: ErrorObject::new(ErrorCode::InvalidParams, message),
        id: Some(request.id.clone()),
    }
}

#[cfg(test)]
mod tests;
