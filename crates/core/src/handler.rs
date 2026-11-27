//! The plugin handler model, mirroring CoreDNS's `plugin.Handler`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use hickory_proto::op::{Edns, ResponseCode};

use crate::request::Request;
use crate::response::ResponseWriter;

/// The rest of the chain after a plugin. `None` means this plugin is last.
pub type Next = Option<Arc<dyn Handler>>;

/// What a handler returns: the response code it produced, or an error.
///
/// Return a code for which [`client_write`] is true (e.g. `NoError`,
/// `NXDomain`) only if you wrote a response. For `ServFail`, `Refused`,
/// `FormErr` and `NotImp` the server writes the error response for you.
pub type HandlerResult = Result<ResponseCode, PluginError>;

/// A DNS handler: one plugin, or a whole chain (its first plugin).
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    /// The plugin name, used in errors and metrics.
    fn name(&self) -> &'static str;

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult;
}

/// An error from a plugin, displayed as `plugin/<name>: <msg>` like
/// CoreDNS's `plugin.Error`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("plugin/{plugin}: {msg}")]
pub struct PluginError {
    pub plugin: String,
    /// The response code the server uses if nobody wrote a response.
    pub rcode: ResponseCode,
    pub msg: String,
}

impl PluginError {
    pub fn new(plugin: impl Into<String>, rcode: ResponseCode, msg: impl Into<String>) -> Self {
        Self {
            plugin: plugin.into(),
            rcode,
            msg: msg.into(),
        }
    }

    pub fn servfail(plugin: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::new(plugin, ResponseCode::ServFail, msg)
    }
}

/// Per-request state passed down the chain (CoreDNS uses `context.Context`).
#[derive(Clone)]
pub struct Context {
    /// The server block zone that matched, e.g. `example.org.`.
    pub zone: Arc<str>,
    /// The listener, e.g. `dns://:53`.
    pub server: Arc<str>,
    /// Values set by the `metadata` plugin and others, `plugin/key` -> value.
    pub metadata: HashMap<String, String>,
    /// Name of the `view` that matched, if any.
    pub view: Option<String>,
    /// When the server received the request.
    pub start: Instant,
    /// Resolves names through the server that received the request.
    pub upstream: Option<Arc<dyn crate::upstream::Upstream>>,
    /// How many times this request has been re-resolved internally (CNAME
    /// chasing through `upstream`); see [`crate::upstream::MAX_LOOP`].
    pub loop_count: u8,
    /// Set on the internal lookups a translation plugin (`siit`) makes
    /// while synthesizing an answer, and inherited by every lookup made
    /// under them, so translation plugins don't re-enter each other.
    pub synthesis: bool,
    /// Signs every encoded response (set by `tsig`).
    pub signer: Option<Arc<dyn ResponseSigner>>,
    /// The normalized name of the TSIG key that `tsig` validated for this
    /// request (`tsig.ValidatedKeyName`).
    pub tsig_key: Option<String>,
    /// Run once the response is encoded, with the bytes sent (all messages
    /// together). `prometheus` reports its metrics here, so the response
    /// is not encoded a second time just to measure it.
    pub on_sent: Vec<SentHook>,
    /// The EDNS UDP size to treat the request as having (set by
    /// `bufsize`); the server echoes it and truncates UDP answers to it,
    /// as CoreDNS does after `bufsize` rewrites the request.
    pub bufsize: Option<u16>,
    /// The request's OPT record as a plugin rewrote it (`rewrite edns0`).
    /// CoreDNS plugins change the request in place, so the server answers
    /// as if the client had sent this one: it echoes it and truncates UDP
    /// answers to its size.
    pub edns: Option<Box<Edns>>,
}

/// See [`Context::on_sent`].
pub type SentHook = Arc<dyn Fn(usize) + Send + Sync>;

/// Signs a response after its final encoding (and truncation), like the
/// TSIG signing miekg/dns does when writing. Called once per message, in
/// order, so multi-message answers (zone transfers) can chain MACs.
pub trait ResponseSigner: Send + Sync {
    fn sign(&self, wire: Vec<u8>) -> Vec<u8>;
}

impl Context {
    pub fn new(zone: impl Into<Arc<str>>, server: impl Into<Arc<str>>) -> Self {
        Self {
            zone: zone.into(),
            server: server.into(),
            metadata: HashMap::new(),
            view: None,
            start: Instant::now(),
            upstream: None,
            loop_count: 0,
            synthesis: false,
            signer: None,
            tsig_key: None,
            on_sent: Vec::new(),
            bufsize: None,
            edns: None,
        }
    }
}

/// True if a handler returning `rcode` has written the response itself,
/// like CoreDNS's `plugin.ClientWrite`.
pub fn client_write(rcode: ResponseCode) -> bool {
    !matches!(
        rcode,
        ResponseCode::ServFail | ResponseCode::Refused | ResponseCode::FormErr | ResponseCode::NotImp
    )
}

/// Call the next handler, or fail with SERVFAIL if there is none, like
/// `plugin.NextOrFailure`.
pub async fn next_or_failure(
    name: &'static str,
    next: &Next,
    ctx: &mut Context,
    w: &mut dyn ResponseWriter,
    req: &Request,
) -> HandlerResult {
    match next {
        Some(h) => h.serve_dns(ctx, w, req).await,
        None => Err(PluginError::servfail(name, "no next plugin found")),
    }
}

/// The response code to act on for a handler result: the code, or the
/// error's code.
pub fn result_rcode(r: &HandlerResult) -> ResponseCode {
    match r {
        Ok(rc) => *rc,
        Err(e) => e.rcode,
    }
}
