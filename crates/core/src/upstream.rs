//! Resolving a name through the server itself, like CoreDNS's
//! `plugin/pkg/upstream`: `file` uses it for CNAME targets outside its zone.

use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};

use crate::handler::{Context, PluginError};
use crate::request::Request;

/// Plugins chain lookups deeper than this get SERVFAIL (CoreDNS's loop limit).
pub const MAX_LOOP: u8 = 8;

#[async_trait]
pub trait Upstream: Send + Sync {
    /// Ask the server that received `req` for `name`/`qtype` (class IN).
    /// `Ok(None)` means the server wrote no response.
    async fn lookup(
        &self,
        ctx: &Context,
        req: &Request,
        name: &Name,
        qtype: RecordType,
    ) -> Result<Option<Message>, PluginError>;
}

/// Resolve through `ctx.upstream`, or fail if the request didn't come
/// through a server (e.g. in unit tests).
pub async fn lookup(
    ctx: &Context,
    req: &Request,
    name: &Name,
    qtype: RecordType,
) -> Result<Option<Message>, PluginError> {
    match &ctx.upstream {
        Some(u) => u.lookup(ctx, req, name, qtype).await,
        None => Err(PluginError::servfail("upstream", "no full server is running")),
    }
}
