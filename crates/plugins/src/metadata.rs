//! `metadata`: makes plugins' metadata (e.g. `view/name`) available to
//! other plugins for requests in its zones. Port of `plugin/metadata`.
//!
//! ```text
//! metadata [ZONES...]
//! ```
//!
//! The server collects it before a block's filters and plugins run
//! ([`kerndns_core::plugin::Metadata`]); providers in KernDNS: `view`.

use std::sync::Arc;

use kerndns_core::plugin::Metadata;
use kerndns_core::zones;
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};

pub struct MetadataPlugin {
    next: Next,
}

#[async_trait]
impl Handler for MetadataPlugin {
    fn name(&self) -> &'static str {
        "metadata"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        next_or_failure("metadata", &self.next, ctx, w, req).await
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "metadata"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let keys = c.server_block_keys();
        c.next();
        let args = c.remaining_args();
        let zs = zones::origins_from_args_or_server_block(&args, &keys);
        if c.next_block() || c.next() {
            return Err(c.arg_err());
        }
        Metadata::of(c.config).enable(zs);
        c.add_plugin(|next| Arc::new(MetadataPlugin { next }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "metadata"));
        assert!(setup_ok(&Setup, "metadata example.org"));
        let (r, cfg) = run_setup(&Setup, "metadata");
        assert!(r.is_ok());
        assert!(Metadata::enabled_in(&cfg).is_some());
        assert!(!setup_err(&Setup, "metadata {\n foo\n}").is_empty());
        assert!(!setup_err(&Setup, "metadata\nmetadata").is_empty());
    }
}
