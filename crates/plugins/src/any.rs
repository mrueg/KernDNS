//! `any`: answers ANY queries with the RFC 8482 HINFO record. Port of
//! `plugin/any`.

use std::sync::Arc;

use kerndns_core::proto::rr::rdata::HINFO;
use kerndns_core::proto::rr::{RData, Record, RecordType};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};

pub struct Any {
    next: Next,
}

#[async_trait]
impl Handler for Any {
    fn name(&self) -> &'static str {
        "any"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        if req.qtype() != RecordType::ANY {
            return next_or_failure("any", &self.next, ctx, w, req).await;
        }
        let mut m = req.reply();
        m.answers = vec![Record::from_rdata(
            req.qname().clone(),
            8482,
            RData::HINFO(HINFO::new("ANY obsoleted".into(), "See RFC 8482".into())),
        )];
        // like CoreDNS, a failed write is not reported
        let _ = w.write_msg(m).await;
        Ok(kerndns_core::proto::op::ResponseCode::NoError)
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "any"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        c.next();
        if c.next_arg() {
            return Err(c.arg_err());
        }
        if c.next_block() {
            let msg = format!("unknown property '{}'", c.val());
            return Err(c.errf(msg));
        }
        c.add_plugin(|next| Arc::new(Any { next }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "any"));
        assert!(!setup_err(&Setup, "any x").is_empty());
        // like caddy, `{` on the directive's line counts as an argument
        assert!(setup_err(&Setup, "any {\n foo\n}").contains("Unexpected token '{'"));
    }

    #[tokio::test]
    async fn answers_any() {
        let h = Any { next: None };
        let (r, w) = serve(&h, &query("example.org.", RecordType::ANY, "10.0.0.1:53")).await;
        assert!(r.is_ok());
        let a = &w.msgs[0].answers[0];
        assert_eq!(a.ttl, 8482);
        assert!(matches!(&a.data, RData::HINFO(h) if &*h.cpu == b"ANY obsoleted"));
    }
}
