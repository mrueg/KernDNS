//! `errors`: logs errors returned by the plugins after it. Port of
//! `plugin/errors` (without `consolidate`, which is not ported yet).

use std::sync::Arc;

use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "errors"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut seen = false;
        while c.next() {
            if seen {
                return Err(c.errf("errors plugin can only be used once per Server Block"));
            }
            seen = true;
            let args = c.remaining_args();
            match args.as_slice() {
                [] => {}
                [a] if a == "stdout" => {}
                _ => return Err(c.arg_err()),
            }
            while c.next_block() {
                match c.val() {
                    "stacktrace" => {
                        if c.next_arg() {
                            return Err(c.arg_err());
                        }
                    }
                    "consolidate" => {
                        return Err(c.errf("'consolidate' is not supported by KernDNS yet"));
                    }
                    _ => return Err(c.syntax_err("stacktrace or consolidate")),
                }
            }
        }
        c.add_plugin(|next| Arc::new(Errors { next }));
        Ok(())
    }
}

pub struct Errors {
    next: Next,
}

#[async_trait]
impl Handler for Errors {
    fn name(&self) -> &'static str {
        "errors"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let res = next_or_failure("errors", &self.next, ctx, w, req).await;
        if let Err(e) = &res {
            kerndns_core::error!(
                plugin = "errors",
                "{} {} {}: {}",
                u16::from(e.rcode),
                req.name(),
                req.qtype(),
                e
            );
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::op::ResponseCode;
    use kerndns_core::proto::rr::RecordType;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "errors"));
        assert!(setup_ok(&Setup, "errors stdout"));
        assert!(setup_ok(&Setup, "errors {\n stacktrace\n}"));
        assert!(setup_err(&Setup, "errors a b").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "errors\nerrors").contains("only be used once"));
    }

    #[tokio::test]
    async fn passes_errors_through() {
        let h = Errors { next: None };
        let (res, _) = serve(&h, &query("example.org.", RecordType::A, "10.0.0.1:1")).await;
        let e = res.unwrap_err();
        assert_eq!(e.rcode, ResponseCode::ServFail);
        assert_eq!(e.to_string(), "plugin/errors: no next plugin found");
    }
}
