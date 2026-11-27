//! `cancel`: gives up on a request after a timeout (5001ms by default).
//! Port of `plugin/cancel`: CoreDNS cancels the request's context, here
//! the rest of the chain is abandoned and the server answers SERVFAIL
//! unless a response was already written.
//!
//! ```text
//! cancel [TIMEOUT]
//! ```

use std::sync::Arc;
use std::time::Duration;

use kerndns_core::duration::parse_duration;
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure,
};

pub struct Cancel {
    next: Next,
    timeout: Duration,
}

#[async_trait]
impl Handler for Cancel {
    fn name(&self) -> &'static str {
        "cancel"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        match tokio::time::timeout(self.timeout, next_or_failure("cancel", &self.next, ctx, w, req)).await {
            Ok(r) => r,
            Err(_) => Err(PluginError::servfail("cancel", "context deadline exceeded")),
        }
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "cancel"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let err = |m: String| SetupError::new("cancel", m);
        let mut timeout = Duration::from_millis(5001);
        while c.next() {
            let args = c.remaining_args();
            match args.as_slice() {
                [] => timeout = Duration::from_millis(5001),
                [d] => {
                    if d.starts_with('-') {
                        return Err(err(format!("invalid negative duration: {d:?}")));
                    }
                    timeout = parse_duration(d).map_err(|_| err(format!("invalid duration: {d:?}")))?;
                    if timeout.is_zero() {
                        return Err(err(format!("invalid negative duration: {d:?}")));
                    }
                }
                _ => return Err(c.arg_err()),
            }
        }
        c.add_plugin(move |next| Arc::new(Cancel { next, timeout }));
        Ok(())
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
        assert!(setup_ok(&Setup, "cancel"));
        assert!(setup_ok(&Setup, "cancel 1s"));
        assert!(setup_err(&Setup, "cancel abc").contains("invalid duration"));
        assert!(setup_err(&Setup, "cancel -1s").contains("invalid negative duration"));
        assert!(!setup_err(&Setup, "cancel 1s 2s").is_empty());
    }

    struct Slow;

    #[async_trait]
    impl Handler for Slow {
        fn name(&self) -> &'static str {
            "slow"
        }
        async fn serve_dns(&self, _: &mut Context, _: &mut dyn ResponseWriter, _: &Request) -> HandlerResult {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(ResponseCode::NoError)
        }
    }

    #[tokio::test]
    async fn times_out() {
        let h = Cancel {
            next: Some(Arc::new(Slow)),
            timeout: Duration::from_millis(20),
        };
        let (r, w) = serve(&h, &query("example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(r.unwrap_err().rcode, ResponseCode::ServFail);
        assert!(w.msgs.is_empty());
    }
}
