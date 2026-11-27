//! `bufsize`: caps the EDNS UDP buffer size of requests. Port of
//! `plugin/bufsize`.
//!
//! ```text
//! bufsize [SIZE]
//! ```

use std::sync::Arc;

use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};

const DEFAULT: u16 = 1232;

pub struct Bufsize {
    next: Next,
    size: u16,
}

#[async_trait]
impl Handler for Bufsize {
    fn name(&self) -> &'static str {
        "bufsize"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        if req.edns().is_some_and(|e| e.max_payload() > self.size) {
            let mut r = req.clone();
            if let Some(e) = r.msg.edns.as_mut() {
                e.set_max_payload(self.size);
            }
            // the server echoes and truncates to this size too
            ctx.bufsize = Some(self.size);
            return next_or_failure("bufsize", &self.next, ctx, w, &r).await;
        }
        next_or_failure("bufsize", &self.next, ctx, w, req).await
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "bufsize"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        // like CoreDNS, only the first `bufsize` line is read
        if !c.next() {
            return Err(c.arg_err());
        }
        let args = c.remaining_args();
        let size = match args.as_slice() {
            [] => DEFAULT,
            [s] => match s.parse::<u16>() {
                Ok(n) if (512..=4096).contains(&n) => n,
                _ => return Err(c.arg_err()),
            },
            _ => return Err(c.arg_err()),
        };
        c.add_plugin(move |next| Arc::new(Bufsize { next, size }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::op::Edns;
    use kerndns_core::proto::rr::RecordType;
    use std::sync::Mutex;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "bufsize"));
        assert!(setup_ok(&Setup, "bufsize 512"));
        assert!(!setup_err(&Setup, "bufsize 511").is_empty());
        assert!(!setup_err(&Setup, "bufsize 4097").is_empty());
        assert!(!setup_err(&Setup, "bufsize 1 2").is_empty());
    }

    #[tokio::test]
    async fn caps_the_request() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        let h = Bufsize {
            next: reply(move |r| {
                s2.lock().unwrap().push(r.bufsize());
                r.reply()
            }),
            size: 1232,
        };
        for size in [4096, 1000] {
            let mut q = query("example.org.", RecordType::A, "10.0.0.1:53");
            let mut e = Edns::new();
            e.set_max_payload(size);
            q.msg.edns = Some(e);
            let _ = serve(&h, &q).await;
        }
        let _ = serve(&h, &query("example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(*seen.lock().unwrap(), vec![1232, 1000, 0]);
    }
}
