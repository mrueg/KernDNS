//! `nsid`: adds the RFC 5001 name server identifier to responses for
//! requests that ask for it. Port of `plugin/nsid`.
//!
//! ```text
//! nsid [DATA]
//! ```

use std::sync::Arc;

use kerndns_core::proto::op::{Edns, Message};
use kerndns_core::proto::rr::rdata::opt::{EdnsCode, EdnsOption, NSIDPayload};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};

pub struct Nsid {
    next: Next,
    data: Arc<[u8]>,
}

struct NsidWriter<'a> {
    inner: &'a mut dyn ResponseWriter,
    data: &'a [u8],
    req: &'a Request,
}

#[async_trait]
impl ResponseWriter for NsidWriter<'_> {
    async fn write_msg(&mut self, mut m: Message) -> std::io::Result<()> {
        if m.edns.is_none()
            && let Some(e) = self.req.edns()
        {
            let mut opt = Edns::new();
            opt.set_max_payload(e.max_payload());
            opt.set_dnssec_ok(true);
            m.edns = Some(opt);
        }
        if let Some(opt) = m.edns.as_mut()
            && let Ok(p) = NSIDPayload::new(self.data.to_vec())
        {
            // replaces an NSID another plugin set, like CoreDNS
            opt.options_mut().remove(EdnsCode::NSID);
            opt.options_mut().insert(EdnsOption::NSID(p));
        }
        self.inner.write_msg(m).await
    }
}

#[async_trait]
impl Handler for Nsid {
    fn name(&self) -> &'static str {
        "nsid"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let asked = req.edns().is_some_and(|e| e.option(EdnsCode::NSID).is_some());
        if !asked {
            return next_or_failure("nsid", &self.next, ctx, w, req).await;
        }
        let mut nw = NsidWriter {
            inner: w,
            data: &self.data,
            req,
        };
        next_or_failure("nsid", &self.next, ctx, &mut nw, req).await
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "nsid"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut data = hostname();
        let mut seen = false;
        while c.next() {
            if seen {
                return Err(SetupError::new(
                    "nsid",
                    "this plugin can only be used once per Server Block",
                ));
            }
            seen = true;
            let args = c.remaining_args();
            if !args.is_empty() {
                data = args.join(" ");
            }
        }
        let data: Arc<[u8]> = Arc::from(data.into_bytes());
        c.add_plugin(move |next| {
            Arc::new(Nsid {
                next,
                data: data.clone(),
            })
        });
        Ok(())
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "localhost".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::rr::RecordType;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "nsid"));
        assert!(setup_ok(&Setup, "nsid kerndns one"));
        assert!(setup_err(&Setup, "nsid a\nnsid b").contains("only be used once"));
    }

    fn nsid_of(m: &Message) -> Option<Vec<u8>> {
        match m.edns.as_ref()?.option(EdnsCode::NSID)? {
            EdnsOption::NSID(p) => Some(p.as_ref().to_vec()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn only_when_asked() {
        let h = Nsid {
            next: reply(|r| r.reply()),
            data: Arc::from(&b"kerndns"[..]),
        };
        let mut q = query("example.org.", RecordType::A, "10.0.0.1:53");
        let (_, w) = serve(&h, &q).await;
        assert_eq!(nsid_of(&w.msgs[0]), None);

        let mut e = Edns::new();
        e.options_mut()
            .insert(EdnsOption::NSID(NSIDPayload::new(Vec::new()).unwrap()));
        q.msg.edns = Some(e);
        let (_, w) = serve(&h, &q).await;
        assert_eq!(nsid_of(&w.msgs[0]), Some(b"kerndns".to_vec()));
    }
}
