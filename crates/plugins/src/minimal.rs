//! `minimal`: strips the authority and additional sections from positive
//! answers. Port of `plugin/minimal`.

use std::sync::Arc;
use std::time::SystemTime;

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::typify::{ResponseClass, ResponseType, typify};
use kerndns_core::{
    CaptureWriter, Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request,
    ResponseWriter, SetupError, async_trait, next_or_failure,
};

pub struct Minimal {
    next: Next,
}

#[async_trait]
impl Handler for Minimal {
    fn name(&self) -> &'static str {
        "minimal"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let mut nw = CaptureWriter::new();
        let rcode = next_or_failure("minimal", &self.next, ctx, &mut nw, req).await?;
        // like the nonwriter: only the last message counts
        let Some(mut m) = nw.msgs.pop() else { return Ok(rcode) };
        let ty = typify(&m, SystemTime::now());
        let class = ty.class();
        let write_err = |e: std::io::Error| PluginError::servfail("minimal", e.to_string());
        if class == ResponseClass::Denial || class == ResponseClass::Error || ty == ResponseType::Delegation {
            w.write_msg(m).await.map_err(write_err)?;
            return Ok(ResponseCode::NoError);
        }
        if ty != ResponseType::NoError {
            let name = req.name();
            w.write_msg(m).await.map_err(write_err)?;
            return Err(PluginError::new(
                "minimal",
                ResponseCode::NoError,
                format!("unhandled response type \"{ty:?}\" for \"{name}\""),
            ));
        }
        m.authorities.clear();
        m.additionals.clear();
        w.write_msg(m).await.map_err(write_err)?;
        Ok(ResponseCode::NoError)
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "minimal"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        c.next();
        if c.next_arg() {
            return Err(c.arg_err());
        }
        c.add_plugin(|next| Arc::new(Minimal { next }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::rr::rdata::{A, NS, SOA};
    use kerndns_core::proto::rr::{Name, RData, Record, RecordType};

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "minimal"));
        assert!(!setup_err(&Setup, "minimal x").is_empty());
    }

    #[tokio::test]
    async fn strips_positive_answers_only() {
        let h = Minimal {
            next: reply(|r| {
                let mut m = r.reply();
                if r.qname() == &n("www.example.org.") {
                    m.answers.push(Record::from_rdata(
                        n("www.example.org."),
                        60,
                        RData::A(A::new(192, 0, 2, 1)),
                    ));
                    m.authorities.push(Record::from_rdata(
                        n("example.org."),
                        60,
                        RData::NS(NS(n("ns.example.org."))),
                    ));
                    m.additionals.push(Record::from_rdata(
                        n("ns.example.org."),
                        60,
                        RData::A(A::new(192, 0, 2, 53)),
                    ));
                } else {
                    m.metadata.response_code = ResponseCode::NXDomain;
                    m.authorities.push(Record::from_rdata(
                        n("example.org."),
                        60,
                        RData::SOA(SOA::new(n("ns."), n("h."), 1, 1, 1, 1, 1)),
                    ));
                }
                m
            }),
        };
        let (_, w) = serve(&h, &query("www.example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(
            (
                w.msgs[0].answers.len(),
                w.msgs[0].authorities.len(),
                w.msgs[0].additionals.len()
            ),
            (1, 0, 0)
        );
        let (_, w) = serve(&h, &query("nx.example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(w.msgs[0].authorities.len(), 1, "denials keep their SOA");
    }
}
