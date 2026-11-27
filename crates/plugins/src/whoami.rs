//! `whoami`: answers with the client's address, port and transport.
//! Port of `plugin/whoami`.

use std::sync::Arc;

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::rdata::{A, AAAA, SRV};
use kerndns_core::proto::rr::{Name, RData, Record};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait,
};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "whoami"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        c.next(); // "whoami"
        if c.next_arg() {
            return Err(c.arg_err());
        }
        c.add_plugin(|_next| Arc::new(Whoami));
        Ok(())
    }
}

/// The handler. It never calls the next plugin.
pub struct Whoami;

#[async_trait]
impl Handler for Whoami {
    fn name(&self) -> &'static str {
        "whoami"
    }

    async fn serve_dns(&self, _ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let mut a = req.reply();
        a.metadata.authoritative = true;

        let qname = req.qname().clone();
        let class = req.qclass();
        let addr = match req.ip() {
            std::net::IpAddr::V4(ip) => RData::A(A(ip)),
            std::net::IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
        };
        let mut rr = Record::from_rdata(qname.clone(), 0, addr);
        rr.dns_class = class;

        let label = format!("_{}", req.proto());
        let srv_name = if qname.is_root() {
            Name::from_ascii(format!("{label}.")).expect("valid label")
        } else {
            qname.prepend_label(label.as_str()).unwrap_or(qname)
        };
        let mut srv = Record::from_rdata(srv_name, 0, RData::SRV(SRV::new(0, 0, req.port(), Name::root())));
        srv.dns_class = class;

        a.additionals = vec![rr, srv];
        w.write_msg(a)
            .await
            .map_err(|e| PluginError::servfail("whoami", e.to_string()))?;
        Ok(ResponseCode::NoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::rr::RecordType;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "whoami"));
        let err = setup_err(&Setup, "whoami example.org");
        assert_eq!(
            err,
            "plugin/whoami: Corefile:2 - Error during parsing: Wrong argument count or unexpected line ending after 'example.org'"
        );
    }

    #[tokio::test]
    async fn answers() {
        for (qname, srv) in [("example.org.", "_udp.example.org."), (".", "_udp.")] {
            let req = query(qname, RecordType::A, "10.240.0.1:40212");
            let (rc, w) = serve(&Whoami, &req).await;
            assert_eq!(rc.unwrap(), ResponseCode::NoError);
            let m = w.msg().unwrap();
            assert!(m.metadata.authoritative);
            assert!(m.answers.is_empty());
            assert_eq!(m.additionals[0].to_string(), format!("{qname} 0 IN A 10.240.0.1"));
            assert_eq!(m.additionals[1].to_string(), format!("{srv} 0 IN SRV 0 0 40212 ."));
        }
        let req = query("example.org.", RecordType::A, "[2001:db8::1]:53");
        let (_, w) = serve(&Whoami, &req).await;
        assert_eq!(w.msg().unwrap().additionals[0].record_type(), RecordType::AAAA);
    }
}
