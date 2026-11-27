//! `local`: answers queries for `localhost.`, `0.in-addr.arpa.`,
//! `127.in-addr.arpa.` and `255.in-addr.arpa.` (and subdomains of
//! `localhost.`) itself. Port of `plugin/local`.
//!
//! ```text
//! local {
//!     localhost_prefix on|off
//! }
//! ```

use std::sync::Arc;

use kerndns_core::proto::op::{Message, ResponseCode};
use kerndns_core::proto::rr::rdata::{A, AAAA, NS, PTR, SOA};
use kerndns_core::proto::rr::{Name, RData, Record, RecordType};
use kerndns_core::zones;
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure,
};

const TTL: u32 = 604800;
const ZONES: [&str; 4] = [
    "localhost.",
    "0.in-addr.arpa.",
    "127.in-addr.arpa.",
    "255.in-addr.arpa.",
];

fn n(s: &str) -> Name {
    Name::from_ascii(s).expect("static name")
}

fn soa(origin: &Name) -> Vec<Record> {
    vec![Record::from_rdata(
        origin.clone(),
        TTL,
        RData::SOA(SOA::new(n("localhost."), n("root.localhost."), 1, 0, 0, 0, TTL)),
    )]
}

pub struct Local {
    next: Next,
    no_prefix: bool,
}

/// `doLocalhost`: answers for names below `localhost.`.
fn localhost(req: &Request) -> Message {
    let mut m = req.reply();
    let q = req.qname().clone();
    match req.qtype() {
        RecordType::A => m.answers = vec![Record::from_rdata(q, TTL, RData::A(A::new(127, 0, 0, 1)))],
        RecordType::AAAA => {
            m.answers = vec![Record::from_rdata(
                q,
                TTL,
                RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)),
            )]
        }
        _ => m.authorities = soa(&q),
    }
    m
}

#[async_trait]
impl Handler for Local {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let werr = |e: std::io::Error| PluginError::servfail("local", e.to_string());
        let name = req.name();
        let lc = "localhost.".len();
        let rfc_sub = name.len() > lc && name.ends_with(".localhost.");
        let legacy = name.len() > lc && !self.no_prefix && name.starts_with("localhost.");
        if rfc_sub || legacy {
            kerndns_core::debug!(
                plugin = "local",
                "Intercepting localhost query for {name:?} {}, from {}",
                req.qtype(),
                req.ip()
            );
            crate::pluginmetrics::LOCALHOST_REQUESTS.inc();
            w.write_msg(localhost(req)).await.map_err(werr)?;
            return Ok(ResponseCode::NoError);
        }
        let zs: Vec<String> = ZONES.iter().map(|z| z.to_string()).collect();
        let Some(zone) = zones::matches(&zs, &name) else {
            return next_or_failure("local", &self.next, ctx, w, req).await;
        };
        let qname = req.qname().clone();
        // the zone with the asking case, like `qname[len(qname)-len(zone):]`
        let zone_name = qname.trim_to(n(zone).num_labels() as usize);
        let mut m = req.reply();
        let qtype = req.qtype();
        match name.as_str() {
            "localhost." | "0.in-addr.arpa." | "127.in-addr.arpa." | "255.in-addr.arpa." => match qtype {
                RecordType::A if name == "localhost." => {
                    m.answers = vec![Record::from_rdata(qname, TTL, RData::A(A::new(127, 0, 0, 1)))]
                }
                RecordType::AAAA if name == "localhost." => {
                    m.answers = vec![Record::from_rdata(
                        qname,
                        TTL,
                        RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    )]
                }
                RecordType::SOA => m.answers = soa(&qname),
                RecordType::NS => m.answers = vec![Record::from_rdata(qname, TTL, RData::NS(NS(n("localhost."))))],
                _ => m.authorities = soa(&qname),
            },
            "1.0.0.127.in-addr.arpa." => match qtype {
                RecordType::PTR => m.answers = vec![Record::from_rdata(qname, TTL, RData::PTR(PTR(n("localhost."))))],
                _ => m.authorities = soa(&zone_name),
            },
            _ => {}
        }
        if m.answers.is_empty() && m.authorities.is_empty() {
            m.authorities = soa(&zone_name);
            m.metadata.response_code = ResponseCode::NXDomain;
        }
        w.write_msg(m).await.map_err(werr)?;
        Ok(ResponseCode::NoError)
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "local"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut no_prefix = false;
        while c.next() {
            if !c.remaining_args().is_empty() {
                return Err(c.arg_err());
            }
            while c.next_block() {
                match c.val() {
                    "localhost_prefix" => {
                        let a = c.remaining_args();
                        if a.len() != 1 {
                            return Err(c.arg_err());
                        }
                        no_prefix = match a[0].as_str() {
                            "on" => false,
                            "off" => true,
                            other => {
                                return Err(c.errf(format!("localhost_prefix expects 'on' or 'off', got {other:?}")));
                            }
                        };
                    }
                    other => {
                        let msg = format!("unknown property '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
        }
        c.add_plugin(move |next| Arc::new(Local { next, no_prefix }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "local"));
        assert!(setup_ok(&Setup, "local {\n localhost_prefix off\n}"));
        assert!(setup_err(&Setup, "local {\n localhost_prefix maybe\n}").contains("expects 'on' or 'off'"));
        assert!(!setup_err(&Setup, "local x").is_empty());
    }

    async fn ask(name: &str, t: RecordType) -> Message {
        let h = Local {
            next: None,
            no_prefix: false,
        };
        let (_, mut w) = serve(&h, &query(name, t, "10.0.0.1:53")).await;
        w.msgs.remove(0)
    }

    #[tokio::test]
    async fn answers() {
        let m = ask("localhost.", RecordType::A).await;
        assert!(matches!(m.answers[0].data, RData::A(a) if a.0.is_loopback()));
        let m = ask("app.localhost.", RecordType::AAAA).await;
        assert!(matches!(m.answers[0].data, RData::AAAA(a) if a.0.is_loopback()));
        let m = ask("localhost.example.org.", RecordType::A).await;
        assert_eq!(m.answers.len(), 1, "legacy localhost. prefix");
        let m = ask("1.0.0.127.in-addr.arpa.", RecordType::PTR).await;
        assert!(matches!(&m.answers[0].data, RData::PTR(p) if p.0 == n("localhost.")));
        let m = ask("2.0.0.127.in-addr.arpa.", RecordType::PTR).await;
        assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(m.authorities[0].name, n("127.in-addr.arpa."));
    }
}
