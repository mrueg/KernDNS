//! `acl`: allows, blocks, filters or drops requests by client address and
//! query type. Port of `plugin/acl`.
//!
//! ```text
//! acl [ZONES...] {
//!     ACTION [type QTYPE...] [net SOURCE...]
//! }
//! ```
//!
//! ACTION is `allow`, `block` (REFUSED with EDE "Blocked"), `filter`
//! (empty NOERROR with EDE "Filtered") or `drop` (no answer).

use std::sync::Arc;

use kerndns_core::cidr::{IpNet, parse_cidr};
use kerndns_core::proto::op::{Edns, ResponseCode};
use kerndns_core::proto::rr::RecordType;
use kerndns_core::proto::rr::rdata::opt::EdnsOption;
use kerndns_core::zones;
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure,
};

use crate::pluginmetrics as pm;

/// RFC 8914 option code and the codes CoreDNS uses.
const EDE: u16 = 15;
const EDE_BLOCKED: u16 = 15;
const EDE_FILTERED: u16 = 17;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Action {
    Allow,
    Block,
    Filter,
    Drop,
}

struct Policy {
    action: Action,
    /// `None` matches every type.
    qtypes: Option<Vec<RecordType>>,
    /// `None` matches every address.
    nets: Option<Vec<IpNet>>,
}

struct Rule {
    zones: Vec<String>,
    policies: Vec<Policy>,
}

pub struct Acl {
    next: Next,
    rules: Arc<Vec<Rule>>,
}

/// `matchWithPolicies`: the first policy matching type and source.
fn decide(policies: &[Policy], req: &Request) -> Option<Action> {
    let (ip, qtype) = (req.ip(), req.qtype());
    policies
        .iter()
        .find(|p| {
            p.qtypes.as_ref().is_none_or(|t| t.contains(&qtype))
                && p.nets.as_ref().is_none_or(|n| n.iter().any(|n| n.contains(&ip)))
        })
        .map(|p| p.action)
}

async fn reply_ede(w: &mut dyn ResponseWriter, req: &Request, rcode: ResponseCode, info: u16) -> HandlerResult {
    let mut m = req.error_reply(rcode);
    let mut e = Edns::new();
    e.set_max_payload(4096);
    e.set_dnssec_ok(true);
    e.options_mut()
        .insert(EdnsOption::Unknown(EDE, info.to_be_bytes().to_vec()));
    m.edns = Some(e);
    w.write_msg(m)
        .await
        .map_err(|e| PluginError::servfail("acl", e.to_string()))?;
    Ok(ResponseCode::NoError)
}

#[async_trait]
impl Handler for Acl {
    fn name(&self) -> &'static str {
        "acl"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let name = req.name();
        let view = ctx.view.clone().unwrap_or_default();
        for rule in self.rules.iter() {
            let Some(zone) = zones::matches(&rule.zones, &name) else {
                continue;
            };
            match decide(&rule.policies, req) {
                Some(Action::Drop) => {
                    pm::ACL_DROPPED.with_label_values(&[&*ctx.server, zone, &view]).inc();
                    return Ok(ResponseCode::NoError);
                }
                Some(Action::Block) => {
                    pm::ACL_BLOCKED.with_label_values(&[&*ctx.server, zone, &view]).inc();
                    return reply_ede(w, req, ResponseCode::Refused, EDE_BLOCKED).await;
                }
                Some(Action::Filter) => {
                    pm::ACL_FILTERED.with_label_values(&[&*ctx.server, zone, &view]).inc();
                    return reply_ede(w, req, ResponseCode::NoError, EDE_FILTERED).await;
                }
                Some(Action::Allow) => break,
                None => {}
            }
        }
        pm::ACL_ALLOWED.with_label_values(&[&*ctx.server, &view]).inc();
        next_or_failure("acl", &self.next, ctx, w, req).await
    }
}

fn is_section(t: &str) -> bool {
    matches!(t.to_ascii_lowercase().as_str(), "type" | "net")
}

/// `normalize` and `net.ParseCIDR`: a bare address is a /32 or /128.
fn parse_net(s: &str) -> Option<IpNet> {
    let suffix = if s.contains('/') {
        ""
    } else if s.contains(':') {
        "/128"
    } else {
        "/32"
    };
    parse_cidr(&format!("{s}{suffix}")).ok()
}

fn parse_type(s: &str) -> Option<RecordType> {
    match s {
        "IXFR" => Some(RecordType::IXFR),
        _ => s
            .parse::<RecordType>()
            .ok()
            .filter(|t| !matches!(t, RecordType::Unknown(_))),
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "acl"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let keys = c.server_block_keys();
        let mut rules = Vec::new();
        while c.next() {
            let args = c.remaining_args();
            let mut rule = Rule {
                zones: zones::origins_from_args_or_server_block(&args, &keys),
                policies: Vec::new(),
            };
            while c.next_block() {
                let action = match c.val().to_ascii_lowercase().as_str() {
                    "allow" => Action::Allow,
                    "block" => Action::Block,
                    "filter" => Action::Filter,
                    "drop" => Action::Drop,
                    _ => {
                        let msg = format!(
                            "unexpected token {:?}; expect 'allow', 'block', 'filter' or 'drop'",
                            c.val()
                        );
                        return Err(c.errf(msg));
                    }
                };
                let mut p = Policy {
                    action,
                    qtypes: None,
                    nets: None,
                };
                let mut rest = c.remaining_args();
                while !rest.is_empty() {
                    if !is_section(&rest[0]) {
                        return Err(c.errf(format!("unexpected token {:?}; expect 'type | net'", rest[0])));
                    }
                    let section = rest[0].to_ascii_lowercase();
                    let n = rest[1..]
                        .iter()
                        .position(|t| is_section(t))
                        .map_or(rest.len(), |i| i + 1);
                    let tokens: Vec<String> = rest[1..n].to_vec();
                    rest.drain(..n);
                    if tokens.is_empty() {
                        return Err(c.errf(format!("no token specified in {section:?} section")));
                    }
                    if section == "type" {
                        let t = p.qtypes.get_or_insert_with(Vec::new);
                        for tok in &tokens {
                            if tok == "*" {
                                p.qtypes = None;
                                break;
                            }
                            let Some(q) = parse_type(tok) else {
                                return Err(c.errf(format!("unexpected token {tok:?}; expect legal QTYPE")));
                            };
                            t.push(q);
                        }
                    } else {
                        let nets = p.nets.get_or_insert_with(Vec::new);
                        for tok in &tokens {
                            if tok == "*" {
                                p.nets = None;
                                break;
                            }
                            let Some(n) = parse_net(tok) else {
                                return Err(c.errf(format!("illegal CIDR notation {tok:?}")));
                            };
                            nets.push(n);
                        }
                    }
                }
                rule.policies.push(p);
            }
            rules.push(rule);
        }
        let rules = Arc::new(rules);
        c.add_plugin(move |next| {
            Arc::new(Acl {
                next,
                rules: rules.clone(),
            })
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    /// The handler `conf` sets up, in front of a plain answering plugin.
    fn handler(conf: &str) -> Arc<dyn Handler> {
        let (r, cfg) = run_setup(&Setup, conf);
        r.unwrap();
        (cfg.plugins[0].1)(reply(|r| r.reply()))
    }

    async fn ask(h: &Arc<dyn Handler>, qtype: RecordType, from: &str) -> Option<(ResponseCode, Option<u16>)> {
        let (_, w) = serve(h.as_ref(), &query("www.example.org.", qtype, from)).await;
        let m = w.msgs.first()?;
        let ede = m.edns.as_ref().and_then(|e| match e.option(EDE.into()) {
            Some(EdnsOption::Unknown(_, d)) => Some(u16::from_be_bytes([d[0], d[1]])),
            _ => None,
        });
        Some((m.metadata.response_code, ede))
    }

    #[tokio::test]
    async fn actions() {
        let h = handler(
            "acl {\n allow net 192.168.1.1\n block type A net 192.168.0.0/16\n filter type AAAA\n drop net 10.0.0.0/8\n}",
        );
        assert_eq!(
            ask(&h, RecordType::A, "192.168.1.1:53").await,
            Some((ResponseCode::NoError, None))
        );
        assert_eq!(
            ask(&h, RecordType::A, "192.168.2.2:53").await,
            Some((ResponseCode::Refused, Some(EDE_BLOCKED)))
        );
        assert_eq!(
            ask(&h, RecordType::AAAA, "172.16.0.1:53").await,
            Some((ResponseCode::NoError, Some(EDE_FILTERED)))
        );
        assert_eq!(ask(&h, RecordType::MX, "10.1.2.3:53").await, None, "dropped");
        assert_eq!(ask(&h, RecordType::MX, "[::ffff:10.1.2.3]:53").await, None, "v4-mapped");
        assert_eq!(
            ask(&h, RecordType::MX, "172.16.0.1:53").await,
            Some((ResponseCode::NoError, None))
        );
    }

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "acl {\n block type A net 192.168.0.0/16\n allow\n}"));
        assert!(setup_ok(
            &Setup,
            "acl example.org {\n filter type * net *\n drop net 10.0.0.1 ::1\n}"
        ));
        assert!(setup_err(&Setup, "acl {\n deny\n}").contains("expect 'allow', 'block'"));
        assert!(setup_err(&Setup, "acl {\n block foo\n}").contains("expect 'type | net'"));
        assert!(setup_err(&Setup, "acl {\n block type\n}").contains("no token specified"));
        assert!(setup_err(&Setup, "acl {\n block type XYZ\n}").contains("legal QTYPE"));
        assert!(setup_err(&Setup, "acl {\n block net 10.0.0.0/33\n}").contains("illegal CIDR"));
    }
}
