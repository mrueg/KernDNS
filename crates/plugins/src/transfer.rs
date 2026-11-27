//! `transfer`: serves zone transfers (AXFR, IXFR with AXFR fallback) out of
//! zone sources such as `file`, and sends NOTIFYs when they change. Port of
//! `plugin/transfer`.
//!
//! ```text
//! transfer [ZONE...] {
//!     to ADDRESS...
//!     source ADDRESS
//! }
//! ```

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use kerndns_core::proto::rr::{Name, RData, Record, RecordType};
use kerndns_core::transfer::{Notifier, TransferError, TransferRegistry};
use kerndns_core::wire::{self, RecordSizer};
use kerndns_core::zones;
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure,
};

use crate::forward::proxy::rand_id;

/// Messages stay below this many bytes of (uncompressed) records.
const BATCH_BYTES: usize = 63000;
/// Encoded messages must stay below the TCP limit with room for a TSIG.
const MAX_ENCODED: usize = 64000;
/// The DNS message header.
const HEADER: usize = 12;

#[derive(Debug, Clone)]
struct Xfr {
    zones: Vec<String>,
    /// `*` or `ip:port`.
    to: Vec<String>,
    source: Option<IpAddr>,
}

impl Xfr {
    fn allowed(&self, ip: IpAddr) -> bool {
        self.to.iter().any(|t| {
            t == "*"
                || t.parse::<SocketAddr>()
                    .ok()
                    .map(|sa| sa.ip())
                    .or_else(|| split_zone(t).map(|z| IpAddr::V6(z.0)))
                    .is_some_and(|a| a.to_canonical() == ip.to_canonical())
        })
    }
}

/// The longest zone match among the stanzas (ties broken by name).
fn longest_match<'a>(xfrs: &'a [Xfr], name: &str) -> Option<&'a Xfr> {
    let mut best: Option<(&str, &Xfr)> = None;
    for x in xfrs {
        if let Some(z) = zones::matches(&x.zones, name) {
            let better = match best {
                None => true,
                Some((bz, _)) => z.len() > bz.len() || (z.len() == bz.len() && z > bz),
            };
            if better {
                best = Some((z, x));
            }
        }
    }
    best.map(|(_, x)| x)
}

/// `ip`, `ip:port`, `[v6]:port` → `ip:port` (port 53 by default). An IPv6
/// address may carry a zone (`[fe80::1%eth0]:53`), which is kept, like
/// `parse.HostPort`.
fn host_port(s: &str) -> Result<String, String> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa.to_string());
    }
    if let Some((ip, zone, port)) = split_zone(s) {
        return Ok(format!("[{ip}%{zone}]:{}", port.unwrap_or(53)));
    }
    let ip: IpAddr = s
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .map_err(|_| format!("not an IP address: {s:?}"))?;
    Ok(SocketAddr::new(ip, 53).to_string())
}

/// An IPv6 address with a zone: `fe80::1%eth0`, `[fe80::1%eth0]` or
/// `[fe80::1%eth0]:53`.
fn split_zone(s: &str) -> Option<(Ipv6Addr, &str, Option<u16>)> {
    let (host, port) = match s.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']')?;
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':')?.parse().ok()?),
            };
            (host, port)
        }
        None => (s, None),
    };
    let (ip, zone) = host.split_once('%')?;
    if zone.is_empty() {
        return None;
    }
    Some((ip.parse().ok()?, zone, port))
}

/// A `to` address as a socket address; a zone becomes the scope id (a
/// number, or an interface's index).
fn to_socket_addr(s: &str) -> Option<SocketAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa);
    }
    let (ip, zone, port) = split_zone(s)?;
    let scope = zone.parse::<u32>().ok().or_else(|| {
        std::fs::read_to_string(format!("/sys/class/net/{zone}/ifindex"))
            .ok()?
            .trim()
            .parse()
            .ok()
    })?;
    Some(SocketAddr::V6(SocketAddrV6::new(ip, port.unwrap_or(53), 0, scope)))
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "transfer"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let keys = c.server_block_keys();
        let mut xfrs = Vec::new();
        while c.next() {
            let args = c.remaining_args();
            let mut x = Xfr {
                zones: zones::origins_from_args_or_server_block(&args, &keys),
                to: Vec::new(),
                source: None,
            };
            while c.next_block() {
                match c.val() {
                    "to" => {
                        let a = c.remaining_args();
                        if a.is_empty() {
                            return Err(c.arg_err());
                        }
                        for h in a {
                            if h == "*" {
                                x.to.push(h);
                            } else {
                                x.to.push(host_port(&h).map_err(|e| SetupError::new("transfer", e))?);
                            }
                        }
                    }
                    "source" => {
                        let a = c.remaining_args();
                        if a.len() != 1 {
                            return Err(c.arg_err());
                        }
                        if x.source.is_some() {
                            return Err(c.errf("source already specified"));
                        }
                        x.source = Some(a[0].parse().map_err(|_| {
                            let msg = format!("invalid source address {:?}", a[0]);
                            c.errf(msg)
                        })?);
                    }
                    other => {
                        let msg = format!("unknown property {other:?}");
                        return Err(c.errf(msg));
                    }
                }
            }
            if x.to.is_empty() {
                return Err(c.errf("'to' is required"));
            }
            xfrs.push(x);
        }
        let core = Arc::new(Core {
            xfrs,
            registry: TransferRegistry::of(c.config),
        });
        core.registry.set_notifier(&(core.clone() as Arc<dyn Notifier>));
        c.add_plugin(move |next| {
            Arc::new(Transfer {
                core: core.clone(),
                next,
            })
        });
        Ok(())
    }
}

struct Core {
    xfrs: Vec<Xfr>,
    registry: TransferRegistry,
}

#[kerndns_core::async_trait]
impl Notifier for Core {
    /// Send a NOTIFY for `zone` to every `to` address (3 tries each).
    async fn notify(&self, zone: &str) {
        let Some(x) = longest_match(&self.xfrs, zone).cloned() else {
            return;
        };
        for to in x.to.iter().filter(|t| *t != "*") {
            if let Err(e) = send_notify(zone, to, x.source).await {
                kerndns_core::warning!(plugin = "transfer", "{e}");
            }
        }
        kerndns_core::debug!(plugin = "transfer", "Sent notifies for zone {zone:?} to {:?}", x.to);
    }
}

async fn send_notify(zone: &str, to: &str, source: Option<IpAddr>) -> Result<(), String> {
    let mut m = Message::new(rand_id(), MessageType::Query, OpCode::Notify);
    m.metadata.authoritative = true;
    m.add_query(Query::query(
        Name::from_ascii(zone).map_err(|e| e.to_string())?,
        RecordType::SOA,
    ));
    let wire = m.to_vec().map_err(|e| e.to_string())?;
    let dst = to_socket_addr(to).ok_or_else(|| format!("{to}: invalid socket address"))?;
    let bind = match (source, dst) {
        (Some(ip), _) => SocketAddr::new(ip, 0),
        (None, SocketAddr::V4(_)) => "0.0.0.0:0".parse().unwrap(),
        (None, SocketAddr::V6(_)) => "[::]:0".parse().unwrap(),
    };
    let mut last = String::from("no answer");
    for _ in 0..3 {
        let sock = tokio::net::UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
        if let Err(e) = sock.send_to(&wire, dst).await {
            last = e.to_string();
            continue;
        }
        let mut buf = [0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await {
            Ok(Ok(n)) => match Message::from_vec(&buf[..n]) {
                Ok(r) if r.metadata.response_code == ResponseCode::NoError => return Ok(()),
                Ok(r) => {
                    last = format!(
                        "rcode was {:?}",
                        kerndns_core::metrics::rcode_string(r.metadata.response_code)
                    )
                }
                Err(e) => last = e.to_string(),
            },
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "i/o timeout".into(),
        }
    }
    Err(format!("notify for zone {zone:?} was not accepted by {to:?}: {last}"))
}

pub struct Transfer {
    core: Arc<Core>,
    next: Next,
}

#[async_trait]
impl Handler for Transfer {
    fn name(&self) -> &'static str {
        "transfer"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let qtype = req.qtype();
        if qtype != RecordType::AXFR && qtype != RecordType::IXFR {
            return next_or_failure("transfer", &self.next, ctx, w, req).await;
        }
        if req.proto() != "tcp" {
            return Ok(ResponseCode::Refused);
        }
        let name = req.name();
        let Some(x) = longest_match(&self.core.xfrs, &name) else {
            return next_or_failure("transfer", &self.next, ctx, w, req).await;
        };
        if !x.allowed(req.ip()) {
            let m = req.error_reply(ResponseCode::Refused);
            w.write_msg(m)
                .await
                .map_err(|e| PluginError::servfail("transfer", e.to_string()))?;
            return Ok(ResponseCode::NoError);
        }
        let mut serial = 0;
        if qtype == RecordType::IXFR {
            // the client's current SOA is in the authority section
            match req.msg.authorities.as_slice() {
                [r] => match &r.data {
                    RData::SOA(soa) => serial = soa.serial,
                    _ => return Ok(ResponseCode::ServFail),
                },
                _ => return Ok(ResponseCode::ServFail),
            }
        }

        let mut batches = None;
        for src in self.core.registry.sources() {
            match src.transfer(&name, serial) {
                Err(TransferError::NotAuthoritative) => continue,
                Err(TransferError::Other(e)) => return Err(PluginError::servfail("transfer", e)),
                Ok(b) => {
                    batches = Some(b);
                    break;
                }
            }
        }
        let Some(batches) = batches else {
            return next_or_failure("transfer", &self.next, ctx, w, req).await;
        };

        let mut soa: Option<Record> = None;
        // each message's records and the most they can take on the wire
        let mut out: Vec<(Vec<Record>, usize)> = Vec::new();
        let mut cur: Vec<Record> = Vec::new();
        let mut size = 0usize;
        let mut bound = 0usize;
        let mut total = 0usize;
        let mut sizer = RecordSizer::new();
        for records in batches {
            if records.is_empty() {
                continue;
            }
            if soa.is_none() && records[0].record_type() == RecordType::SOA {
                soa = Some(records[0].clone());
            }
            for rr in records {
                let (len, max) = sizer.measure(&rr);
                if !cur.is_empty() && size + len > BATCH_BYTES {
                    total += cur.len();
                    out.push((std::mem::take(&mut cur), bound));
                    size = 0;
                    bound = 0;
                }
                cur.push(rr);
                size += len;
                bound += max;
            }
        }
        let serial_of = |r: &Option<Record>| match r.as_ref().map(|r| &r.data) {
            Some(RData::SOA(s)) => s.serial,
            _ => 0,
        };
        if out.is_empty() && cur.len() == 1 && soa.is_some() {
            // IXFR for an up to date zone: just the SOA
            let mut m = req.reply();
            m.answers = vec![soa.clone().unwrap()];
            w.write_msg(m)
                .await
                .map_err(|e| PluginError::servfail("transfer", e.to_string()))?;
            kerndns_core::info!(
                plugin = "transfer",
                "Outgoing noop, incremental transfer for up to date zone {:?} to {} for {} SOA serial",
                req.qname().to_ascii(),
                req.ip(),
                serial_of(&soa)
            );
            return Ok(ResponseCode::NoError);
        }
        if !cur.is_empty() {
            total += cur.len();
            out.push((cur, bound));
        }
        // the size estimate is per record; split any message whose actual
        // encoding is too big for TCP (64K, minus room for a TSIG). Only
        // messages that might be too big are encoded here: the header, the
        // question and the uncompressed records bound the encoded size.
        let question = req.msg.queries.first().map_or(0, |q| wire::name_len(q.name()) + 4);
        let mut queue: std::collections::VecDeque<(Vec<Record>, Option<usize>)> =
            out.into_iter().map(|(b, max)| (b, Some(max))).collect();
        while let Some((batch, max)) = queue.pop_front() {
            let mut m = req.reply();
            m.metadata.authoritative = true;
            m.answers = batch;
            let fits = max.is_some_and(|max| HEADER + question + max <= MAX_ENCODED);
            let len = if fits {
                0
            } else {
                wire::to_wire(&m).map(|v| v.len()).unwrap_or(usize::MAX)
            };
            if len > MAX_ENCODED && m.answers.len() > 1 {
                let second = m.answers.split_off(m.answers.len() / 2);
                queue.push_front((second, None));
                queue.push_front((std::mem::take(&mut m.answers), None));
                continue;
            }
            w.write_msg(m)
                .await
                .map_err(|e| PluginError::servfail("transfer", e.to_string()))?;
        }
        kerndns_core::info!(
            plugin = "transfer",
            "Outgoing transfer of {total} records of zone {:?} to {} for {} SOA serial",
            req.qname().to_ascii(),
            req.ip(),
            serial_of(&soa)
        );
        Ok(ResponseCode::NoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    /// The registry holds the notifier weakly: the plugin holds the
    /// registry, so a strong reference back leaked both on every load.
    #[test]
    fn setup_does_not_leak() {
        let (res, mut cfg) = run_setup(&Setup, "transfer {\n to *\n}");
        res.unwrap();
        let registry = TransferRegistry::of(&mut cfg).downgrade();
        assert!(registry.has_notifier());
        drop(cfg);
        assert!(
            !registry.has_notifier(),
            "the transfer plugin and its registry form a cycle"
        );
    }

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "transfer {\n to * 10.0.0.1 [::1]:5300\n}"));
        assert!(setup_err(&Setup, "transfer").contains("'to' is required"));
        assert!(setup_err(&Setup, "transfer {\n to example.org\n}").contains("not an IP address"));
        assert!(setup_err(&Setup, "transfer {\n to *\n bogus\n}").contains("unknown property"));
    }

    /// An IPv6 zone is accepted and kept, like parse.HostPort (CoreDNS's
    /// transfer TestParse).
    #[test]
    fn zone_identifier() {
        assert!(setup_ok(&Setup, "transfer {\n to [fe80::1%eth0]:53 fe80::2%3\n}"));
        assert_eq!(host_port("[fe80::1%eth0]:53").unwrap(), "[fe80::1%eth0]:53");
        assert_eq!(host_port("fe80::2%3").unwrap(), "[fe80::2%3]:53");
        let sa = to_socket_addr("[fe80::2%3]:5300").unwrap();
        assert_eq!(
            sa,
            "[fe80::2]:5300"
                .parse::<SocketAddr>()
                .map(|s| match s {
                    SocketAddr::V6(v) => SocketAddr::V6(SocketAddrV6::new(*v.ip(), 5300, 0, 3)),
                    v4 => v4,
                })
                .unwrap()
        );
        let x = Xfr {
            zones: vec![".".into()],
            to: vec![host_port("[fe80::1%eth0]:53").unwrap()],
            source: None,
        };
        assert!(x.allowed("fe80::1".parse().unwrap()));
        assert!(!x.allowed("fe80::2".parse().unwrap()));
        assert!(setup_err(&Setup, "transfer {\n to [fe80::1%]:53\n}").contains("not an IP address"));
    }

    #[test]
    fn matching_and_acl() {
        let xs = vec![
            Xfr {
                zones: vec!["example.org.".into()],
                to: vec!["10.0.0.1:53".into()],
                source: None,
            },
            Xfr {
                zones: vec!["sub.example.org.".into()],
                to: vec!["*".into()],
                source: None,
            },
        ];
        assert_eq!(longest_match(&xs, "a.sub.example.org.").unwrap().to, vec!["*"]);
        let x = longest_match(&xs, "example.org.").unwrap();
        assert!(x.allowed("10.0.0.1".parse().unwrap()));
        assert!(!x.allowed("10.0.0.2".parse().unwrap()));
    }
}
