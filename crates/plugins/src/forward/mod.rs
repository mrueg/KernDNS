//! `forward`: proxies queries to upstream resolvers over UDP, TCP or TLS.
//! Port of `plugin/forward`.
//!
//! ```text
//! forward FROM TO... {
//!     except IGNORED_NAMES...
//!     force_tcp
//!     prefer_udp
//!     expire DURATION
//!     max_age DURATION
//!     max_fails INTEGER
//!     max_connect_attempts INTEGER
//!     tls [CERT KEY CA]
//!     tls_servername NAME
//!     policy random|round_robin|sequential
//!     health_check DURATION [no_rec] [domain FQDN]
//!     max_concurrent MAX
//!     next RCODE...
//!     next_on_nodata
//!     failover RCODE...
//!     failfast_all_unhealthy_upstreams
//!     read_timeout DURATION
//!     source_address IP
//! }
//! ```
//!
//! Queries and answers are logged to the block's `dnstap` plugins as
//! FORWARDER_QUERY / FORWARDER_RESPONSE, like CoreDNS's `dnstap.go`.
//!
//! Not ported yet: `https://` and `quic://` upstreams (`doh_method`) and
//! upstreams given as hostnames (`resolver`).
//! These are rejected with an error rather than ignored.

pub mod policy;
pub mod proxy;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use kerndns_core::duration::parse_duration;
use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::Name;
use kerndns_core::zones::normalize_exact;
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure,
};
use rustls_pki_types::ServerName;

use policy::Picker;
pub use policy::Policy;
use proxy::{ExchangeError, Options, Proto, Proxy, TlsSettings, rand_below};

use crate::dnstap::Taps;

/// Overall time budget for one query (CoreDNS `defaultTimeout`).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CONNECT_ATTEMPTS_PER_UPSTREAM: u64 = 2;
/// Maximum number of upstreams per stanza.
const MAX_UPSTREAMS: usize = 15;

/// One `forward` stanza: its upstreams and settings.
pub struct ForwardCore {
    pub from: String,
    pub ignored: Vec<String>,
    pub proxies: Vec<Arc<Proxy>>,
    pub picker: Picker,
    pub max_fails: u32,
    pub max_connect_attempts: Option<u64>,
    pub hc_interval: Duration,
    pub opts: Options,
    pub max_concurrent: i64,
    concurrent: AtomicI64,
    pub next_rcodes: Vec<ResponseCode>,
    pub next_on_nodata: bool,
    pub failover_rcodes: Vec<ResponseCode>,
    pub failfast: bool,
}

impl ForwardCore {
    /// Upstreams in the order the policy wants them tried.
    fn list(&self) -> Vec<Arc<Proxy>> {
        self.picker.list(&self.proxies)
    }

    fn matches(&self, name: &str) -> bool {
        policy::matches(&self.from, &self.ignored, name)
    }
}

pub struct Setup;

fn parse_rcode(s: &str) -> Option<ResponseCode> {
    Some(match s.to_ascii_uppercase().as_str() {
        "NOERROR" => ResponseCode::NoError,
        "FORMERR" => ResponseCode::FormErr,
        "SERVFAIL" => ResponseCode::ServFail,
        "NXDOMAIN" => ResponseCode::NXDomain,
        "NOTIMP" => ResponseCode::NotImp,
        "REFUSED" => ResponseCode::Refused,
        "YXDOMAIN" => ResponseCode::YXDomain,
        "YXRRSET" => ResponseCode::YXRRSet,
        "NXRRSET" => ResponseCode::NXRRSet,
        "NOTAUTH" => ResponseCode::NotAuth,
        "NOTZONE" => ResponseCode::NotZone,
        _ => return None,
    })
}

/// An upstream: `IP`, `IP:port`, `[v6]:port`, `dns://…`, `tls://…[%servername]`.
struct To {
    addr: SocketAddr,
    tls: bool,
    server_name: Option<String>,
}

fn parse_to(s: &str) -> Result<Vec<To>, String> {
    let (scheme, rest) = match s.split_once("://") {
        Some((sch, r)) => (sch.to_ascii_lowercase(), r),
        None => (String::from("dns"), s),
    };
    let tls = match scheme.as_str() {
        "dns" => false,
        "tls" => true,
        "https" | "quic" | "grpc" | "https3" => {
            return Err(format!("'{scheme}' upstreams are not supported by KernDNS yet: {s}"));
        }
        other => {
            return Err(format!(
                "'{other}' is not supported as a destination protocol in forward: {s}"
            ));
        }
    };
    // a resolv.conf-style file
    if !tls && std::path::Path::new(rest).is_file() {
        let text = std::fs::read_to_string(rest).map_err(|e| format!("{rest}: {e}"))?;
        let mut out = Vec::new();
        for line in text.lines() {
            let mut f = line.split_whitespace();
            if f.next() == Some("nameserver")
                && let Some(ip) = f.next()
            {
                out.extend(parse_to(ip)?);
            }
        }
        return Ok(out);
    }
    // TLS server name after '%', like CoreDNS's splitZone:
    // tls://1.2.3.4%dns.example, tls://1.2.3.4%dns.example:853, tls://[::1%dns.example]:853
    let (host, server_name) = match rest.rfind('%') {
        Some(i) if tls => {
            let mut host = rest[..i].to_string();
            let mut name = rest[i + 1..].to_string();
            if host.starts_with('[') {
                host.push(']');
            }
            if let Some(j) = name.rfind(':') {
                host.push_str(&name[j..]);
                name.truncate(j);
            }
            (host, Some(name.trim_end_matches(']').to_string()))
        }
        _ => (rest.to_string(), None),
    };
    let default_port = if tls { 853 } else { 53 };
    let addr = if let Ok(sa) = host.parse::<SocketAddr>() {
        sa
    } else if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        SocketAddr::new(ip, default_port)
    } else {
        return Err(format!(
            "not an IP address or file: {s:?} (upstreams given as hostnames are not supported by KernDNS yet)"
        ));
    };
    Ok(vec![To { addr, tls, server_name }])
}

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "forward"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut cores: Vec<Arc<ForwardCore>> = Vec::new();
        while c.next() {
            cores.push(Arc::new(parse_stanza(c)?));
        }
        for core in &cores {
            let start = core.clone();
            c.on_startup(move || {
                for p in &start.proxies {
                    p.set_health_options(start.hc_interval, start.opts.clone());
                }
                Ok(())
            });
            let stop = core.clone();
            c.on_shutdown(move || {
                for p in &stop.proxies {
                    p.stop();
                }
            });
            let core = core.clone();
            let taps = Taps::of(c.config);
            c.add_plugin(move |next| {
                Arc::new(Forward {
                    core: core.clone(),
                    next,
                    taps: taps.clone(),
                })
            });
        }
        Ok(())
    }
}

fn parse_stanza(c: &mut Controller<'_>) -> Result<ForwardCore, SetupError> {
    let err = |m: String| SetupError::new("forward", m);
    if !c.next_arg() {
        return Err(c.arg_err());
    }
    let from_arg = c.val().to_string();
    let zones = normalize_exact(&from_arg);
    let Some(from) = zones.first().cloned() else {
        return Err(err(format!("unable to normalize '{from_arg}'")));
    };
    if zones.len() > 1 {
        kerndns_core::warning!(
            plugin = "forward",
            "Unsupported CIDR notation: '{from_arg}' expands to multiple zones. Using only '{from}'."
        );
    }
    let to = c.remaining_args();
    if to.is_empty() {
        return Err(c.arg_err());
    }

    let mut ignored = Vec::new();
    let mut max_fails = 2u32;
    let mut max_connect_attempts = None;
    let mut hc_interval = Duration::from_millis(500);
    let mut opts = Options::default();
    let mut tls_args: Option<Vec<String>> = None;
    let mut tls_server_name: Option<String> = None;
    let mut expire = Duration::from_secs(10);
    let mut max_age = Duration::ZERO;
    let mut read_timeout = Duration::from_secs(2);
    let mut policy = Policy::Random;
    let mut max_concurrent = 0i64;
    let mut next_rcodes = Vec::new();
    let mut next_on_nodata = false;
    let mut failover_rcodes = Vec::new();
    let mut failfast = false;
    let mut source = None;

    while c.next_block() {
        let opt = c.val().to_string();
        match opt.as_str() {
            "except" => {
                let a = c.remaining_args();
                if a.is_empty() {
                    return Err(c.arg_err());
                }
                ignored.extend(a.iter().flat_map(|x| normalize_exact(x)));
            }
            "max_fails" => {
                if !c.next_arg() {
                    return Err(c.arg_err());
                }
                max_fails = c.val().parse().map_err(|e| err(format!("{e}")))?;
            }
            "max_connect_attempts" => {
                if !c.next_arg() {
                    return Err(c.arg_err());
                }
                max_connect_attempts = Some(c.val().parse().map_err(|e| err(format!("{e}")))?);
            }
            "health_check" => {
                if !c.next_arg() {
                    return Err(c.arg_err());
                }
                hc_interval = parse_duration(c.val()).map_err(err)?;
                opts.hc_domain = Name::root();
                while c.next_arg() {
                    match c.val() {
                        "no_rec" => opts.hc_recursion_desired = false,
                        "domain" => {
                            if !c.next_arg() {
                                return Err(c.arg_err());
                            }
                            let d = c.val().to_string();
                            let n = normalize_exact(&d)
                                .into_iter()
                                .next()
                                .and_then(|n| Name::from_ascii(n).ok())
                                .ok_or_else(|| err(format!("health_check: invalid domain name {d}")))?;
                            opts.hc_domain = n;
                        }
                        other => return Err(err(format!("health_check: unknown option {other}"))),
                    }
                }
            }
            "force_tcp" => {
                if c.next_arg() {
                    return Err(c.arg_err());
                }
                opts.force_tcp = true;
            }
            "prefer_udp" => {
                if c.next_arg() {
                    return Err(c.arg_err());
                }
                opts.prefer_udp = true;
            }
            "tls" => {
                let mut a = c.remaining_args();
                if a.len() > 3 {
                    return Err(c.arg_err());
                }
                if let Some(root) = &c.config.root {
                    for x in &mut a {
                        if std::path::Path::new(x).is_relative() {
                            *x = root.join(&x).display().to_string();
                        }
                    }
                }
                tls_args = Some(a);
            }
            "tls_servername" => {
                if !c.next_arg() {
                    return Err(c.arg_err());
                }
                tls_server_name = Some(c.val().to_string());
            }
            "expire" | "max_age" | "read_timeout" => {
                if !c.next_arg() {
                    return Err(c.arg_err());
                }
                let d = parse_duration(c.val()).map_err(|e| {
                    if e.contains("negative") {
                        err(format!("{opt} can't be negative: {}", c.val()))
                    } else {
                        err(e)
                    }
                })?;
                match opt.as_str() {
                    "expire" => expire = d,
                    "max_age" => max_age = d,
                    _ => {
                        if d.is_zero() {
                            return Err(err(format!("read_timeout must be positive: {}", c.val())));
                        }
                        read_timeout = d;
                    }
                }
            }
            "max_idle_conns" => {
                if !c.next_arg() {
                    return Err(c.arg_err());
                }
                let n: i64 = c.val().parse().map_err(|e| err(format!("{e}")))?;
                if n < 0 {
                    return Err(err(format!("max_idle_conns can't be negative: {n}")));
                }
            }
            "policy" => policy = Policy::parse(c)?,
            "max_concurrent" => {
                if !c.next_arg() {
                    return Err(c.arg_err());
                }
                let n: i64 = c.val().parse().map_err(|e| err(format!("{e}")))?;
                if n < 0 {
                    return Err(err(format!("max_concurrent can't be negative: {n}")));
                }
                max_concurrent = n;
            }
            "next" | "failover" => {
                let a = c.remaining_args();
                if a.is_empty() {
                    return Err(c.arg_err());
                }
                for rc in a {
                    let code = parse_rcode(&rc).ok_or_else(|| err(format!("{rc} is not a valid rcode")))?;
                    if opt == "failover" {
                        if code == ResponseCode::NoError {
                            return Err(err("NoError cannot be used in failover".into()));
                        }
                        failover_rcodes.push(code);
                    } else {
                        next_rcodes.push(code);
                    }
                }
            }
            "next_on_nodata" => {
                if c.next_arg() {
                    return Err(c.arg_err());
                }
                next_on_nodata = true;
            }
            "failfast_all_unhealthy_upstreams" => {
                if !c.remaining_args().is_empty() {
                    return Err(c.arg_err());
                }
                failfast = true;
            }
            "source_address" => {
                if !c.next_arg() {
                    return Err(c.arg_err());
                }
                source = Some(c.val().parse::<IpAddr>().map_err(|_| {
                    let msg = format!("invalid IP address: {}", c.val());
                    c.errf(msg)
                })?);
            }
            "doh_method" | "resolver" => {
                return Err(err(format!("'{opt}' is not supported by KernDNS yet")));
            }
            other => {
                let msg = format!("unknown property '{other}'");
                return Err(c.errf(msg));
            }
        }
    }
    if !max_age.is_zero() && max_age < expire {
        return Err(err(format!(
            "max_age ({}) must not be less than expire ({})",
            kerndns_core::duration::format_duration(max_age),
            kerndns_core::duration::format_duration(expire)
        )));
    }

    let mut tos = Vec::new();
    for t in &to {
        tos.extend(parse_to(t).map_err(err)?);
    }
    if tos.is_empty() {
        return Err(err("no valid upstream addresses found".into()));
    }
    if tos.len() > MAX_UPSTREAMS {
        return Err(err(format!("more than {MAX_UPSTREAMS} TOs configured: {}", tos.len())));
    }

    let mut proxies = Vec::new();
    for t in tos {
        let tls = if t.tls {
            if t.server_name.is_some() && tls_server_name.is_some() {
                return Err(err(format!(
                    "both forward ('{}') and proxy level ('{}') TLS servernames are set for upstream proxy '{}'",
                    tls_server_name.as_deref().unwrap_or_default(),
                    t.server_name.as_deref().unwrap_or_default(),
                    t.addr
                )));
            }
            let config = crate::tlsconfig::client_config(tls_args.as_deref().unwrap_or(&[])).map_err(err)?;
            let name = t
                .server_name
                .clone()
                .or_else(|| tls_server_name.clone())
                .unwrap_or_else(|| t.addr.ip().to_string());
            let server_name =
                ServerName::try_from(name.clone()).map_err(|e| err(format!("invalid TLS server name {name}: {e}")))?;
            Some(TlsSettings { config, server_name })
        } else {
            None
        };
        let mut p = Proxy::new(t.addr, tls);
        p.expire = expire;
        p.max_age = max_age;
        p.read_timeout = read_timeout;
        p.source = source;
        proxies.push(Arc::new(p));
    }

    let core = ForwardCore {
        from,
        ignored,
        proxies,
        picker: Picker::new(policy),
        max_fails,
        max_connect_attempts,
        hc_interval,
        opts,
        max_concurrent,
        concurrent: AtomicI64::new(0),
        next_rcodes,
        next_on_nodata,
        failover_rcodes,
        failfast,
    };
    Ok(core)
}

/// The handler: one stanza plus the rest of the chain.
pub struct Forward {
    core: Arc<ForwardCore>,
    next: Next,
    /// The block's `dnstap` plugins (`SetTapPlugin`).
    taps: Taps,
}

impl Forward {
    fn next_is_forward(&self) -> bool {
        self.next.as_ref().is_some_and(|n| n.name() == "forward")
    }
}

struct ConcurrencyGuard<'a>(&'a AtomicI64);

impl Drop for ConcurrencyGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[async_trait]
impl Handler for Forward {
    fn name(&self) -> &'static str {
        "forward"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let f = &self.core;
        if !f.matches(&req.name()) {
            return next_or_failure("forward", &self.next, ctx, w, req).await;
        }
        let _guard = if f.max_concurrent > 0 {
            let n = f.concurrent.fetch_add(1, Ordering::Relaxed) + 1;
            let g = ConcurrencyGuard(&f.concurrent);
            if n > f.max_concurrent {
                crate::pluginmetrics::FORWARD_MAX_CONCURRENT_REJECTS.inc();
                return Err(PluginError::new(
                    "forward",
                    ResponseCode::Refused,
                    format!("concurrent queries exceeded maximum {}", f.max_concurrent),
                ));
            }
            Some(g)
        } else {
            None
        };

        let list = f.list();
        let start = std::time::SystemTime::now();
        let deadline = Instant::now() + DEFAULT_TIMEOUT;
        let max_attempts = f
            .max_connect_attempts
            .unwrap_or(DEFAULT_CONNECT_ATTEMPTS_PER_UPSTREAM * list.len() as u64);
        let mut attempts = 0u64;
        let mut fails = 0usize;
        let mut failover_attempts = 0usize;
        let mut i = 0usize;
        let mut upstream_err: Option<String> = None;

        while Instant::now() < deadline && (max_attempts == 0 || attempts < max_attempts) {
            if i >= list.len() {
                i = 0;
                fails = 0;
            }
            let mut proxy = list[i].clone();
            i += 1;
            if proxy.down(f.max_fails) {
                fails += 1;
                if fails < f.proxies.len() {
                    continue;
                }
                // all upstreams are down: try a random one anyway, unless failfast
                crate::pluginmetrics::FORWARD_HC_BROKEN.inc();
                if f.failfast {
                    break;
                }
                proxy = f.proxies[rand_below(f.proxies.len())].clone();
            }
            ctx.metadata.insert("forward/upstream".into(), proxy.display_addr());

            let mut force_tcp = f.opts.force_tcp;
            let mut local = None;
            let mut used;
            let result = loop {
                // force_tcp wins over prefer_udp; otherwise use the client's protocol
                let proto = if force_tcp {
                    Proto::Tcp
                } else if f.opts.prefer_udp || req.proto() == "udp" {
                    Proto::Udp
                } else {
                    Proto::Tcp
                };
                let mut msg = req.msg.clone();
                // the upstream may answer up to the client's buffer size
                if let Some(e) = msg.edns.as_mut()
                    && e.max_payload() < 512
                {
                    e.set_max_payload(512);
                }
                used = if proxy.is_tls() { Proto::Tcp } else { proto };
                match proxy.connect(&msg, proto, &mut local).await {
                    Err(ExchangeError::CachedClosed) => continue,
                    Ok((ret, _)) if ret.metadata.truncation && !force_tcp && f.opts.prefer_udp => {
                        force_tcp = true;
                        continue;
                    }
                    r => break r,
                }
            };
            if let Some(taps) = self.taps.get()
                && !taps.is_empty()
            {
                let reply = result.as_ref().ok().map(|(m, _)| m);
                to_dnstap(ctx, taps, proxy.addr, local, used, req, reply, start);
            }

            let ret = match result {
                Ok((ret, _)) => ret,
                Err(ExchangeError::InvalidRequest(e)) => {
                    return Err(PluginError::new("forward", ResponseCode::FormErr, e));
                }
                Err(e) => {
                    upstream_err = Some(e.to_string());
                    if f.max_fails != 0 {
                        proxy.healthcheck();
                    }
                    if max_attempts > 0 {
                        attempts += 1;
                        if attempts >= max_attempts {
                            break;
                        }
                    }
                    if fails < f.proxies.len() {
                        continue;
                    }
                    break;
                }
            };

            if !response_matches(req, &ret) {
                let m = req.error_reply(ResponseCode::FormErr);
                w.write_msg(m)
                    .await
                    .map_err(|e| PluginError::servfail("forward", e.to_string()))?;
                return Ok(ResponseCode::NoError);
            }

            let rcode = ret.metadata.response_code;
            if f.failover_rcodes.contains(&rcode) {
                failover_attempts += 1;
                if failover_attempts < f.proxies.len() {
                    continue;
                }
            }
            if f.next_rcodes.contains(&rcode) && self.next_is_forward() {
                return next_or_failure("forward", &self.next, ctx, w, req).await;
            }
            if f.next_on_nodata && self.next_is_forward() && rcode == ResponseCode::NoError && ret.answers.is_empty() {
                return next_or_failure("forward", &self.next, ctx, w, req).await;
            }

            w.write_msg(ret)
                .await
                .map_err(|e| PluginError::servfail("forward", e.to_string()))?;
            return Ok(ResponseCode::NoError);
        }

        Err(PluginError::servfail(
            "forward",
            upstream_err.unwrap_or_else(|| "no healthy proxies".into()),
        ))
    }
}

/// `toDnstap`: FORWARDER_QUERY and, if there is an answer,
/// FORWARDER_RESPONSE, seen from KernDNS (`local`) towards the upstream.
#[allow(clippy::too_many_arguments)]
fn to_dnstap(
    ctx: &Context,
    taps: &[Arc<crate::dnstap::Tap>],
    upstream: SocketAddr,
    local: Option<SocketAddr>,
    proto: Proto,
    req: &Request,
    reply: Option<&kerndns_core::proto::op::Message>,
    start: std::time::SystemTime,
) {
    use crate::dnstap::msg::{Message as TapMsg, MessageType};
    let proto = proto.as_str();
    let raw_query = taps
        .iter()
        .any(|t| t.include_raw)
        .then(|| kerndns_core::wire::to_wire(&req.msg).ok())
        .flatten();
    let raw_reply = reply
        .filter(|_| taps.iter().any(|t| t.include_raw))
        .and_then(|m| kerndns_core::wire::to_wire(m).ok());
    for t in taps {
        let mut q = TapMsg::new(MessageType::ForwarderQuery);
        q.set_query_time(start);
        if let Some(l) = local {
            q.set_query_address(l, proto);
        }
        q.set_response_address(upstream, proto);
        if t.include_raw {
            q.query_message = raw_query.clone();
        }
        t.tap_message_with_metadata(ctx, req, &q);
        if reply.is_some() {
            let mut r = TapMsg::new(MessageType::ForwarderResponse);
            if t.include_raw {
                r.response_message = raw_reply.clone();
            }
            r.set_query_time(start);
            if let Some(l) = local {
                r.set_query_address(l, proto);
            }
            r.set_response_address(upstream, proto);
            r.set_response_time(std::time::SystemTime::now());
            t.tap_message_with_metadata(ctx, req, &r);
        }
    }
}

/// `request.Match`: the reply is a response to our question.
fn response_matches(req: &Request, ret: &kerndns_core::proto::op::Message) -> bool {
    use kerndns_core::proto::op::MessageType;
    if ret.metadata.message_type != MessageType::Response {
        return false;
    }
    let Some(q) = ret.queries.first() else {
        // some servers omit the question in error responses; CoreDNS
        // accepts a missing question only if the request had none either
        return req.msg.queries.is_empty();
    };
    let rq = req.query();
    q.name() == rq.name() && q.query_type() == rq.query_type() && q.query_class() == rq.query_class()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "forward . 127.0.0.1"));
        assert!(setup_ok(
            &Setup,
            "forward . 127.0.0.1:1053 [::1]:53 {\n policy round_robin\n max_fails 3\n health_check 1s no_rec domain example.org\n}"
        ));
        assert!(setup_ok(
            &Setup,
            "forward . tls://9.9.9.9 {\n tls_servername dns.quad9.net\n}"
        ));
        assert!(setup_ok(
            &Setup,
            "forward example.org 127.0.0.1 {\n except a.example.org\n next NXDOMAIN SERVFAIL\n}"
        ));
        assert!(setup_err(&Setup, "forward .").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "forward . dns.google").contains("not an IP address or file"));
        assert!(setup_err(&Setup, "forward . https://1.1.1.1").contains("not supported by KernDNS yet"));
        assert!(setup_err(&Setup, "forward . 127.0.0.1 {\n policy foo\n}").contains("unknown policy 'foo'"));
        assert!(setup_err(&Setup, "forward . 127.0.0.1 {\n failover NOERROR\n}").contains("NoError cannot be used"));
        assert!(
            setup_err(&Setup, "forward . 127.0.0.1 {\n expire 10s\n max_age 1s\n}")
                .contains("must not be less than expire")
        );
        assert!(setup_err(&Setup, "forward . 127.0.0.1 {\n bogus\n}").contains("unknown property 'bogus'"));
    }

    #[test]
    fn upstream_parsing() {
        let p = |s: &str| {
            parse_to(s).map(|v| {
                v.iter()
                    .map(|t| (t.addr.to_string(), t.tls, t.server_name.clone()))
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(p("1.2.3.4").unwrap(), vec![("1.2.3.4:53".into(), false, None)]);
        assert_eq!(p("[::1]:1053").unwrap(), vec![("[::1]:1053".into(), false, None)]);
        assert_eq!(p("tls://1.1.1.1").unwrap(), vec![("1.1.1.1:853".into(), true, None)]);
        assert_eq!(
            p("tls://1.1.1.1%cloudflare-dns.com").unwrap(),
            vec![("1.1.1.1:853".into(), true, Some("cloudflare-dns.com".into()))]
        );
        assert_eq!(
            p("dns://8.8.8.8:5353").unwrap(),
            vec![("8.8.8.8:5353".into(), false, None)]
        );
    }

    #[test]
    fn matching() {
        let core = |from: &str, ignored: &[&str]| ForwardCore {
            from: from.into(),
            ignored: ignored.iter().map(|s| s.to_string()).collect(),
            proxies: vec![],
            picker: Picker::new(Policy::Random),
            max_fails: 2,
            max_connect_attempts: None,
            hc_interval: Duration::from_millis(500),
            opts: Options::default(),
            max_concurrent: 0,
            concurrent: AtomicI64::new(0),
            next_rcodes: vec![],
            next_on_nodata: false,
            failover_rcodes: vec![],
            failfast: false,
        };
        let f = core("example.org.", &["internal.example.org."]);
        assert!(f.matches("www.example.org."));
        assert!(!f.matches("a.internal.example.org."));
        assert!(!f.matches("example.net."));
        assert!(core(".", &["example.org."]).matches("."));
    }
}
