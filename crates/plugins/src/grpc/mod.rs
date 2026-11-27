//! `grpc`: proxies queries to upstreams speaking CoreDNS's gRPC
//! `DnsService`. Port of `plugin/grpc`.
//!
//! ```text
//! grpc FROM TO... {
//!     except IGNORED_NAMES...
//!     tls [CERT KEY CA]
//!     tls_servername NAME
//!     policy random|round_robin|sequential
//!     fallthrough [ZONES...]
//! }
//! ```
//!
//! **TO** is `IP[:PORT]` (port 53 by default, as in CoreDNS),
//! `unix:///path` or a resolv.conf-style file. Upstream selection
//! (`policy`) and `except` are shared with `forward`. Like CoreDNS, the
//! plugin has no health checks: every upstream in the policy's order is
//! tried once within 5 seconds.

pub mod client;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kerndns_core::proto::op::{Message, MessageType, ResponseCode};
use kerndns_core::zones::normalize_exact;
use kerndns_core::{
    Context, Controller, Fall, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter,
    SetupError, async_trait, next_or_failure,
};
use rustls_pki_types::ServerName;

use crate::forward::policy::{self, Picker, Policy};
use client::{Code, DnsServiceClient, H2Client, RpcError, Target, Tls};

/// Overall time budget for one query (CoreDNS `defaultTimeout`).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum number of upstreams.
const MAX_UPSTREAMS: usize = 15;
/// `dns.MaxMsgSize`.
const MAX_DNS_MESSAGE_BYTES: usize = 65535;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrpcError {
    #[error("dns message exceeds size limit: {0} bytes (limit {MAX_DNS_MESSAGE_BYTES})")]
    TooLarge(usize),
    #[error("{0}")]
    Rpc(#[from] RpcError),
    #[error("{0}")]
    Pack(String),
    #[error("{0}")]
    Unpack(String),
}

/// One upstream.
pub struct Proxy {
    /// As configured: `127.0.0.1:53`, `unix:///path`. The `to` label.
    pub addr: String,
    client: Box<dyn DnsServiceClient>,
}

impl Proxy {
    pub fn new(addr: String, client: Box<dyn DnsServiceClient>) -> Self {
        Self { addr, client }
    }

    /// Send the request and wait for the answer, like `Proxy.query`.
    pub async fn query(&self, req: &Request, deadline: Instant) -> Result<Message, GrpcError> {
        let start = Instant::now();
        let msg = kerndns_core::wire::to_wire(&req.msg).map_err(|e| GrpcError::Pack(e.to_string()))?;
        validate_size(&msg)?;
        let wire = match self.client.query(&msg, deadline).await {
            Ok(w) => w,
            // "not found" is an empty NXDOMAIN answer
            Err(e) if e.code == Code::NOT_FOUND => return Ok(req.error_reply(ResponseCode::NXDomain)),
            Err(e) => return Err(e.into()),
        };
        validate_size(&wire)?;
        let ret = Message::from_vec(&wire).map_err(|e| GrpcError::Unpack(e.to_string()))?;
        let rc = kerndns_core::metrics::rcode_string(ret.metadata.response_code);
        crate::pluginmetrics::GRPC_REQUESTS
            .with_label_values(&[&self.addr])
            .inc();
        crate::pluginmetrics::GRPC_RESPONSES
            .with_label_values(&[&rc, &self.addr])
            .inc();
        crate::pluginmetrics::GRPC_REQUEST_DURATION
            .with_label_values(&[&self.addr])
            .observe(start.elapsed().as_secs_f64());
        Ok(ret)
    }

    fn close(&self) {
        self.client.close();
    }
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy").field("addr", &self.addr).finish()
    }
}

fn validate_size(data: &[u8]) -> Result<(), GrpcError> {
    if data.len() > MAX_DNS_MESSAGE_BYTES {
        return Err(GrpcError::TooLarge(data.len()));
    }
    Ok(())
}

/// The plugin's configuration: one stanza.
#[derive(Debug)]
pub struct GrpcCore {
    pub from: String,
    pub ignored: Vec<String>,
    pub proxies: Vec<Arc<Proxy>>,
    pub picker: Picker,
    pub fall: Fall,
    /// Set by `tls` or `tls_servername`.
    pub tls: bool,
    pub tls_server_name: Option<String>,
}

impl GrpcCore {
    fn new(from: &str) -> Self {
        Self {
            from: from.to_string(),
            ignored: Vec::new(),
            proxies: Vec::new(),
            picker: Picker::new(Policy::Random),
            fall: Fall::default(),
            tls: false,
            tls_server_name: None,
        }
    }

    fn matches(&self, name: &str) -> bool {
        policy::matches(&self.from, &self.ignored, name)
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "grpc"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let core = Arc::new(parse_grpc(c)?);
        let stop = core.clone();
        c.on_shutdown(move || {
            for p in &stop.proxies {
                p.close();
            }
        });
        c.add_plugin(move |next| {
            Arc::new(Grpc {
                core: core.clone(),
                next,
            })
        });
        Ok(())
    }
}

fn parse_grpc(c: &mut Controller<'_>) -> Result<GrpcCore, SetupError> {
    let mut g = None;
    while c.next() {
        if g.is_some() {
            return Err(SetupError::new(
                "grpc",
                "this plugin can only be used once per Server Block",
            ));
        }
        g = Some(parse_stanza(c)?);
    }
    g.ok_or_else(|| c.arg_err())
}

fn parse_stanza(c: &mut Controller<'_>) -> Result<GrpcCore, SetupError> {
    let err = |m: String| SetupError::new("grpc", m);
    if !c.next_arg() {
        return Err(c.arg_err());
    }
    let from_arg = c.val().to_string();
    let Some(from) = normalize_exact(&from_arg).into_iter().next() else {
        return Err(err(format!("unable to normalize '{from_arg}'")));
    };
    let mut g = GrpcCore::new(&from);
    let to = c.remaining_args();
    if to.is_empty() {
        return Err(c.arg_err());
    }
    let hosts = host_port_or_file(&to).map_err(err)?;

    let mut tls_args: Option<Vec<String>> = None;
    while c.next_block() {
        let opt = c.val().to_string();
        match opt.as_str() {
            "except" => {
                let a = c.remaining_args();
                if a.is_empty() {
                    return Err(c.arg_err());
                }
                g.ignored.extend(a.iter().flat_map(|x| normalize_exact(x)));
            }
            "tls" => {
                let mut a = c.remaining_args();
                if a.len() > 3 {
                    return Err(c.arg_err());
                }
                if let Some(root) = &c.config.root {
                    for x in &mut a {
                        if Path::new(x).is_relative() {
                            *x = root.join(&x).display().to_string();
                        }
                    }
                }
                // like pkgtls.NewTLSConfigFromArgs: files are read now
                crate::tlsconfig::client_config(&a).map_err(err)?;
                tls_args = Some(a);
            }
            "tls_servername" => {
                if !c.next_arg() {
                    return Err(c.arg_err());
                }
                g.tls_server_name = Some(c.val().to_string());
            }
            "policy" => g.picker = Picker::new(Policy::parse(c)?),
            "fallthrough" => {
                let a = c.remaining_args();
                g.fall.set_zones_from_args(&a);
            }
            other => {
                let msg = format!("unknown property '{other}'");
                return Err(c.errf(msg));
            }
        }
    }

    g.tls = tls_args.is_some() || g.tls_server_name.is_some();
    let tls_config = if g.tls {
        Some(crate::tlsconfig::client_config(tls_args.as_deref().unwrap_or(&[])).map_err(err)?)
    } else {
        None
    };
    for (addr, target) in hosts {
        let tls = match &tls_config {
            None => None,
            Some(config) => {
                // without tls_servername, grpc-go verifies the address's host
                let name = g.tls_server_name.clone().unwrap_or_else(|| match &target {
                    Target::Tcp(a) => a.ip().to_string(),
                    Target::Unix(_) => "localhost".to_string(),
                });
                let server_name = ServerName::try_from(name.clone())
                    .map_err(|e| err(format!("invalid TLS server name {name}: {e}")))?;
                Some(Tls {
                    config: config.clone(),
                    server_name,
                })
            }
        };
        let client = H2Client::new(target, tls);
        g.proxies.push(Arc::new(Proxy::new(addr, Box::new(client))));
    }
    if g.proxies.len() > MAX_UPSTREAMS {
        return Err(err(format!(
            "more than {MAX_UPSTREAMS} TOs configured: {}",
            g.proxies.len()
        )));
    }
    Ok(g)
}

/// `parse.HostPortOrFile`: each upstream as its metric label and dial
/// target. Addresses without a port get 53, like CoreDNS.
fn host_port_or_file(to: &[String]) -> Result<Vec<(String, Target)>, String> {
    let mut out = Vec::new();
    for h in to {
        let (scheme, host) = match h.split_once("://") {
            Some((s, rest)) => (s.to_ascii_lowercase(), rest),
            None => ("dns".to_string(), h.as_str()),
        };
        if host.is_empty() {
            return Err(format!("invalid address: {h:?}"));
        }
        match scheme.as_str() {
            "unix" => {
                out.push((format!("unix://{host}"), Target::Unix(PathBuf::from(host))));
                continue;
            }
            "dns" => {}
            other => {
                return Err(format!(
                    "'{other}' is not supported as a grpc upstream: {h} (use the tls option for TLS)"
                ));
            }
        }
        if let Ok(sa) = host.parse::<SocketAddr>() {
            out.push((sa.to_string(), Target::Tcp(sa)));
            continue;
        }
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            let sa = SocketAddr::new(ip, 53);
            out.push((sa.to_string(), Target::Tcp(sa)));
            continue;
        }
        match try_file(bare) {
            Ok(v) => out.extend(v),
            Err(e) => return Err(format!("not an IP address or file {bare:?}: {e}")),
        }
    }
    if out.is_empty() {
        return Err("no nameservers found".into());
    }
    Ok(out)
}

/// The nameservers of a resolv.conf-style file.
fn try_file(path: &str) -> Result<Vec<(String, Target)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        let msg = match e.kind() {
            std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
            _ => e.to_string(),
        };
        format!("failed to open file {path:?}: \"open {path}: {msg}\"")
    })?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut f = line.split_whitespace();
        if f.next() == Some("nameserver")
            && let Some(ns) = f.next()
        {
            let ns = ns.split('%').next().unwrap_or(ns);
            if let Ok(ip) = ns.parse::<IpAddr>() {
                let sa = SocketAddr::new(ip, 53);
                out.push((sa.to_string(), Target::Tcp(sa)));
            }
        }
    }
    Ok(out)
}

/// The handler.
pub struct Grpc {
    core: Arc<GrpcCore>,
    next: Next,
}

impl Grpc {
    async fn next_or_servfail(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        match &self.next {
            Some(_) => next_or_failure("grpc", &self.next, ctx, w, req).await,
            None => Ok(ResponseCode::ServFail),
        }
    }
}

#[async_trait]
impl Handler for Grpc {
    fn name(&self) -> &'static str {
        "grpc"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let g = &self.core;
        let name = req.name();
        if !g.matches(&name) {
            // no next plugin: SERVFAIL
            return self.next_or_servfail(ctx, w, req).await;
        }
        let list = g.picker.list(&g.proxies);
        let deadline = Instant::now() + DEFAULT_TIMEOUT;
        let mut last_err: Option<GrpcError> = None;
        for proxy in &list {
            if Instant::now() >= deadline {
                break;
            }
            let ret = match proxy.query(req, deadline).await {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            if !response_matches(req, &ret) {
                let m = req.error_reply(ResponseCode::FormErr);
                w.write_msg(m)
                    .await
                    .map_err(|e| PluginError::servfail("grpc", e.to_string()))?;
                return Ok(ResponseCode::NoError);
            }
            if ret.metadata.response_code == ResponseCode::NXDomain && g.fall.through(&name) && self.next.is_some() {
                return next_or_failure("grpc", &self.next, ctx, w, req).await;
            }
            w.write_msg(ret)
                .await
                .map_err(|e| PluginError::servfail("grpc", e.to_string()))?;
            return Ok(ResponseCode::NoError);
        }
        // every upstream failed (or there are none): fall through if
        // allowed, else SERVFAIL with the last error
        if g.fall.through(&name) && self.next.is_some() {
            return next_or_failure("grpc", &self.next, ctx, w, req).await;
        }
        Err(PluginError::servfail(
            "grpc",
            last_err.map_or_else(|| "no healthy gRPC proxies".to_string(), |e| e.to_string()),
        ))
    }
}

/// `request.Match`: the reply has one question, ours.
fn response_matches(req: &Request, ret: &Message) -> bool {
    if ret.queries.len() != 1 || ret.metadata.message_type != MessageType::Response {
        return false;
    }
    let (q, rq) = (&ret.queries[0], req.query());
    q.name() == rq.name() && q.query_type() == rq.query_type() && q.query_class() == rq.query_class()
}

#[cfg(test)]
mod tests;
