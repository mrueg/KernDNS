//! `trace`: traces requests through the plugin chain and reports the spans
//! to Zipkin or Datadog. Port of `plugin/trace`.
//!
//! ```text
//! trace [ENDPOINT-TYPE] [ENDPOINT] {
//!     every AMOUNT
//!     service NAME
//!     client_server
//!     datadog_analytics_rate RATE
//!     zipkin_max_backlog_size SIZE
//!     zipkin_max_batch_size SIZE
//!     zipkin_max_batch_interval DURATION
//! }
//! ```
//!
//! CoreDNS uses zipkin-go (through OpenTracing) and dd-trace-go. KernDNS
//! has its own small reporters instead of those SDKs:
//!
//! - **Zipkin**: a `servedns` server span per sampled query with CoreDNS's
//!   tags (`coredns.io/name`, `type`, `proto`, `remote`, `rcode`, `error`)
//!   and a child span per plugin, as `plugin.NextOrFailure` creates them,
//!   sent as Zipkin v2 JSON (`POST ENDPOINT`) in batches like zipkin-go's
//!   HTTP reporter (`zipkin_max_*`).
//! - **Datadog**: a `servedns` span per sampled query with the
//!   `coredns.io@...` tags, sent as JSON to the agent's `/v0.4/traces`.
//!   Like CoreDNS, Datadog traces have no per-plugin spans.
//!
//! The trace id is published as `trace/traceid` metadata. Not supported:
//! continuing a trace from a DoH request's B3 headers, and `client_server`
//! (shared spans) has no effect since spans never join a client's.

use std::fmt::Write as _;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kerndns_core::trace::{SpanRef, Tracer, new_id};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Recorder, Request, ResponseWriter, SetupError,
    async_trait, client_write, next_or_failure, result_rcode,
};
use tokio::sync::Notify;

const NAME: &str = "trace";
const TOP_LEVEL_SPAN: &str = "servedns";
const META_TRACE_ID: &str = "trace/traceid";
const DEF_SERVICE: &str = "coredns";

/// Tag names per provider (`tagByProvider`).
struct TagSet {
    name: &'static str,
    ty: &'static str,
    rcode: &'static str,
    proto: &'static str,
    remote: &'static str,
}

const DEFAULT_TAGS: TagSet = TagSet {
    name: "coredns.io/name",
    ty: "coredns.io/type",
    rcode: "coredns.io/rcode",
    proto: "coredns.io/proto",
    remote: "coredns.io/remote",
};

const DATADOG_TAGS: TagSet = TagSet {
    name: "coredns.io@name",
    ty: "coredns.io@type",
    rcode: "coredns.io@rcode",
    proto: "coredns.io@proto",
    remote: "coredns.io@remote",
};

/// Parsed configuration (`trace`).
#[derive(Debug, Clone, PartialEq)]
struct Config {
    endpoint_type: String,
    endpoint: String,
    service_endpoint: String,
    service_name: String,
    client_server: bool,
    every: u64,
    datadog_analytics_rate: f64,
    zipkin_max_backlog_size: i64,
    zipkin_max_batch_size: i64,
    zipkin_max_batch_interval: Duration,
}

/// `normalizeEndpoint`.
fn normalize_endpoint(ep_type: &str, ep: &str) -> Result<(String, String), String> {
    let default = match ep_type {
        "zipkin" => "localhost:9411",
        "datadog" => "localhost:8126",
        _ => return Err(format!("tracing endpoint type '{ep_type}' is not supported")),
    };
    let mut ep = if ep.is_empty() {
        default.to_string()
    } else {
        ep.to_string()
    };
    if ep_type == "zipkin" {
        let lower = ep.to_lowercase();
        if !lower.starts_with("http://") && !lower.starts_with("https://") {
            ep = format!("http://{ep}/api/v2/spans");
        }
    }
    Ok((ep_type.to_string(), ep))
}

/// Go's `strconv.ParseBool`.
fn parse_bool(s: &str) -> Result<bool, String> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!("strconv.ParseBool: parsing {s:?}: invalid syntax")),
    }
}

fn parse_int(fname: &str, s: &str) -> Result<i64, String> {
    s.parse()
        .map_err(|_| format!("strconv.{fname}: parsing {s:?}: invalid syntax"))
}

/// `traceParse`.
fn parse(c: &mut Controller<'_>) -> Result<Config, SetupError> {
    let err = |e: String| SetupError::new(NAME, e);
    let mut cfg = Config {
        endpoint_type: String::new(),
        endpoint: String::new(),
        service_endpoint: String::new(),
        service_name: DEF_SERVICE.into(),
        client_server: false,
        every: 1,
        datadog_analytics_rate: 0.0,
        zipkin_max_backlog_size: 0,
        zipkin_max_batch_size: 0,
        zipkin_max_batch_interval: Duration::ZERO,
    };
    if let Some(h) = c.config.listen_hosts.first()
        && !h.is_empty()
    {
        let port = c.config.port.clone();
        cfg.service_endpoint = if h.contains(':') {
            format!("[{h}]:{port}")
        } else {
            format!("{h}:{port}")
        };
    }
    while c.next() {
        let args = c.remaining_args();
        let (t, e) = match args.len() {
            0 => normalize_endpoint("zipkin", ""),
            1 => normalize_endpoint("zipkin", &args[0]),
            2 => normalize_endpoint(&args[0].to_lowercase(), &args[1]),
            _ => return Err(c.arg_err()),
        }
        .map_err(err)?;
        cfg.endpoint_type = t;
        cfg.endpoint = e;
        while c.next_block() {
            match c.val() {
                "every" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    cfg.every = a[0]
                        .parse()
                        .map_err(|_| err(format!("strconv.ParseUint: parsing {:?}: invalid syntax", a[0])))?;
                }
                "service" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    cfg.service_name = a[0].clone();
                }
                "client_server" => {
                    let a = c.remaining_args();
                    if a.len() > 1 {
                        return Err(c.arg_err());
                    }
                    cfg.client_server = match a.first() {
                        Some(v) => parse_bool(v).map_err(err)?,
                        None => true,
                    };
                }
                "datadog_analytics_rate" => {
                    let a = c.remaining_args();
                    if a.len() > 1 {
                        return Err(c.arg_err());
                    }
                    cfg.datadog_analytics_rate = match a.first() {
                        Some(v) => v
                            .parse()
                            .map_err(|_| err(format!("strconv.ParseFloat: parsing {v:?}: invalid syntax")))?,
                        None => 0.0,
                    };
                    let r = cfg.datadog_analytics_rate;
                    if !(0.0..=1.0).contains(&r) {
                        return Err(err(format!(
                            "datadog analytics rate must be between 0 and 1, '{r:.6}' is not supported"
                        )));
                    }
                }
                "zipkin_max_backlog_size" | "zipkin_max_batch_size" => {
                    let key = c.val().to_string();
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    let n = parse_int("Atoi", &a[0]).map_err(err)?;
                    if key == "zipkin_max_backlog_size" {
                        cfg.zipkin_max_backlog_size = n;
                    } else {
                        cfg.zipkin_max_batch_size = n;
                    }
                }
                "zipkin_max_batch_interval" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    cfg.zipkin_max_batch_interval = kerndns_core::duration::parse_duration(&a[0]).map_err(err)?;
                }
                other => {
                    let msg = format!("unknown property '{other}'");
                    return Err(c.errf(msg));
                }
            }
        }
    }
    Ok(cfg)
}

/// Minimal JSON string escaping.
fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_map(out: &mut String, kv: &[(String, String)]) {
    out.push('{');
    for (i, (k, v)) in kv.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_str(out, k);
        out.push(':');
        json_str(out, v);
    }
    out.push('}');
}

fn micros(t: SystemTime) -> u128 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_micros()
}

/// A finished span, in the provider's JSON.
struct FinishedSpan {
    trace_id: u128,
    id: u64,
    parent: Option<u64>,
    name: String,
    server: bool,
    start: SystemTime,
    duration: Duration,
    tags: Vec<(String, String)>,
    error: Option<String>,
}

/// Sends spans in batches over HTTP, like zipkin-go's HTTP reporter: a
/// batch goes out when it is full or the interval passes, and the oldest
/// spans are dropped beyond the backlog.
struct Reporter {
    cfg: Arc<Config>,
    local: Option<(IpAddr, u16)>,
    queue: Mutex<Vec<FinishedSpan>>,
    notify: Notify,
    batch_size: usize,
    backlog: usize,
    interval: Duration,
}

impl Reporter {
    fn new(cfg: Arc<Config>) -> Reporter {
        let local = (!cfg.service_endpoint.is_empty())
            .then(|| cfg.service_endpoint.to_socket_addrs().ok()?.next())
            .flatten()
            .map(|a| (a.ip(), a.port()));
        let pos = |n: i64, d: usize| if n > 0 { n as usize } else { d };
        Reporter {
            batch_size: pos(cfg.zipkin_max_batch_size, 100),
            backlog: pos(cfg.zipkin_max_backlog_size, 1000),
            interval: if cfg.zipkin_max_batch_interval.is_zero() {
                Duration::from_secs(1)
            } else {
                cfg.zipkin_max_batch_interval
            },
            local,
            cfg,
            queue: Mutex::new(Vec::new()),
            notify: Notify::new(),
        }
    }

    fn send(&self, span: FinishedSpan) {
        let full = {
            let mut q = self.queue.lock().unwrap();
            q.push(span);
            if q.len() > self.backlog {
                let drop = q.len() - self.backlog;
                q.drain(..drop);
            }
            q.len() >= self.batch_size
        };
        if full {
            self.notify.notify_one();
        }
    }

    fn zipkin_json(&self, spans: &[FinishedSpan]) -> String {
        let mut out = String::from("[");
        for (i, s) in spans.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"traceId\":\"{:016x}\",\"id\":\"{:016x}\"",
                s.trace_id as u64, s.id
            );
            if let Some(p) = s.parent {
                let _ = write!(out, ",\"parentId\":\"{p:016x}\"");
            }
            out.push_str(",\"name\":");
            json_str(&mut out, &s.name);
            if s.server {
                out.push_str(",\"kind\":\"SERVER\"");
            }
            let _ = write!(
                out,
                ",\"timestamp\":{},\"duration\":{}",
                micros(s.start),
                s.duration.as_micros().max(1)
            );
            out.push_str(",\"localEndpoint\":{\"serviceName\":");
            json_str(&mut out, &self.cfg.service_name.to_lowercase());
            match self.local {
                Some((IpAddr::V4(ip), port)) => {
                    let _ = write!(out, ",\"ipv4\":\"{ip}\",\"port\":{port}");
                }
                Some((IpAddr::V6(ip), port)) => {
                    let _ = write!(out, ",\"ipv6\":\"{ip}\",\"port\":{port}");
                }
                None => {}
            }
            out.push('}');
            if let Some(e) = &s.error {
                let _ = write!(
                    out,
                    ",\"annotations\":[{{\"timestamp\":{},\"value\":",
                    micros(s.start + s.duration)
                );
                json_str(&mut out, &format!("event:error error.object:{e}"));
                out.push_str("}]");
            }
            if !s.tags.is_empty() {
                out.push_str(",\"tags\":");
                json_map(&mut out, &s.tags);
            }
            out.push('}');
        }
        out.push(']');
        out
    }

    /// Datadog agent v0.4 traces: one trace per span here.
    fn datadog_json(&self, spans: &[FinishedSpan]) -> String {
        let mut out = String::from("[");
        for (i, s) in spans.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let start = s.start.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
            let _ = write!(
                out,
                "[{{\"trace_id\":{},\"span_id\":{},\"parent_id\":{},\"name\":",
                s.trace_id as u64,
                s.id,
                s.parent.unwrap_or(0)
            );
            json_str(&mut out, &s.name);
            out.push_str(",\"resource\":");
            json_str(&mut out, &s.name);
            out.push_str(",\"service\":");
            json_str(&mut out, &self.cfg.service_name);
            let _ = write!(
                out,
                ",\"start\":{start},\"duration\":{},\"error\":{}",
                s.duration.as_nanos(),
                u8::from(s.error.is_some())
            );
            let mut meta = s.tags.clone();
            meta.push(("dns".into(), "true".into()));
            meta.push(("_dd.p.tid".into(), format!("{:016x}", (s.trace_id >> 64) as u64)));
            out.push_str(",\"meta\":");
            json_map(&mut out, &meta);
            out.push_str(",\"metrics\":{\"_sampling_priority_v1\":1");
            if self.cfg.datadog_analytics_rate > 0.0 {
                let _ = write!(out, ",\"_dd1.sr.eausr\":{}", self.cfg.datadog_analytics_rate);
            }
            out.push_str("}}]");
        }
        out.push(']');
        out
    }

    /// The URL the batches go to, and the body for `spans`.
    fn request(&self, spans: &[FinishedSpan]) -> (String, String) {
        if self.cfg.endpoint_type == "datadog" {
            let host = self
                .cfg
                .endpoint
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_end_matches('/');
            let host = if host.contains(':') {
                host.to_string()
            } else {
                format!("{host}:8126")
            };
            (format!("http://{host}/v0.4/traces"), self.datadog_json(spans))
        } else {
            (self.cfg.endpoint.clone(), self.zipkin_json(spans))
        }
    }

    async fn run(self: Arc<Self>) {
        loop {
            let _ = tokio::time::timeout(self.interval, self.notify.notified()).await;
            loop {
                let batch: Vec<FinishedSpan> = {
                    let mut q = self.queue.lock().unwrap();
                    let n = q.len().min(self.batch_size);
                    q.drain(..n).collect()
                };
                if batch.is_empty() {
                    break;
                }
                let (url, body) = self.request(&batch);
                if let Err(e) = post(&url, body, batch.len()).await {
                    kerndns_core::warning!(plugin = NAME, "failed to send the request: {e}");
                }
                if batch.len() < self.batch_size {
                    break;
                }
            }
        }
    }
}

/// POST `body` (JSON) to an `http://` or `https://` URL.
async fn post(url: &str, body: String, count: usize) -> Result<(), String> {
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::TokioIo;

    let uri: hyper::Uri = url.parse().map_err(|e| format!("{url}: {e}"))?;
    let https = uri.scheme_str().is_some_and(|s| s.eq_ignore_ascii_case("https"));
    let host = uri.host().ok_or_else(|| format!("{url}: no host"))?.to_string();
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let path = uri.path_and_query().map_or("/".to_string(), |p| p.to_string());
    let tcp = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect((host.trim_matches(['[', ']']), port)),
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| e.to_string())?;
    let req = hyper::Request::post(path)
        .header(
            "Host",
            if port == 80 || port == 443 {
                host.clone()
            } else {
                format!("{host}:{port}")
            },
        )
        .header("Content-Type", "application/json")
        .header("X-Datadog-Trace-Count", count.to_string())
        .body(Full::new(bytes::Bytes::from(body)))
        .map_err(|e| e.to_string())?;
    let resp = if https {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(c);
        }
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let (mut s, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        s.send_request(req).await.map_err(|e| e.to_string())?
    } else {
        let (mut s, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        s.send_request(req).await.map_err(|e| e.to_string())?
    };
    let status = resp.status();
    let _ = resp.into_body().collect().await;
    if !status.is_success() {
        return Err(format!("unexpected status {status}"));
    }
    Ok(())
}

impl Tracer for Reporter {
    fn child_finished(&self, parent: &SpanRef, id: u64, name: &str, start: SystemTime, duration: Duration) {
        self.send(FinishedSpan {
            trace_id: parent.trace_id,
            id,
            parent: Some(parent.span_id),
            name: name.to_string(),
            server: false,
            start,
            duration,
            tags: Vec::new(),
            error: None,
        });
    }
}

/// The handler.
pub struct Trace {
    next: Next,
    cfg: Arc<Config>,
    count: Arc<AtomicU64>,
    reporter: Arc<Mutex<Option<Arc<Reporter>>>>,
}

impl Trace {
    fn tags(&self) -> &'static TagSet {
        if self.cfg.endpoint_type == "datadog" {
            &DATADOG_TAGS
        } else {
            &DEFAULT_TAGS
        }
    }
}

#[async_trait]
impl Handler for Trace {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let should_trace =
            self.cfg.every > 0 && (self.count.fetch_add(1, Ordering::Relaxed) + 1).is_multiple_of(self.cfg.every);
        let datadog = self.cfg.endpoint_type == "datadog";
        let reporter = self.reporter.lock().unwrap().clone();
        let Some(reporter) = reporter.filter(|_| should_trace && (datadog || ctx.span.is_none())) else {
            return next_or_failure(NAME, &self.next, ctx, w, req).await;
        };

        let trace_id = (u128::from(new_id()) << 64) | u128::from(new_id());
        let span_id = new_id();
        let meta_id = if datadog {
            format!("{trace_id:032x}")
        } else {
            format!("{:016x}", trace_id as u64)
        };
        ctx.metadata.insert(META_TRACE_ID.into(), meta_id);

        let parent = ctx.span.take();
        if !datadog {
            ctx.span = Some(SpanRef {
                tracer: reporter.clone(),
                trace_id,
                span_id,
            });
        }
        let start = SystemTime::now();
        let started = std::time::Instant::now();
        let mut rw = Recorder::rcode_only(w);
        let res = next_or_failure(NAME, &self.next, ctx, &mut rw, req).await;
        let written = rw.rcode;
        ctx.span = parent;

        let status = result_rcode(&res);
        let rc = match written {
            Some(rc) if client_write(status) => rc,
            None if client_write(status) => kerndns_core::proto::op::ResponseCode::NoError,
            _ => status,
        };
        let t = self.tags();
        let mut tags = vec![
            (t.name.to_string(), req.name()),
            (t.ty.to_string(), req.qtype().to_string()),
            (t.proto.to_string(), req.proto().to_string()),
            (t.remote.to_string(), req.ip().to_string()),
            (t.rcode.to_string(), kerndns_core::metrics::rcode_string(rc)),
        ];
        let error = res.as_ref().err().map(|e| e.to_string());
        if let Some(e) = &error {
            if datadog {
                tags.push(("error.message".into(), e.clone()));
                tags.push(("error.type".into(), "dns_error".into()));
            } else {
                tags.push(("error".into(), "true".into()));
            }
        }
        reporter.send(FinishedSpan {
            trace_id,
            id: span_id,
            parent: None,
            name: TOP_LEVEL_SPAN.into(),
            server: true,
            start,
            duration: started.elapsed(),
            tags,
            error,
        });
        res
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let cfg = Arc::new(parse(c)?);
        let reporter: Arc<Mutex<Option<Arc<Reporter>>>> = Arc::default();
        let count = Arc::new(AtomicU64::new(0));
        {
            let (cfg, reporter) = (cfg.clone(), reporter.clone());
            let task: Arc<Mutex<Option<tokio::task::AbortHandle>>> = Arc::default();
            let task2 = task.clone();
            c.on_startup(move || {
                let r = Arc::new(Reporter::new(cfg));
                if let Ok(h) = tokio::runtime::Handle::try_current() {
                    *task.lock().unwrap() = Some(h.spawn(r.clone().run()).abort_handle());
                }
                *reporter.lock().unwrap() = Some(r);
                Ok(())
            });
            c.on_shutdown(move || {
                if let Some(t) = task2.lock().unwrap().take() {
                    t.abort();
                }
            });
        }
        c.add_plugin(move |next| {
            Arc::new(Trace {
                next,
                cfg: cfg.clone(),
                count: count.clone(),
                reporter: reporter.clone(),
            })
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::op::ResponseCode;
    use kerndns_core::proto::rr::RecordType;
    use kerndns_core::{BlockConfig, CaptureWriter, Hooks, PluginError, ZoneAddr};

    fn parse_trace(input: &str) -> Result<Config, String> {
        with_controller(NAME, input, |c| parse(c).map_err(|e| e.to_string()))
    }

    // setup_test.go: TestTraceParse
    #[test]
    fn trace_parse() {
        let z = "http://localhost:9411/api/v2/spans";
        // (input, endpoint, every, service, client_server, backlog, batch, interval)
        type Case<'a> = (&'a str, &'a str, u64, &'a str, bool, i64, i64, u64);
        let ok: &[Case] = &[
            ("trace", z, 1, "coredns", false, 0, 0, 0),
            (
                "trace localhost:1234",
                "http://localhost:1234/api/v2/spans",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            (
                "trace zipkin-http.monitoring:9411",
                "http://zipkin-http.monitoring:9411/api/v2/spans",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            (
                "trace zipkin http-collector:9411",
                "http://http-collector:9411/api/v2/spans",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            (
                "trace zipkin myhttpscollector:9411",
                "http://myhttpscollector:9411/api/v2/spans",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            (
                "trace zipkin https://zipkin-http.monitoring:9411/custom/spans",
                "https://zipkin-http.monitoring:9411/custom/spans",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            (
                "trace HTTP://collector:9411/api/v2/spans",
                "HTTP://collector:9411/api/v2/spans",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            (
                "trace zipkin HTTPS://collector:9411/api/v2/spans",
                "HTTPS://collector:9411/api/v2/spans",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            (
                "trace zipkin HtTpS://collector:9411/Custom/Spans?Tenant=Blue",
                "HtTpS://collector:9411/Custom/Spans?Tenant=Blue",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            (
                "trace zipkin httpS://collector:9411/Custom/Spans?Tenant=Blue",
                "httpS://collector:9411/Custom/Spans?Tenant=Blue",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            (
                "trace http://localhost:1234/somewhere/else",
                "http://localhost:1234/somewhere/else",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            (
                "trace zipkin localhost:1234",
                "http://localhost:1234/api/v2/spans",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            ("trace datadog localhost", "localhost", 1, "coredns", false, 0, 0, 0),
            (
                "trace datadog http://localhost:8127",
                "http://localhost:8127",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            (
                "trace datadog localhost {\n datadog_analytics_rate 0.1\n}",
                "localhost",
                1,
                "coredns",
                false,
                0,
                0,
                0,
            ),
            ("trace {\n every 100\n}", z, 100, "coredns", false, 0, 0, 0),
            (
                "trace {\n every 100\n service foobar\nclient_server\n}",
                z,
                100,
                "foobar",
                true,
                0,
                0,
                0,
            ),
            (
                "trace {\n every 2\n client_server true\n}",
                z,
                2,
                "coredns",
                true,
                0,
                0,
                0,
            ),
            ("trace {\n client_server false\n}", z, 1, "coredns", false, 0, 0, 0),
            (
                "trace {\n zipkin_max_backlog_size 100\n zipkin_max_batch_size 200\n zipkin_max_batch_interval 10s\n}",
                z,
                1,
                "coredns",
                false,
                100,
                200,
                10,
            ),
        ];
        for (input, endpoint, every, service, cs, backlog, batch, interval) in ok {
            let m = parse_trace(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(m.service_endpoint, "", "{input}");
            assert_eq!(m.endpoint, *endpoint, "{input}");
            assert_eq!(m.every, *every, "{input}");
            assert_eq!(m.service_name, *service, "{input}");
            assert_eq!(m.client_server, *cs, "{input}");
            assert_eq!(m.zipkin_max_backlog_size, *backlog, "{input}");
            assert_eq!(m.zipkin_max_batch_size, *batch, "{input}");
            assert_eq!(m.zipkin_max_batch_interval, Duration::from_secs(*interval), "{input}");
        }
        for input in [
            "trace footype localhost:4321",
            "trace {\n every 2\n client_server junk\n}",
            "trace datadog localhost {\n datadog_analytics_rate 2\n}",
            "trace {\n zipkin_max_backlog_size wrong\n}",
            "trace {\n zipkin_max_batch_size wrong\n}",
            "trace {\n zipkin_max_batch_interval wrong\n}",
            "trace {\n zipkin_max_backlog_size\n}",
            "trace {\n zipkin_max_batch_size\n}",
            "trace {\n zipkin_max_batch_interval\n}",
            "trace {\n evrey 100\n}",
        ] {
            assert!(parse_trace(input).is_err(), "{input}");
        }
        assert_eq!(
            parse_trace("trace footype localhost:4321").unwrap_err(),
            "plugin/trace: tracing endpoint type 'footype' is not supported"
        );
        assert_eq!(
            parse_trace("trace datadog localhost {\n datadog_analytics_rate 2\n}").unwrap_err(),
            "plugin/trace: datadog analytics rate must be between 0 and 1, '2.000000' is not supported"
        );
    }

    // setup_test.go: TestParseServiceEndpoint
    #[test]
    fn service_endpoint() {
        let cases: &[(&[&str], &str, &str)] = &[
            (&["127.0.0.1"], "8053", "127.0.0.1:8053"),
            (&["3d47:98c0:b113::3"], "8853", "[3d47:98c0:b113::3]:8853"),
            (&["localhost"], "8053", "localhost:8053"),
            (&["3d47:98c0:b113::3", "127.0.0.1"], "8853", "[3d47:98c0:b113::3]:8853"),
        ];
        for (hosts, port, want) in cases {
            let blocks = kerndns_core::corefile::parse(".:53 {\ntrace\n}", "Corefile").unwrap();
            let mut cfg = BlockConfig::new(ZoneAddr::parse(".:53", "53").unwrap());
            cfg.listen_hosts = hosts.iter().map(|h| h.to_string()).collect();
            cfg.port = port.to_string();
            let mut hooks = Hooks::default();
            let mut c = Controller::new(
                NAME,
                kerndns_core::corefile::Dispenser::new(blocks[0].tokens_for(NAME)),
                &mut cfg,
                &mut hooks,
                ".".into(),
            );
            assert_eq!(parse(&mut c).unwrap().service_endpoint, *want);
        }
    }

    /// A handler that writes `rcode` if it is a client-write code and
    /// returns `status` (and `err`), like the Go test's `HandlerFunc`.
    struct Fake {
        rcode: ResponseCode,
        status: ResponseCode,
        err: bool,
    }

    #[async_trait]
    impl Handler for Fake {
        fn name(&self) -> &'static str {
            "fake"
        }
        async fn serve_dns(&self, _: &mut Context, w: &mut dyn ResponseWriter, r: &Request) -> HandlerResult {
            if client_write(self.status) {
                let _ = w.write_msg(r.error_reply(self.rcode)).await;
            }
            if self.err {
                return Err(PluginError::new("fake", self.status, "test error"));
            }
            Ok(self.status)
        }
    }

    fn tracer(next: Next, endpoint_type: &str) -> (Trace, Arc<Reporter>) {
        let input = if endpoint_type == "datadog" {
            "trace datadog localhost"
        } else {
            "trace"
        };
        let cfg = Arc::new(parse_trace(input).unwrap());
        let r = Arc::new(Reporter::new(cfg.clone()));
        let t = Trace {
            next,
            cfg,
            count: Arc::default(),
            reporter: Arc::new(Mutex::new(Some(r.clone()))),
        };
        (t, r)
    }

    // trace_test.go: TestTrace
    #[tokio::test]
    async fn trace() {
        use ResponseCode::*;
        // (name, rcode, status, qname, qtype, err)
        let cases = [
            ("NXDOMAIN", NXDomain, NoError, "example.org.", RecordType::A, false),
            ("NOERROR", NoError, NoError, "example.net.", RecordType::CNAME, false),
            ("SERVFAIL", ServFail, NoError, "example.net.", RecordType::A, true),
            (
                "No response written",
                ServFail,
                ServFail,
                "example.net.",
                RecordType::A,
                true,
            ),
        ];
        for (name, rcode, status, qname, qtype, err) in cases {
            let (t, r) = tracer(Some(Arc::new(Fake { rcode, status, err })), "zipkin");
            let req = query(qname, qtype, "10.240.0.1:40212");
            let mut ctx = Context::new(".", "dns://:53");
            let mut w = CaptureWriter::new();
            let _ = t.serve_dns(&mut ctx, &mut w, &req).await;
            let spans = std::mem::take(&mut *r.queue.lock().unwrap());
            // the root and the next plugin
            assert_eq!(spans.len(), 2, "{name}");
            let (child, root) = (&spans[0], &spans[1]);
            assert_eq!(child.name, "fake");
            assert_eq!(child.parent, Some(root.id));
            assert_eq!(child.trace_id, root.trace_id);
            assert_eq!(root.name, TOP_LEVEL_SPAN, "{name}");
            let tag = |k: &str| root.tags.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
            assert_eq!(tag("coredns.io/name").as_deref(), Some(qname), "{name}");
            assert_eq!(tag("coredns.io/type"), Some(qtype.to_string()), "{name}");
            assert_eq!(tag("coredns.io/proto").as_deref(), Some("udp"), "{name}");
            assert_eq!(tag("coredns.io/remote").as_deref(), Some("10.240.0.1"), "{name}");
            assert_eq!(
                tag("coredns.io/rcode"),
                Some(kerndns_core::metrics::rcode_string(rcode)),
                "{name}"
            );
            assert_eq!(tag("error").is_some(), err, "{name}");
            assert_eq!(
                ctx.metadata.get(META_TRACE_ID),
                Some(&format!("{:016x}", root.trace_id as u64))
            );
            assert!(ctx.span.is_none(), "the span ends with the request");
            let json = r.zipkin_json(&spans);
            assert!(json.contains("\"kind\":\"SERVER\""), "{json}");
            assert!(
                json.contains("\"localEndpoint\":{\"serviceName\":\"coredns\"}"),
                "{json}"
            );
        }
    }

    // trace_test.go: TestTrace_DataDog
    #[tokio::test]
    async fn trace_datadog() {
        let (t, r) = tracer(
            Some(Arc::new(Fake {
                rcode: ResponseCode::NXDomain,
                status: ResponseCode::NoError,
                err: false,
            })),
            "datadog",
        );
        let req = query("example.org.", RecordType::A, "10.240.0.1:40212");
        let mut ctx = Context::new(".", "dns://:53");
        let mut w = CaptureWriter::new();
        t.serve_dns(&mut ctx, &mut w, &req).await.unwrap();
        let spans = std::mem::take(&mut *r.queue.lock().unwrap());
        // no per-plugin spans with Datadog
        assert_eq!(spans.len(), 1);
        let tag = |k: &str| spans[0].tags.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(tag("coredns.io@name").as_deref(), Some("example.org."));
        assert_eq!(tag("coredns.io@rcode").as_deref(), Some("NXDOMAIN"));
        assert_eq!(ctx.metadata.get(META_TRACE_ID).unwrap().len(), 32);
        let (url, body) = r.request(&spans);
        assert_eq!(url, "http://localhost:8126/v0.4/traces");
        assert!(body.starts_with("[[{\"trace_id\":"), "{body}");
        assert!(body.contains("\"service\":\"coredns\""), "{body}");
    }

    #[tokio::test]
    async fn every() {
        let next = reply(|r: &Request| r.reply());
        let (mut t, r) = tracer(next, "zipkin");
        let mut cfg = (*t.cfg).clone();
        cfg.every = 3;
        t.cfg = Arc::new(cfg);
        for _ in 0..9 {
            let req = query("example.org.", RecordType::A, "10.240.0.1:40212");
            let _ = serve(&t, &req).await;
        }
        let roots = r.queue.lock().unwrap().iter().filter(|s| s.server).count();
        assert_eq!(roots, 3);
    }

    /// Zipkin batches reach the collector over HTTP.
    #[tokio::test]
    async fn reports_to_zipkin() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let got = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = s.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(i) = text.find("\r\n\r\n")
                    && let Some(len) = text.lines().find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    && buf.len() >= i + 4 + len
                {
                    s.write_all(b"HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\n\r\n")
                        .await
                        .unwrap();
                    return text;
                }
                if n == 0 {
                    return text;
                }
            }
        });
        let cfg = parse_trace(&format!(
            "trace 127.0.0.1:{port} {{\n zipkin_max_batch_interval 50ms\n}}"
        ))
        .unwrap();
        let r = Arc::new(Reporter::new(Arc::new(cfg)));
        let h = tokio::spawn(r.clone().run());
        let (t, _) = tracer(reply(|r: &Request| r.reply()), "zipkin");
        let t = Trace {
            reporter: Arc::new(Mutex::new(Some(r))),
            ..t
        };
        let _ = serve(&t, &query("example.org.", RecordType::A, "10.240.0.1:40212")).await;
        let text = tokio::time::timeout(Duration::from_secs(5), got)
            .await
            .unwrap()
            .unwrap();
        h.abort();
        assert!(text.starts_with("POST /api/v2/spans HTTP/1.1"), "{text}");
        assert!(text.contains("\"name\":\"servedns\""), "{text}");
        assert!(text.contains("\"coredns.io/name\":\"example.org.\""), "{text}");
    }
}
