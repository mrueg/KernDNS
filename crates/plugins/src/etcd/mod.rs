//! `etcd`: SkyDNS service discovery from etcd v3. Port of `plugin/etcd`.
//!
//! ```text
//! etcd [ZONES...] {
//!     fallthrough [ZONES...]
//!     path PATH
//!     endpoint ENDPOINT...
//!     credentials USERNAME PASSWORD
//!     tls [CERT KEY] [CACERT]
//!     min-lease-ttl DURATION
//!     max-lease-ttl DURATION
//!     no_apex_fallback
//! }
//! ```
//!
//! Like CoreDNS, every query reads etcd (one prefix range, a second exact
//! read when the prefix is empty, and one `LeaseTimeToLive` per key with a
//! lease); nothing is watched or cached here, that is the `cache` plugin's
//! job. Records become answers through the shared service backend
//! ([`crate::backend`]), as in CoreDNS. The etcd client is KernDNS's own
//! ([`client`]).

pub mod client;
pub mod msg;
#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kerndns_core::proto::op::{Message, ResponseCode};
use kerndns_core::proto::rr::{Record, RecordType};
use kerndns_core::zones::{self, Fall};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure,
};

use crate::backend::{self, BackendError, BackendResult, Options, Service, ServiceBackend, State};
use client::{KeyValue, Kv};

const NAME: &str = "etcd";
/// Priority of services that set none.
const DEFAULT_PRIORITY: i32 = 10;
/// TTL of services without a TTL or lease.
const DEFAULT_TTL: u32 = 300;
const DEFAULT_LEASE_MIN_TTL: u32 = 30;
const DEFAULT_LEASE_MAX_TTL: u32 = 86400;
/// Time budget for each etcd read.
const ETCD_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_ENDPOINT: &str = "http://localhost:2379";
const KEY_NOT_FOUND: &str = "key not found";

/// The plugin's configuration and its etcd client, like `etcd.Etcd`.
pub struct Etcd {
    pub fall: Fall,
    pub zones: Vec<String>,
    pub path_prefix: String,
    pub min_lease_ttl: u32,
    pub max_lease_ttl: u32,
    /// Don't fall back to the zone's whole subtree when `apex.dns.ZONE`
    /// does not exist.
    pub no_apex_fallback: bool,
    pub endpoints: Vec<String>,
    pub username: String,
    pub password: String,
    pub client: Arc<dyn Kv>,
}

impl Etcd {
    pub fn new(zones: Vec<String>, client: Arc<dyn Kv>) -> Etcd {
        Etcd {
            fall: Fall::default(),
            zones,
            path_prefix: "skydns".into(),
            min_lease_ttl: DEFAULT_LEASE_MIN_TTL,
            max_lease_ttl: DEFAULT_LEASE_MAX_TTL,
            no_apex_fallback: false,
            endpoints: vec![DEFAULT_ENDPOINT.into()],
            username: String::new(),
            password: String::new(),
            client,
        }
    }

    /// Read `path`, or everything below it when `recursive` (and `path`
    /// itself if nothing is below it), like `Etcd.get`.
    async fn get(&self, path: &str, recursive: bool) -> BackendResult<Vec<KeyValue>> {
        let deadline = Instant::now() + ETCD_TIMEOUT;
        let other = |e: client::RpcError| BackendError::Other(e.to_string());
        if recursive {
            let dir = if path.ends_with('/') {
                path.to_string()
            } else {
                format!("{path}/")
            };
            let r = self.client.get(&dir, true, deadline).await.map_err(other)?;
            if r.count != 0 {
                return Ok(r.kvs);
            }
            let r = self
                .client
                .get(dir.trim_end_matches('/'), false, deadline)
                .await
                .map_err(other)?;
            if r.count == 0 {
                return Err(BackendError::NameError(KEY_NOT_FOUND));
            }
            return Ok(r.kvs);
        }
        let r = self.client.get(path, false, deadline).await.map_err(other)?;
        if r.count == 0 {
            return Err(BackendError::NameError(KEY_NOT_FOUND));
        }
        Ok(r.kvs)
    }

    /// Services from the keys; with a wildcard, only keys whose labels
    /// match the name's (`*` and `any` match any label), like `loopNodes`.
    async fn loop_nodes(
        &self,
        kvs: Vec<KeyValue>,
        name_parts: &[&str],
        star: bool,
        qtype: RecordType,
    ) -> BackendResult<Vec<Service>> {
        let mut sx = Vec::new();
        'nodes: for kv in kvs {
            let key = String::from_utf8_lossy(&kv.key);
            if star {
                let key_parts: Vec<&str> = key.split('/').collect();
                for (i, n) in name_parts.iter().enumerate() {
                    // a name longer than the key
                    let Some(k) = key_parts.get(i) else { continue 'nodes };
                    if *n == "*" || *n == "any" {
                        continue;
                    }
                    if k != n {
                        continue 'nodes;
                    }
                }
            }
            let mut serv = msg::decode_service(&kv.value).map_err(|e| BackendError::Other(format!("{key}: {e}")))?;
            serv.key = key.into_owned();
            serv.ttl = self.ttl(kv.lease, serv.ttl).await;
            if serv.priority == 0 {
                serv.priority = DEFAULT_PRIORITY;
            }
            // only TXT answers come from services without a host
            if (qtype == RecordType::TXT && !serv.text.is_empty()) || !serv.host.is_empty() {
                sx.push(serv);
            }
        }
        Ok(sx)
    }

    /// The smaller of the lease's TTL (clamped to the lease bounds) and the
    /// service's, either one if the other is unset, else 300, like `TTL`.
    async fn ttl(&self, lease: i64, serv_ttl: u32) -> u32 {
        let mut etcd_ttl = 0;
        if lease != 0
            && let Ok(t) = self.client.lease_ttl(lease, Instant::now() + ETCD_TIMEOUT).await
            && t > 0
        {
            etcd_ttl = self.clamp_lease_ttl(t);
        }
        match (etcd_ttl, serv_ttl) {
            (0, 0) => DEFAULT_TTL,
            (0, s) => s,
            (e, 0) => e,
            (e, s) => e.min(s),
        }
    }

    fn clamp_lease_ttl(&self, ttl: i64) -> u32 {
        let min = if self.min_lease_ttl == 0 {
            DEFAULT_LEASE_MIN_TTL
        } else {
            self.min_lease_ttl
        };
        let max = if self.max_lease_ttl == 0 {
            DEFAULT_LEASE_MAX_TTL
        } else {
            self.max_lease_ttl
        };
        if ttl < i64::from(min) {
            min
        } else if ttl > i64::from(max) {
            max
        } else {
            ttl as u32
        }
    }
}

#[async_trait]
impl ServiceBackend for Etcd {
    async fn services(&self, ctx: &Context, st: &State, exact: bool, _opt: Options) -> BackendResult<Vec<Service>> {
        self.records(ctx, st, exact).await.map(msg::group)
    }

    async fn reverse(&self, ctx: &Context, st: &State, exact: bool, opt: Options) -> BackendResult<Vec<Service>> {
        self.services(ctx, st, exact, opt).await
    }

    async fn lookup(&self, ctx: &Context, st: &State, name: &str, qtype: RecordType) -> Option<Message> {
        let n = kerndns_core::proto::rr::Name::from_ascii(name).ok()?;
        kerndns_core::upstream::lookup(ctx, &st.req, &n, qtype)
            .await
            .ok()
            .flatten()
    }

    /// Like `Etcd.Records`: the name's key and everything below it (just
    /// the key when `exact`), cut at a wildcard label.
    async fn records(&self, _ctx: &Context, st: &State, exact: bool) -> BackendResult<Vec<Service>> {
        let name = st.name_ref();
        let (path, star) = msg::path_with_wildcard(name, &self.path_prefix);
        let kvs = self.get(&path, !exact).await?;
        let full = msg::path(name, &self.path_prefix);
        let segments: Vec<&str> = full.split('/').collect();
        self.loop_nodes(kvs, &segments, star, st.qtype()).await
    }

    /// The current Unix time.
    fn serial(&self, _st: &State) -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }

    fn min_ttl(&self, _st: &State) -> u32 {
        30
    }
}

/// The handler, like `Etcd.ServeDNS`.
pub struct EtcdHandler {
    pub e: Arc<Etcd>,
    pub next: Next,
}

#[async_trait]
impl Handler for EtcdHandler {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let e = &*self.e;
        let opt = Options {
            no_apex_fallback: e.no_apex_fallback,
        };
        let Some(zone) = zones::matches(&e.zones, &req.name()) else {
            return next_or_failure(NAME, &self.next, ctx, w, req).await;
        };
        let zone = zone.to_string();
        let st = State::new(req.clone(), zone.clone());
        let b: &dyn ServiceBackend = e;

        let mut truncated = false;
        let mut extra = Vec::new();
        let result: BackendResult<Vec<Record>> = match st.qtype() {
            RecordType::A => backend::a(b, ctx, &zone, &st, opt).await.map(|(r, tc)| {
                truncated = tc;
                r
            }),
            RecordType::AAAA => backend::aaaa(b, ctx, &zone, &st, opt).await.map(|(r, tc)| {
                truncated = tc;
                r
            }),
            RecordType::TXT => backend::txt(b, ctx, &zone, &st, Vec::new(), opt).await.map(|(r, tc)| {
                truncated = tc;
                r
            }),
            RecordType::CNAME => backend::cname(b, ctx, &st, opt).await,
            RecordType::PTR => backend::ptr(b, ctx, &st, opt).await,
            RecordType::MX => backend::mx(b, ctx, &zone, &st, opt).await.map(|(r, x)| {
                extra = x;
                r
            }),
            RecordType::SRV => backend::srv(b, ctx, &zone, &st, opt).await.map(|(r, x)| {
                extra = x;
                r
            }),
            RecordType::SOA => Ok(backend::soa(b, &zone, &st)),
            RecordType::NS if st.name_ref() == zone => backend::ns(b, ctx, &zone, &st, opt).await.map(|(r, x)| {
                extra = x;
                r
            }),
            // a fake A lookup tells NODATA from NXDOMAIN
            _ => backend::a(b, ctx, &zone, &st, opt).await.map(|_| Vec::new()),
        };
        let records = match result {
            Err(BackendError::NameError(_)) => {
                if e.fall.through(st.name_ref()) {
                    return next_or_failure(NAME, &self.next, ctx, w, req).await;
                }
                return backend::backend_error(b, &zone, ResponseCode::NXDomain, &st, w, NAME).await;
            }
            Err(BackendError::Other(err)) => {
                // SERVFAIL with the SOA is written; the error is for `errors`
                backend::backend_error(b, &zone, ResponseCode::ServFail, &st, w, NAME).await?;
                return Err(PluginError::new(NAME, ResponseCode::NoError, err));
            }
            Ok(r) => r,
        };
        if records.is_empty() {
            return backend::backend_error(b, &zone, ResponseCode::NoError, &st, w, NAME).await;
        }
        let mut m = req.reply();
        m.metadata.truncation = truncated;
        m.metadata.authoritative = true;
        m.answers = records;
        m.additionals = extra;
        w.write_msg(m)
            .await
            .map_err(|err| PluginError::servfail(NAME, err.to_string()))?;
        Ok(ResponseCode::NoError)
    }
}

/// `parseTTL`: a number of seconds or a Go duration (`30s`, `5m`, `2h30m`).
pub fn parse_ttl(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let invalid = || "invalid TTL format, use format like '30', '30s', '5m', '1h', or '2h30m'".to_string();
    let secs = if s.parse::<u64>().is_ok() {
        // a plain number is seconds, but still goes through ParseDuration
        go_duration_secs(&format!("{s}s")).ok_or_else(invalid)?
    } else {
        go_duration_secs(s).ok_or_else(invalid)?
    };
    if secs < 0.0 {
        return Err("TTL must be non-negative".into());
    }
    if secs > 4294967295.0 {
        return Err("TTL too large, maximum is 4294967295 seconds".into());
    }
    Ok(secs as u32)
}

/// Go's `time.ParseDuration`, in (fractional) seconds; `None` where Go
/// returns an error.
fn go_duration_secs(s: &str) -> Option<f64> {
    let (neg, mut rest) = match s.as_bytes().first()? {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    if rest == "0" {
        return Some(0.0);
    }
    if rest.is_empty() {
        return None;
    }
    let mut nanos: u128 = 0;
    while !rest.is_empty() {
        let int_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        let (int, r) = rest.split_at(int_end);
        let (frac, r) = match r.strip_prefix('.') {
            Some(r) => {
                let e = r.find(|c: char| !c.is_ascii_digit()).unwrap_or(r.len());
                r.split_at(e)
            }
            None => ("", r),
        };
        if int.is_empty() && frac.is_empty() {
            return None;
        }
        let unit_end = r.find(|c: char| c == '.' || c.is_ascii_digit()).unwrap_or(r.len());
        let (unit, r) = r.split_at(unit_end);
        let scale: u128 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return None,
        };
        let int: u128 = if int.is_empty() { 0 } else { int.parse().ok()? };
        let mut v = int.checked_mul(scale)?;
        if !frac.is_empty() {
            let f: f64 = format!("0.{frac}").parse().ok()?;
            v += (f * scale as f64) as u128;
        }
        nanos = nanos.checked_add(v)?;
        if nanos > i64::MAX as u128 {
            return None;
        }
        rest = r;
    }
    let secs = nanos as f64 / 1e9;
    Some(if neg { -secs } else { secs })
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let e = Arc::new(parse(c)?);
        c.add_plugin(move |next| Arc::new(EtcdHandler { e: e.clone(), next }));
        Ok(())
    }
}

/// `etcdParse`: only the first `etcd` of a server block is read.
pub fn parse(c: &mut Controller<'_>) -> Result<Etcd, SetupError> {
    let err = |m: String| SetupError::new(NAME, m);
    let mut endpoints = vec![DEFAULT_ENDPOINT.to_string()];
    let mut tls_args: Option<Vec<String>> = None;
    let (mut username, mut password) = (String::new(), String::new());
    let placeholder: Arc<dyn Kv> = Arc::new(NoClient);
    let mut e = Etcd::new(Vec::new(), placeholder);
    if !c.next() {
        return Ok(e);
    }
    let keys = c.server_block_keys();
    e.zones = zones::origins_from_args_or_server_block(&c.remaining_args(), &keys);
    while c.next_block() {
        let v = c.val().to_string();
        match v.as_str() {
            // ignored, like CoreDNS
            "stubzones" | "debug" => {}
            "fallthrough" => e.fall.set_zones_from_args(&c.remaining_args()),
            "no_apex_fallback" => {
                if !c.remaining_args().is_empty() {
                    return Err(c.arg_err());
                }
                e.no_apex_fallback = true;
            }
            "path" => {
                if !c.next_arg() {
                    return Err(c.arg_err());
                }
                e.path_prefix = c.val().to_string();
            }
            "endpoint" => {
                let a = c.remaining_args();
                if a.is_empty() {
                    return Err(c.arg_err());
                }
                endpoints = a;
            }
            "upstream" => {
                c.remaining_args();
            }
            "tls" => {
                let mut a = c.remaining_args();
                if let Some(root) = &c.config.root {
                    for x in &mut a {
                        if Path::new(x).is_relative() {
                            *x = root.join(&x).display().to_string();
                        }
                    }
                }
                crate::tlsconfig::client_config(&a).map_err(err)?;
                tls_args = Some(a);
            }
            "credentials" => {
                let a = c.remaining_args();
                if a.is_empty() {
                    return Err(c.arg_err());
                }
                if a.len() != 2 {
                    return Err(c.errf("credentials requires 2 arguments, username and password"));
                }
                username = a[0].clone();
                password = a[1].clone();
            }
            "min-lease-ttl" | "max-lease-ttl" => {
                if !c.next_arg() {
                    return Err(c.arg_err());
                }
                let ttl = parse_ttl(c.val()).map_err(|m| c.errf(format!("invalid {v} value: {m}")))?;
                if v == "min-lease-ttl" {
                    e.min_lease_ttl = ttl;
                } else {
                    e.max_lease_ttl = ttl;
                }
            }
            "}" => {}
            other => return Err(c.errf(format!("unknown property '{other}'"))),
        }
    }
    let tls = match &tls_args {
        Some(a) => Some(crate::tlsconfig::client_config(a).map_err(err)?),
        None => None,
    };
    let credentials = (!username.is_empty() && !password.is_empty()).then(|| (username.clone(), password.clone()));
    e.client = Arc::new(client::Client::new(&endpoints, tls, credentials).map_err(err)?);
    e.endpoints = endpoints;
    e.username = username;
    e.password = password;
    Ok(e)
}

/// The client of an `Etcd` that was never configured (no `etcd` token).
struct NoClient;

#[async_trait]
impl Kv for NoClient {
    async fn get(&self, _: &str, _: bool, _: Instant) -> Result<client::RangeResponse, client::RpcError> {
        Err(client::RpcError::new(
            client::Code::UNAVAILABLE,
            "etcdclient: no client",
        ))
    }

    async fn lease_ttl(&self, _: i64, _: Instant) -> Result<i64, client::RpcError> {
        Err(client::RpcError::new(
            client::Code::UNAVAILABLE,
            "etcdclient: no client",
        ))
    }
}
