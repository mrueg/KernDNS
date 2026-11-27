//! Answer generation for plugins that store "services" rather than zone
//! data (`kubernetes`, `etcd`, `k8s_external`), a port of CoreDNS's
//! `plugin/backend.go`, `plugin/backend_lookup.go` and `plugin/etcd/msg`.
//!
//! A backend returns [`Service`]s for a name; the functions here turn them
//! into A, AAAA, SRV, MX, CNAME, TXT, PTR, NS and SOA records with the same
//! CNAME chasing, deduplication and SRV weighting as CoreDNS.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use kerndns_core::proto::op::{Message, Query, ResponseCode};
use kerndns_core::proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT};
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kerndns_core::zones::is_subdomain;
use kerndns_core::{Context, PluginError, Request, ResponseWriter, async_trait};

const MAX_CNAME_CHAIN: usize = 10;
const HOSTMASTER: &str = "hostmaster";

/// A backend record, like `msg.Service`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Service {
    pub host: String,
    pub port: i32,
    pub priority: i32,
    pub weight: i32,
    pub text: String,
    /// Be an MX record; priority becomes the preference.
    pub mail: bool,
    pub ttl: u32,
    pub target_strip: usize,
    pub group: String,
    /// `/c/local/cluster/svc/ns/name[/endpoint]`: the record's own name, reversed.
    pub key: String,
}

/// What `Service::host_type` found in `host`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostType {
    Cname,
    Txt,
    A(std::net::Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
}

/// Parse an IP like Go's `net.ParseIP`; IPv4-mapped IPv6 counts as IPv4.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    match s.parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))),
        ip => Some(ip),
    }
}

fn fqdn(s: &str) -> String {
    if s.ends_with('.') {
        s.to_string()
    } else {
        format!("{s}.")
    }
}

/// `dnsutil.Join`: labels joined and fully qualified.
pub fn join(parts: &[&str]) -> String {
    let parts: Vec<&str> = parts
        .iter()
        .map(|p| p.trim_end_matches('.'))
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        ".".into()
    } else {
        format!("{}.", parts.join("."))
    }
}

fn name(s: &str) -> Name {
    Name::from_ascii(fqdn(s)).unwrap_or_else(|_| Name::root())
}

fn rr(owner: &str, ttl: u32, data: RData) -> Record {
    let mut r = Record::from_rdata(name(owner), ttl, data);
    r.dns_class = DNSClass::IN;
    r
}

/// Skip the first `n` labels of a target, like `targetStrip`.
fn target_strip(host: &str, n: usize) -> String {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    if n >= labels.len() {
        return host.to_string();
    }
    fqdn(&labels[n..].join("."))
}

impl Service {
    pub fn host_type(&self) -> HostType {
        match parse_ip(&self.host) {
            None if self.text.is_empty() => HostType::Cname,
            None => HostType::Txt,
            Some(IpAddr::V4(v4)) => HostType::A(v4),
            Some(IpAddr::V6(v6)) => HostType::Aaaa(v6),
        }
    }

    fn target(&self) -> String {
        let host = fqdn(&self.host);
        if self.target_strip > 0 {
            target_strip(&host, self.target_strip)
        } else {
            host
        }
    }

    pub fn new_srv(&self, owner: &str, weight: u16) -> Record {
        let srv = SRV::new(self.priority as u16, weight, self.port as u16, name(&self.target()));
        rr(owner, self.ttl, RData::SRV(srv))
    }

    pub fn new_mx(&self, owner: &str) -> Record {
        rr(
            owner,
            self.ttl,
            RData::MX(MX::new(self.priority as u16, name(&self.target()))),
        )
    }

    pub fn new_a(&self, owner: &str, ip: std::net::Ipv4Addr) -> Record {
        rr(owner, self.ttl, RData::A(A(ip)))
    }

    pub fn new_aaaa(&self, owner: &str, ip: std::net::Ipv6Addr) -> Record {
        rr(owner, self.ttl, RData::AAAA(AAAA(ip)))
    }

    pub fn new_cname(&self, owner: &str, target: &str) -> Record {
        rr(owner, self.ttl, RData::CNAME(CNAME(name(target))))
    }

    pub fn new_txt(&self, owner: &str) -> Record {
        let chunks: Vec<Vec<u8>> = self.text.as_bytes().chunks(255).map(<[u8]>::to_vec).collect();
        let chunks = if chunks.is_empty() { vec![Vec::new()] } else { chunks };
        rr(
            owner,
            self.ttl,
            RData::TXT(TXT::try_new(chunks.into_iter()).expect("chunks of at most 255 bytes")),
        )
    }

    pub fn new_ptr(&self, owner: &str, target: &str) -> Record {
        rr(owner, self.ttl, RData::PTR(PTR(name(target))))
    }

    pub fn new_ns(&self, owner: &str) -> Record {
        rr(owner, self.ttl, RData::NS(NS(name(&self.target()))))
    }
}

/// `msg.Path`: `/prefix/` + the labels of `s` in reverse order.
pub fn path(s: &str, prefix: &str) -> String {
    let mut labels: Vec<&str> = s.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).collect();
    labels.reverse();
    let mut p = format!("/{prefix}");
    for l in labels {
        p.push('/');
        p.push_str(l);
    }
    p
}

/// `msg.Domain`: the name a key stands for.
pub fn domain(key: &str) -> String {
    let mut l: Vec<&str> = key.split('/').collect();
    if l.last() == Some(&"") {
        l.pop();
    }
    if l.len() < 2 {
        return ".".into();
    }
    // drop the leading "" and the prefix, reverse the rest
    let mut labels: Vec<&str> = l[2..].to_vec();
    labels.reverse();
    join(&labels)
}

/// `Name.Matches`: `child` is `n` or below it (case-insensitive).
fn name_matches(n: &str, child: &str) -> bool {
    is_subdomain(&n.to_ascii_lowercase(), &child.to_ascii_lowercase())
}

/// Errors from a backend; name errors become NXDOMAIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// No such name (`errNoItems`, `errNsNotExposed`, `errInvalidRequest`, ...).
    NameError(&'static str),
    Other(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::NameError(s) => f.write_str(s),
            BackendError::Other(s) => f.write_str(s),
        }
    }
}

/// The request as a backend sees it: possibly with a rewritten question,
/// and the matched zone in the query's case (`request.Request` + `Zone`).
#[derive(Clone)]
pub struct State {
    pub req: Request,
    pub zone: String,
    qname: String,
    name: String,
}

impl State {
    pub fn new(req: Request, zone: String) -> Self {
        let qname = req.qname().to_ascii();
        let name = req.name();
        Self { req, zone, qname, name }
    }

    /// The query name as sent.
    pub fn qname(&self) -> String {
        self.qname.clone()
    }

    /// The query name, lowercase.
    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn name_ref(&self) -> &str {
        &self.name
    }

    pub fn qtype(&self) -> RecordType {
        self.req.qtype()
    }

    /// `NewWithQuestion`: the same request asking `name`/`qtype` (class IN).
    pub fn with_question(&self, qname: &str, qtype: RecordType) -> State {
        let mut req = self.req.clone();
        req.msg.queries = vec![Query::query(name(qname), qtype)];
        State::new(req, self.zone.clone())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub no_apex_fallback: bool,
}

pub type BackendResult<T> = Result<T, BackendError>;

/// `plugin.ServiceBackend`.
#[async_trait]
pub trait ServiceBackend: Send + Sync {
    async fn services(&self, ctx: &Context, st: &State, exact: bool, opt: Options) -> BackendResult<Vec<Service>>;
    async fn reverse(&self, ctx: &Context, st: &State, exact: bool, opt: Options) -> BackendResult<Vec<Service>>;
    /// Resolve a name outside the backend (through the server).
    async fn lookup(&self, ctx: &Context, st: &State, name: &str, qtype: RecordType) -> Option<Message>;
    async fn records(&self, ctx: &Context, st: &State, exact: bool) -> BackendResult<Vec<Service>>;
    fn serial(&self, st: &State) -> u32;
    fn min_ttl(&self, st: &State) -> u32;
}

type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

fn is_duplicate_cname(r: &Record, previous: &[Record]) -> bool {
    let RData::CNAME(c) = &r.data else { return false };
    previous
        .iter()
        .any(|p| matches!(&p.data, RData::CNAME(pc) if pc.0 == c.0))
}

/// `checkForApex`: at the zone apex, ask for `apex.dns.<zone>` first.
async fn check_for_apex(
    b: &dyn ServiceBackend,
    ctx: &Context,
    zone: &str,
    st: &State,
    opt: Options,
) -> BackendResult<Vec<Service>> {
    if st.name() != zone.to_ascii_lowercase() {
        return b.services(ctx, st, false, opt).await;
    }
    let apex = st.with_question(&join(&["apex.dns", zone]), st.qtype());
    match b.services(ctx, &apex, false, opt).await {
        Err(BackendError::NameError(_)) if !opt.no_apex_fallback => b.services(ctx, st, false, opt).await,
        other => other,
    }
}

/// A or AAAA records (with CNAME chasing), like `plugin.A` / `plugin.AAAA`.
#[allow(clippy::collapsible_match)] // dedup inserts read better outside the match guard
pub fn address<'a>(
    b: &'a dyn ServiceBackend,
    ctx: &'a Context,
    zone: &'a str,
    st: &'a State,
    previous: Vec<Record>,
    opt: Options,
    v6: bool,
) -> Fut<'a, BackendResult<(Vec<Record>, bool)>> {
    Box::pin(async move {
        let services = check_for_apex(b, ctx, zone, st, opt).await?;
        let mut records = Vec::new();
        let mut truncated = false;
        let mut dup: HashSet<String> = HashSet::new();
        for serv in services {
            match serv.host_type() {
                HostType::Cname => {
                    if name_matches(&st.name(), &fqdn(&serv.host)) {
                        continue;
                    }
                    let new = serv.new_cname(&st.qname(), &serv.host);
                    if previous.len() > MAX_CNAME_CHAIN || is_duplicate_cname(&new, &previous) {
                        continue;
                    }
                    if is_subdomain(&zone.to_ascii_lowercase(), &fqdn(&serv.host).to_ascii_lowercase()) {
                        let st1 = st.with_question(&serv.host, st.qtype());
                        let mut prev = previous.clone();
                        prev.push(new.clone());
                        if let Ok((next, tc)) = address(b, ctx, zone, &st1, prev, opt, v6).await {
                            if !next.is_empty() {
                                records.push(new);
                                records.extend(next);
                            }
                            truncated |= tc;
                        }
                        continue;
                    }
                    let target = fqdn(&serv.host);
                    let Some(m1) = b.lookup(ctx, st, &target, st.qtype()).await else {
                        continue;
                    };
                    truncated |= m1.metadata.truncation;
                    records.push(new);
                    records.extend(m1.answers);
                }
                HostType::A(ip) if !v6 => {
                    if dup.insert(serv.host.clone()) {
                        records.push(serv.new_a(&st.qname(), ip));
                    }
                }
                HostType::Aaaa(ip) if v6 => {
                    if dup.insert(serv.host.clone()) {
                        records.push(serv.new_aaaa(&st.qname(), ip));
                    }
                }
                _ => {}
            }
        }
        Ok((records, truncated))
    })
}

pub async fn a(
    b: &dyn ServiceBackend,
    ctx: &Context,
    zone: &str,
    st: &State,
    opt: Options,
) -> BackendResult<(Vec<Record>, bool)> {
    address(b, ctx, zone, st, Vec::new(), opt, false).await
}

pub async fn aaaa(
    b: &dyn ServiceBackend,
    ctx: &Context,
    zone: &str,
    st: &State,
    opt: Options,
) -> BackendResult<(Vec<Record>, bool)> {
    address(b, ctx, zone, st, Vec::new(), opt, true).await
}

fn new_address(s: &Service, owner: &str, ip: HostType) -> Option<Record> {
    match ip {
        HostType::A(v4) => Some(s.new_a(owner, v4)),
        HostType::Aaaa(v6) => Some(s.new_aaaa(owner, v6)),
        _ => None,
    }
}

/// Addresses of an out-of-zone target, CNAMEs dropped from the AAAA part.
async fn external_addresses(b: &dyn ServiceBackend, ctx: &Context, st: &State, target: &str) -> Vec<Record> {
    let mut extra = Vec::new();
    if let Some(m) = b.lookup(ctx, st, target, RecordType::A).await {
        extra.extend(m.answers);
    }
    if let Some(m) = b.lookup(ctx, st, target, RecordType::AAAA).await {
        extra.extend(m.answers.into_iter().filter(|r| r.record_type() != RecordType::CNAME));
    }
    extra
}

/// SRV records with weights spread per priority, like `plugin.SRV`.
pub async fn srv(
    b: &dyn ServiceBackend,
    ctx: &Context,
    zone: &str,
    st: &State,
    opt: Options,
) -> BackendResult<(Vec<Record>, Vec<Record>)> {
    let services = b.services(ctx, st, false, opt).await?;
    let mut w: HashMap<i32, i32> = HashMap::new();
    for s in &services {
        let weight = if s.weight != 0 { s.weight } else { 100 };
        *w.entry(s.priority).or_insert(0) += weight;
    }
    let (mut records, mut extra) = (Vec::new(), Vec::new());
    let mut dup: HashSet<(String, u16, String)> = HashSet::new();
    let mut lookup: HashSet<String> = HashSet::new();
    for mut s in services {
        if s.port == -1 {
            continue;
        }
        let mut w1 = 100.0 / w[&s.priority] as f64;
        w1 *= if s.weight == 0 { 100.0 } else { s.weight as f64 };
        let weight = (w1.floor() as u16).max(1);
        match s.host_type() {
            HostType::Cname => {
                let r = s.new_srv(&st.qname(), weight);
                let target = match &r.data {
                    RData::SRV(x) => x.target.to_ascii(),
                    _ => unreachable!(),
                };
                records.push(r);
                if !lookup.insert(target.clone()) {
                    continue;
                }
                if !is_subdomain(&zone.to_ascii_lowercase(), &target.to_ascii_lowercase()) {
                    extra.extend(external_addresses(b, ctx, st, &target).await);
                    continue;
                }
                let st1 = st.with_question(&target, RecordType::A);
                if let Ok((addr, _)) = a(b, ctx, zone, &st1, opt).await {
                    extra.extend(addr);
                }
            }
            ht @ (HostType::A(_) | HostType::Aaaa(_)) => {
                let addr = s.host.clone();
                s.host = domain(&s.key);
                let r = s.new_srv(&st.qname(), weight);
                let target = fqdn(&s.host);
                if dup.insert((target.clone(), s.port as u16, String::new())) {
                    records.push(r);
                }
                if dup.insert((target.clone(), 0, addr))
                    && let Some(x) = new_address(&s, &target, ht)
                {
                    extra.push(x);
                }
            }
            HostType::Txt => {}
        }
    }
    Ok((records, extra))
}

/// MX records, like `plugin.MX`.
pub async fn mx(
    b: &dyn ServiceBackend,
    ctx: &Context,
    zone: &str,
    st: &State,
    opt: Options,
) -> BackendResult<(Vec<Record>, Vec<Record>)> {
    let services = b.services(ctx, st, false, opt).await?;
    let (mut records, mut extra) = (Vec::new(), Vec::new());
    let mut dup: HashSet<(String, u16, String)> = HashSet::new();
    let mut lookup: HashSet<String> = HashSet::new();
    for mut s in services {
        if !s.mail {
            continue;
        }
        match s.host_type() {
            HostType::Cname => {
                let r = s.new_mx(&st.qname());
                let target = match &r.data {
                    RData::MX(x) => x.exchange.to_ascii(),
                    _ => unreachable!(),
                };
                records.push(r);
                if !lookup.insert(target.clone()) {
                    continue;
                }
                if !is_subdomain(&zone.to_ascii_lowercase(), &target.to_ascii_lowercase()) {
                    extra.extend(external_addresses(b, ctx, st, &target).await);
                    continue;
                }
                let st1 = st.with_question(&target, RecordType::A);
                if let Ok((addr, _)) = a(b, ctx, zone, &st1, opt).await {
                    extra.extend(addr);
                }
            }
            ht @ (HostType::A(_) | HostType::Aaaa(_)) => {
                let addr = s.host.clone();
                s.host = domain(&s.key);
                let r = s.new_mx(&st.qname());
                let target = fqdn(&s.host);
                if dup.insert((target.clone(), s.priority as u16, String::new())) {
                    records.push(r);
                }
                if dup.insert((target.clone(), 0, addr))
                    && let Some(x) = new_address(&s, &target, ht)
                {
                    extra.push(x);
                }
            }
            HostType::Txt => {}
        }
    }
    Ok((records, extra))
}

/// A CNAME for the first non-IP service, like `plugin.CNAME`.
pub async fn cname(b: &dyn ServiceBackend, ctx: &Context, st: &State, opt: Options) -> BackendResult<Vec<Record>> {
    let services = b.services(ctx, st, true, opt).await?;
    Ok(match services.first() {
        Some(s) if parse_ip(&s.host).is_none() => vec![s.new_cname(&st.qname(), &s.host)],
        _ => Vec::new(),
    })
}

/// TXT records (with CNAME chasing), like `plugin.TXT`.
#[allow(clippy::collapsible_match)] // dedup inserts read better outside the match guard
pub fn txt<'a>(
    b: &'a dyn ServiceBackend,
    ctx: &'a Context,
    zone: &'a str,
    st: &'a State,
    previous: Vec<Record>,
    opt: Options,
) -> Fut<'a, BackendResult<(Vec<Record>, bool)>> {
    Box::pin(async move {
        let services = b.services(ctx, st, false, opt).await?;
        let mut records = Vec::new();
        let mut truncated = false;
        let mut dup: HashSet<String> = HashSet::new();
        for serv in services {
            match serv.host_type() {
                HostType::Cname => {
                    if name_matches(&st.name(), &fqdn(&serv.host)) {
                        continue;
                    }
                    let new = serv.new_cname(&st.qname(), &serv.host);
                    if previous.len() > MAX_CNAME_CHAIN || is_duplicate_cname(&new, &previous) {
                        continue;
                    }
                    if is_subdomain(&zone.to_ascii_lowercase(), &fqdn(&serv.host).to_ascii_lowercase()) {
                        let st1 = st.with_question(&serv.host, st.qtype());
                        let mut prev = previous.clone();
                        prev.push(new.clone());
                        if let Ok((next, tc)) = txt(b, ctx, zone, &st1, prev, opt).await {
                            truncated |= tc;
                            if !next.is_empty() {
                                records.push(new);
                                records.extend(next);
                            }
                        }
                        continue;
                    }
                    let Some(m1) = b.lookup(ctx, st, &fqdn(&serv.host), st.qtype()).await else {
                        continue;
                    };
                    records.push(new);
                    records.extend(m1.answers);
                }
                HostType::Txt => {
                    if dup.insert(serv.text.clone()) {
                        records.push(serv.new_txt(&st.qname()));
                    }
                }
                _ => {}
            }
        }
        Ok((records, truncated))
    })
}

/// PTR records, like `plugin.PTR`.
pub async fn ptr(b: &dyn ServiceBackend, ctx: &Context, st: &State, opt: Options) -> BackendResult<Vec<Record>> {
    let services = b.reverse(ctx, st, true, opt).await?;
    let mut dup: HashSet<String> = HashSet::new();
    let mut records = Vec::new();
    for s in services {
        if parse_ip(&s.host).is_none() && dup.insert(s.host.clone()) {
            records.push(s.new_ptr(&st.qname(), &s.host));
        }
    }
    Ok(records)
}

/// NS records for the zone from `ns.dns.<zone>`, like `plugin.NS`.
pub async fn ns(
    b: &dyn ServiceBackend,
    ctx: &Context,
    zone: &str,
    st: &State,
    opt: Options,
) -> BackendResult<(Vec<Record>, Vec<Record>)> {
    let st1 = st.with_question(&join(&["ns.dns.", zone]), st.qtype());
    let services = b.services(ctx, &st1, false, opt).await?;
    let (mut records, mut extra) = (Vec::new(), Vec::new());
    let mut seen: HashSet<String> = HashSet::new();
    for mut s in services {
        match s.host_type() {
            HostType::Cname => {
                return Err(BackendError::Other(format!(
                    "NS record must be an IP address: {}",
                    s.host
                )));
            }
            ht @ (HostType::A(_) | HostType::Aaaa(_)) => {
                s.host = domain(&s.key);
                let r = s.new_ns(&st.qname());
                let target = match &r.data {
                    RData::NS(x) => x.0.to_ascii(),
                    _ => unreachable!(),
                };
                if let Some(x) = new_address(&s, &target, ht) {
                    extra.push(x);
                }
                if seen.insert(target) {
                    records.push(r);
                }
            }
            HostType::Txt => {}
        }
    }
    Ok((records, extra))
}

/// The synthesized SOA, like `plugin.SOA`.
pub fn soa(b: &dyn ServiceBackend, zone: &str, st: &State) -> Vec<Record> {
    let min_ttl = b.min_ttl(st);
    let ttl = min_ttl.min(300);
    let soa = SOA::new(
        name(&join(&["ns.dns", zone])),
        name(&join(&[HOSTMASTER, zone])),
        b.serial(st),
        7200,
        1800,
        86400,
        min_ttl,
    );
    vec![rr(zone, ttl, RData::SOA(soa))]
}

/// Answer with `rcode` and the SOA, like `plugin.BackendError`.
pub async fn backend_error(
    b: &dyn ServiceBackend,
    zone: &str,
    rcode: ResponseCode,
    st: &State,
    w: &mut dyn ResponseWriter,
    plugin: &str,
) -> Result<ResponseCode, PluginError> {
    let mut m = st.req.error_reply(rcode);
    m.metadata.authoritative = true;
    m.authorities = soa(b, zone, st);
    w.write_msg(m)
        .await
        .map_err(|e| PluginError::servfail(plugin, e.to_string()))?;
    Ok(ResponseCode::NoError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(
            path("svc1.testns.svc.cluster.local.", "c"),
            "/c/local/cluster/svc/testns/svc1"
        );
        assert_eq!(
            domain("/c/local/cluster/svc/testns/svc1/ep-1"),
            "ep-1.svc1.testns.svc.cluster.local."
        );
        assert_eq!(join(&["ns.dns.", "cluster.local."]), "ns.dns.cluster.local.");
        assert_eq!(target_strip("a.b.example.org.", 1), "b.example.org.");
    }

    #[test]
    fn host_types() {
        let s = |h: &str, t: &str| Service {
            host: h.into(),
            text: t.into(),
            ..Default::default()
        };
        assert_eq!(s("10.0.0.1", "").host_type(), HostType::A("10.0.0.1".parse().unwrap()));
        assert_eq!(
            s("::ffff:10.0.0.1", "").host_type(),
            HostType::A("10.0.0.1".parse().unwrap())
        );
        assert!(matches!(s("1234:abcd::1", "").host_type(), HostType::Aaaa(_)));
        assert_eq!(s("example.org", "").host_type(), HostType::Cname);
        assert_eq!(s("", "hello").host_type(), HostType::Txt);
    }
}
