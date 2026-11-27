//! `k8s_external`: answers for Services' external IPs (LoadBalancer
//! ingress and `externalIPs`) in an external zone, using the `kubernetes`
//! plugin's API cache. A port of `plugin/k8s_external` and
//! `plugin/kubernetes/external.go`.
//!
//! ```text
//! k8s_external [ZONE...] {
//!     apex APEX
//!     ttl TTL
//!     headless
//!     fallthrough [ZONES...]
//! }
//! ```
//!
//! Zone transfers go through `transfer` ([`ExternalTransfer`]).

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::rdata::{A, AAAA, NS, SOA};
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kerndns_core::transfer::{TransferError, TransferRegistry, Transferer};
use kerndns_core::zones::{self, Fall, extract_address_from_reverse, is_subdomain};
use kerndns_core::{
    BlockConfig, Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request,
    ResponseWriter, SetupError, async_trait, next_or_failure,
};
use kerndns_plugins::backend::{self, HostType, Service, ServiceBackend, State};

use crate::parse::trim_zone;
use crate::{Kubernetes, endpoint_hostname};

/// The block's `kubernetes` instance, filled in when `kubernetes` is set up.
#[derive(Clone, Default)]
pub struct KubernetesSlot(Arc<OnceLock<Arc<Kubernetes>>>);

impl KubernetesSlot {
    pub fn set(&self, k: Arc<Kubernetes>) {
        let _ = self.0.set(k);
    }

    pub fn get(&self) -> Option<&Arc<Kubernetes>> {
        self.0.get()
    }
}

/// The slot of this server block (created on first use).
pub fn slot(cfg: &mut BlockConfig) -> KubernetesSlot {
    if cfg.extensions.get::<KubernetesSlot>().is_none() {
        cfg.extensions.insert(KubernetesSlot::default());
    }
    cfg.extensions.get::<KubernetesSlot>().cloned().expect("inserted above")
}

fn strip_underscore(s: &str) -> &str {
    s.strip_prefix('_').unwrap_or(s)
}

impl Kubernetes {
    /// `External`: services for a name in the external zone.
    pub fn external(&self, st: &State, headless: bool) -> (Vec<Service>, ResponseCode) {
        if st.qtype() == RecordType::PTR
            && let Some(ip) = extract_address_from_reverse(st.name_ref())
        {
            let svcs = self.external_reverse(&ip.to_string());
            return if svcs.is_empty() {
                (svcs, ResponseCode::NXDomain)
            } else {
                (svcs, ResponseCode::NoError)
            };
        }
        let base = trim_zone(st.name_ref(), &st.zone).unwrap_or_default();
        let segs: Vec<&str> = base.split('.').filter(|s| !s.is_empty()).collect();
        let Some(mut last) = segs.len().checked_sub(1) else {
            return (Vec::new(), ResponseCode::ServFail);
        };
        let namespace = segs[last];
        if !self.namespace_exposed(namespace) {
            return (Vec::new(), ResponseCode::NXDomain);
        }
        let Some(l) = last.checked_sub(1) else {
            return (Vec::new(), ResponseCode::NoError);
        };
        last = l;
        let service = segs[last];
        let (mut port, mut protocol, mut endpoint) = ("", "", "");
        let rest = last; // labels left before the service
        match rest {
            0 => {}
            1 => endpoint = strip_underscore(segs[0]),
            2 => {
                protocol = strip_underscore(segs[1]);
                port = strip_underscore(segs[0]);
            }
            _ => return (Vec::new(), ResponseCode::NXDomain),
        }
        let Some(api) = self.api() else {
            return (Vec::new(), ResponseCode::NXDomain);
        };
        let idx = crate::object::Service::key(service, namespace);
        let zone_path = backend::path(&st.zone, "c");
        let mut rcode = ResponseCode::NXDomain;
        let mut services = Vec::new();
        let mut endpoints = None;
        let pp = |a_port: &str, b_port: &str, a_proto: &str, b_proto: &str| {
            (a_port.is_empty() || a_port.eq_ignore_ascii_case(b_port))
                && (a_proto.is_empty() || a_proto.eq_ignore_ascii_case(b_proto))
        };
        for svc in api.svc_index(&idx) {
            if svc.namespace != namespace || svc.name != service {
                continue;
            }
            if headless && svc.external_ips.is_empty() && (svc.headless() || !endpoint.is_empty()) {
                let eps = endpoints.get_or_insert_with(|| api.ep_index(&idx));
                for ep in eps.iter() {
                    if crate::object::Service::key(&svc.name, &svc.namespace) != ep.index {
                        continue;
                    }
                    for sub in &ep.subsets {
                        for addr in &sub.addresses {
                            let host = endpoint_hostname(addr, self.endpoint_name_mode);
                            if !endpoint.is_empty() && !endpoint.eq_ignore_ascii_case(&host) {
                                continue;
                            }
                            for p in &sub.ports {
                                if !pp(port, &p.name, protocol, &p.protocol) {
                                    continue;
                                }
                                rcode = ResponseCode::NoError;
                                services.push(Service {
                                    host: addr.ip.clone(),
                                    port: p.port,
                                    ttl: self.ttl,
                                    key: format!("{zone_path}/{}/{}/{host}", svc.namespace, svc.name),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
                continue;
            }
            for ip in &svc.external_ips {
                for p in &svc.ports {
                    if !pp(port, &p.name, protocol, &p.protocol) {
                        continue;
                    }
                    rcode = ResponseCode::NoError;
                    services.push(Service {
                        host: ip.clone(),
                        port: p.port,
                        ttl: self.ttl,
                        key: format!("{zone_path}/{}/{}", svc.namespace, svc.name),
                        ..Default::default()
                    });
                }
            }
        }
        if st.qtype() == RecordType::PTR {
            return (Vec::new(), rcode);
        }
        (services, rcode)
    }

    fn external_reverse(&self, ip: &str) -> Vec<Service> {
        let Some(api) = self.api() else { return Vec::new() };
        api.svc_ext_index_reverse(ip)
            .iter()
            .filter(|s| self.namespaces.is_empty() || self.namespace_exposed(&s.namespace))
            .map(|s| Service {
                host: format!("{}.{}", s.name, s.namespace),
                ttl: self.ttl,
                ..Default::default()
            })
            .collect()
    }

    /// `ExternalSerial`: when services' external IPs or ports last changed.
    fn external_serial(&self) -> u32 {
        self.api().map(|a| a.modified_external() as u32).unwrap_or(0)
    }
}

pub struct Setup;

struct Config {
    zones: Vec<String>,
    fall: Fall,
    apex: String,
    ttl: u32,
    headless: bool,
}

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "k8s_external"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut cfg = Config {
            zones: Vec::new(),
            fall: Fall::default(),
            apex: "dns".into(),
            ttl: 5,
            headless: false,
        };
        let keys = c.server_block_keys();
        while c.next() {
            let args = c.remaining_args();
            cfg.zones = zones::origins_from_args_or_server_block(&args, &keys);
            while c.next_block() {
                let opt = c.val().to_string();
                let a = c.remaining_args();
                match opt.as_str() {
                    "ttl" => {
                        let Some(t) = a.first() else { return Err(c.arg_err()) };
                        let t: i64 = t.parse().map_err(|e| SetupError::new("k8s_external", format!("{e}")))?;
                        if !(0..=3600).contains(&t) {
                            return Err(c.errf(format!("ttl must be in range [0, 3600]: {t}")));
                        }
                        cfg.ttl = t as u32;
                    }
                    "apex" => {
                        let Some(x) = a.first() else { return Err(c.arg_err()) };
                        cfg.apex = x.clone();
                    }
                    "headless" => cfg.headless = true,
                    "fallthrough" => cfg.fall.set_zones_from_args(&a),
                    other => {
                        let msg = format!("unknown property '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
        }
        let k = slot(c.config);
        let k2 = k.clone();
        c.on_startup(move || {
            if k2.get().is_none() {
                return Err("kubernetes plugin not loaded".into());
            }
            Ok(())
        });
        let cfg = Arc::new(cfg);
        TransferRegistry::of(c.config).add_source(Arc::new(ExternalTransfer {
            cfg: cfg.clone(),
            k: k.clone(),
        }));
        c.add_plugin(move |next| {
            Arc::new(External {
                cfg: cfg.clone(),
                k: k.clone(),
                next,
            })
        });
        Ok(())
    }
}

pub struct External {
    cfg: Arc<Config>,
    k: KubernetesSlot,
    next: Next,
}

fn rr(owner: &str, ttl: u32, data: RData) -> Record {
    let mut r = Record::from_rdata(Name::from_ascii(owner).unwrap_or_else(|_| Name::root()), ttl, data);
    r.dns_class = DNSClass::IN;
    r
}

impl Config {
    fn soa(&self, k: &Kubernetes, zone: &str) -> Record {
        let c = self;
        let soa = SOA::new(
            Name::from_ascii(backend::join(&["ns1", &c.apex, zone])).unwrap_or_default(),
            Name::from_ascii(backend::join(&["hostmaster", &c.apex, zone])).unwrap_or_default(),
            k.external_serial(),
            7200,
            1800,
            86400,
            c.ttl,
        );
        rr(zone, c.ttl, RData::SOA(soa))
    }

    fn addresses(&self, k: &Kubernetes, zone: &str, owner: &str) -> Vec<Record> {
        k.ns_addrs_ext(true, self.headless, zone)
            .into_iter()
            .map(|(_, ip)| match ip {
                std::net::IpAddr::V4(v4) => rr(owner, self.ttl, RData::A(A(v4))),
                std::net::IpAddr::V6(v6) => rr(owner, self.ttl, RData::AAAA(AAAA(v6))),
            })
            .collect()
    }
}

#[async_trait]
#[allow(clippy::collapsible_match)] // dedup inserts read better outside the match guard
impl Handler for External {
    fn name(&self) -> &'static str {
        "k8s_external"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let name = req.name();
        let Some(zone) = zones::matches(&self.cfg.zones, &name).map(str::to_string) else {
            return next_or_failure("k8s_external", &self.next, ctx, w, req).await;
        };
        let Some(k) = self.k.get().cloned() else {
            return Err(PluginError::servfail("k8s_external", "kubernetes plugin not loaded"));
        };
        let st = State::new(req.clone(), zone.clone());
        let qname = st.qname();
        let c = &self.cfg;
        let mut m = req.reply();
        m.metadata.authoritative = true;

        // the apex and the "dns" sub-apex
        for z in &c.zones {
            if name == *z {
                match req.qtype() {
                    RecordType::SOA => m.answers = vec![self.cfg.soa(&k, &zone)],
                    RecordType::NS => {
                        let ns_name = backend::join(&["ns1", &c.apex, &zone]);
                        m.answers = vec![rr(
                            &zone,
                            c.ttl,
                            RData::NS(NS(Name::from_ascii(&ns_name).unwrap_or_default())),
                        )];
                        m.additionals = self.cfg.addresses(&k, &zone, &backend::join(&["ns1", &c.apex, &qname]));
                    }
                    _ => m.authorities = vec![self.cfg.soa(&k, &zone)],
                }
                return write(w, m).await;
            }
            if is_subdomain(&format!("{}.{z}", c.apex), &name) {
                let base = trim_zone(&name, &zone).unwrap_or_default();
                let labels: Vec<&str> = base.split('.').filter(|l| !l.is_empty()).collect();
                match labels.len() {
                    2 if labels[0] == "ns1" => {
                        m.answers = self
                            .cfg
                            .addresses(&k, &zone, &qname)
                            .into_iter()
                            .filter(|r| r.record_type() == req.qtype())
                            .collect();
                        if m.answers.is_empty() {
                            m.authorities = vec![self.cfg.soa(&k, &zone)];
                        }
                    }
                    1 => m.authorities = vec![self.cfg.soa(&k, &zone)],
                    _ => {
                        m.metadata.response_code = ResponseCode::NXDomain;
                        m.authorities = vec![self.cfg.soa(&k, &zone)];
                    }
                }
                return write(w, m).await;
            }
        }

        let (svc, rcode) = k.external(&st, c.headless);
        if svc.is_empty() {
            if c.fall.through(&name) && rcode == ResponseCode::NXDomain {
                return next_or_failure("k8s_external", &self.next, ctx, w, req).await;
            }
            m.metadata.response_code = rcode;
            m.authorities = vec![self.cfg.soa(&k, &zone)];
            return write(w, m).await;
        }
        let b: &dyn ServiceBackend = &*k;
        match req.qtype() {
            RecordType::A | RecordType::AAAA => {
                let v6 = req.qtype() == RecordType::AAAA;
                let mut dup = HashSet::new();
                for s in &svc {
                    match s.host_type() {
                        HostType::Cname => {
                            m.answers.push(s.new_cname(&qname, &s.host));
                            let target = format!("{}.", s.host.trim_end_matches('.'));
                            if let Some(resp) = b.lookup(ctx, &st, &target, req.qtype()).await {
                                m.metadata.truncation |= resp.metadata.truncation;
                                m.answers.extend(resp.answers);
                            }
                        }
                        HostType::A(ip) if !v6 => {
                            if dup.insert(s.host.clone()) {
                                m.answers.push(rr(&qname, c.ttl, RData::A(A(ip))));
                            }
                        }
                        HostType::Aaaa(ip) if v6 => {
                            if dup.insert(s.host.clone()) {
                                m.answers.push(rr(&qname, c.ttl, RData::AAAA(AAAA(ip))));
                            }
                        }
                        _ => {}
                    }
                }
            }
            RecordType::SRV => {
                let (records, extra) = srv(b, ctx, &st, &svc, c.ttl).await;
                m.answers = records;
                m.additionals = extra;
            }
            RecordType::PTR => {
                let mut dup = HashSet::new();
                for s in &svc {
                    if dup.insert(s.host.clone()) {
                        let mut r = s.new_ptr(&qname, &backend::join(&[&s.host, &c.zones[0]]));
                        r.ttl = c.ttl;
                        m.answers.push(r);
                    }
                }
            }
            _ => m.authorities = vec![self.cfg.soa(&k, &zone)],
        }
        if m.answers.is_empty() {
            m.authorities = vec![self.cfg.soa(&k, &zone)];
        }
        write(w, m).await
    }
}

/// SRV for external services, like `External.srv`.
async fn srv(
    b: &dyn ServiceBackend,
    ctx: &Context,
    st: &State,
    services: &[Service],
    ttl: u32,
) -> (Vec<Record>, Vec<Record>) {
    let mut w: std::collections::HashMap<i32, i32> = std::collections::HashMap::new();
    for s in services {
        *w.entry(s.priority).or_insert(0) += if s.weight != 0 { s.weight } else { 100 };
    }
    let (mut records, mut extra) = (Vec::new(), Vec::new());
    let mut dup: HashSet<(String, u16, String)> = HashSet::new();
    let qname = st.qname();
    for s in services {
        if s.port == -1 {
            continue;
        }
        let mut w1 = 100.0 / w[&s.priority] as f64;
        w1 *= if s.weight == 0 { 100.0 } else { s.weight as f64 };
        let weight = (w1.floor() as u16).max(1);
        match s.host_type() {
            HostType::Cname => {
                let addr = format!("{}.", s.host.trim_end_matches('.'));
                let r = s.new_srv(&qname, weight);
                if dup.insert((addr.clone(), s.port as u16, String::new())) {
                    records.push(r);
                }
                if dup.insert((addr.clone(), 0, addr.clone())) {
                    for t in [RecordType::A, RecordType::AAAA] {
                        if let Some(resp) = b.lookup(ctx, st, &addr, t).await {
                            extra.extend(resp.answers);
                        }
                    }
                }
            }
            ht @ (HostType::A(_) | HostType::Aaaa(_)) => {
                let mut s2 = s.clone();
                s2.host = backend::domain(&s.key);
                let r = s2.new_srv(&qname, weight);
                let target = format!("{}.", s2.host.trim_end_matches('.'));
                if dup.insert((target.clone(), s.port as u16, String::new())) {
                    records.push(r);
                }
                if dup.insert((target.clone(), 0, s.host.clone())) {
                    extra.push(match ht {
                        HostType::A(ip) => rr(&target, ttl, RData::A(A(ip))),
                        HostType::Aaaa(ip) => rr(&target, ttl, RData::AAAA(AAAA(ip))),
                        _ => unreachable!(),
                    });
                }
            }
            HostType::Txt => {}
        }
    }
    (records, extra)
}

async fn write(w: &mut dyn ResponseWriter, m: kerndns_core::proto::op::Message) -> HandlerResult {
    w.write_msg(m)
        .await
        .map_err(|e| PluginError::servfail("k8s_external", e.to_string()))?;
    Ok(ResponseCode::NoError)
}

/// `kubernetes.Endpoint` and `kubernetes.PortProtocol`: what a group of
/// headless records in [`Kubernetes::external_services`] answers for.
pub const ENDPOINT: &str = "endpoint";
pub const PORT_PROTOCOL: &str = "port.protocol";

/// Records of headless services, grouped by `<key>/endpoint` or
/// `<key>/port.protocol`, in first-seen order (Go's map order is random).
pub type HeadlessGroups = Vec<(String, Vec<Service>)>;

fn port_key(base: &str, protocol: &str, name: &str) -> String {
    format!("{base}/_{}/_{}", protocol.to_lowercase(), name.to_lowercase())
}

impl Kubernetes {
    /// `ExternalServices`: every service with external IPs and, with
    /// `headless`, the records of headless services.
    pub fn external_services(&self, zone: &str, headless: bool) -> (Vec<Service>, HeadlessGroups) {
        let zone_path = backend::path(zone, "c");
        let mut services = Vec::new();
        let mut groups: HeadlessGroups = Vec::new();
        let mut add = |key: String, s: Service| match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(s),
            None => groups.push((key, vec![s])),
        };
        let Some(api) = self.api() else {
            return (services, groups);
        };
        let mut list = api.service_list();
        list.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.namespace.cmp(&b.namespace)));
        for svc in list {
            let base = format!("{zone_path}/{}/{}", svc.namespace, svc.name);
            if headless && svc.external_ips.is_empty() && svc.headless() {
                for ep in api.ep_index(&crate::object::Service::key(&svc.name, &svc.namespace)) {
                    for sub in &ep.subsets {
                        for addr in &sub.addresses {
                            for p in &sub.ports {
                                let mut s = Service {
                                    host: addr.ip.clone(),
                                    port: p.port,
                                    ttl: self.ttl,
                                    key: format!("{base}/{}", endpoint_hostname(addr, self.endpoint_name_mode)),
                                    ..Default::default()
                                };
                                add(format!("{base}/{ENDPOINT}"), s.clone());
                                // unnamed ports have no SRV record of their own
                                if p.name.is_empty() {
                                    continue;
                                }
                                s.host = backend::domain(&s.key);
                                s.key = port_key(&base, &p.protocol, &p.name);
                                add(format!("{}/{PORT_PROTOCOL}", s.key), s);
                            }
                        }
                    }
                }
                continue;
            }
            for ip in &svc.external_ips {
                for p in &svc.ports {
                    let mut s = Service {
                        host: ip.clone(),
                        port: p.port,
                        ttl: self.ttl,
                        key: base.clone(),
                        ..Default::default()
                    };
                    services.push(s.clone());
                    s.key = port_key(&base, &p.protocol, &p.name);
                    s.target_strip = 2;
                    services.push(s);
                }
            }
        }
        (services, groups)
    }
}

/// `External.a` / `External.aaaa` for a transfer: the address records of
/// `services` (deduplicated by address) named `owner`.
fn address_records(services: &[Service], owner: &str, ttl: u32, v6: bool) -> Vec<Record> {
    let mut dup = HashSet::new();
    let mut out = Vec::new();
    for s in services {
        match s.host_type() {
            HostType::A(ip) if !v6 && dup.insert(s.host.clone()) => out.push(rr(owner, ttl, RData::A(A(ip)))),
            HostType::Aaaa(ip) if v6 && dup.insert(s.host.clone()) => out.push(rr(owner, ttl, RData::AAAA(AAAA(ip)))),
            // CoreDNS also looks the target up, but without a server in the
            // transfer's context that lookup always fails
            HostType::Cname => out.push(s.new_cname(owner, &s.host)),
            _ => {}
        }
    }
    out
}

/// The answer records of `External.srv` (no glue, no lookups).
fn srv_records(services: &[Service], owner: &str) -> Vec<Record> {
    let mut w: std::collections::HashMap<i32, i32> = std::collections::HashMap::new();
    for s in services {
        *w.entry(s.priority).or_insert(0) += if s.weight != 0 { s.weight } else { 100 };
    }
    let mut dup: HashSet<(String, u16)> = HashSet::new();
    let mut out = Vec::new();
    for s in services {
        if s.port == -1 {
            continue;
        }
        let mut w1 = 100.0 / w[&s.priority] as f64;
        w1 *= if s.weight == 0 { 100.0 } else { s.weight as f64 };
        let weight = (w1.floor() as u16).max(1);
        let r = match s.host_type() {
            HostType::Cname => s.new_srv(owner, weight),
            HostType::A(_) | HostType::Aaaa(_) => {
                let mut s2 = s.clone();
                s2.host = backend::domain(&s.key);
                s2.new_srv(owner, weight)
            }
            HostType::Txt => continue,
        };
        let target = match &r.data {
            RData::SRV(x) => x.target.to_ascii(),
            _ => unreachable!(),
        };
        if dup.insert((target, s.port as u16)) {
            out.push(r);
        }
    }
    out
}

impl External {
    /// `k8s_external ZONES` (default `apex` and `ttl`) in front of `k`,
    /// for tests.
    pub fn new(zones: Vec<String>, headless: bool, k: Arc<Kubernetes>, next: Next) -> Self {
        let slot = KubernetesSlot::default();
        slot.set(k);
        let cfg = Config {
            zones,
            fall: Fall::default(),
            apex: "dns".into(),
            ttl: 5,
            headless,
        };
        External {
            cfg: Arc::new(cfg),
            k: slot,
            next,
        }
    }

    /// The zone source `transfer` uses for this plugin.
    pub fn transferer(&self) -> ExternalTransfer {
        ExternalTransfer {
            cfg: self.cfg.clone(),
            k: self.k.clone(),
        }
    }
}

/// `k8s_external` as a zone source for `transfer` (`External.Transfer`).
pub struct ExternalTransfer {
    cfg: Arc<Config>,
    k: KubernetesSlot,
}

impl Transferer for ExternalTransfer {
    fn transfer(&self, zone: &str, serial: u32) -> Result<Vec<Vec<Record>>, TransferError> {
        if zones::matches(&self.cfg.zones, zone) != Some(zone) {
            return Err(TransferError::NotAuthoritative);
        }
        let Some(k) = self.k.get() else {
            return Err(TransferError::NotAuthoritative);
        };
        Ok(self.cfg.transfer(k, zone, serial))
    }
}

impl Config {
    /// `External.Transfer`.
    fn transfer(&self, k: &Kubernetes, zone: &str, serial: u32) -> Vec<Vec<Record>> {
        let soa = self.soa(k, zone);
        let mut out = vec![vec![soa.clone()]];
        let soa_serial = match &soa.data {
            RData::SOA(s) => s.serial,
            _ => 0,
        };
        if serial != 0 && serial >= soa_serial {
            return out;
        }
        let ns_name = backend::join(&["ns1", &self.apex, zone]);
        out.push(vec![rr(
            zone,
            self.ttl,
            RData::NS(NS(Name::from_ascii(&ns_name).unwrap_or_default())),
        )]);
        for r in self.addresses(k, zone, &ns_name) {
            out.push(vec![r]);
        }

        let (svcs, headless) = k.external_services(zone, self.headless);
        let mut srv_seen = HashSet::new();
        for s in &svcs {
            let name = backend::domain(&s.key);
            let one = std::slice::from_ref(s);
            if s.target_strip == 0 {
                for v6 in [false, true] {
                    let rs = address_records(one, &name, self.ttl, v6);
                    if !rs.is_empty() {
                        out.push(rs);
                    }
                }
            }
            for srv in srv_records(one, &name) {
                if srv_seen.insert(srv.name.to_ascii()) {
                    out.push(vec![srv]);
                }
            }
        }
        for (key, svcs) in &headless {
            let (base, kind) = key.rsplit_once('/').unwrap_or((key, ""));
            let name = backend::domain(base);
            match kind {
                ENDPOINT => {
                    // like CoreDNS, the SRV records go out twice: as one
                    // batch and one by one
                    let mut emit = |svcs: &[Service], name: &str| {
                        for v6 in [false, true] {
                            let rs = address_records(svcs, name, self.ttl, v6);
                            if !rs.is_empty() {
                                out.push(rs);
                            }
                        }
                        let recs = srv_records(svcs, name);
                        out.push(recs.clone());
                        out.extend(recs.into_iter().map(|r| vec![r]));
                    };
                    emit(svcs, &name);
                    for s in svcs {
                        emit(std::slice::from_ref(s), &backend::domain(&s.key));
                    }
                }
                PORT_PROTOCOL => out.push(srv_records(svcs, &name)),
                _ => {}
            }
        }
        out.push(vec![soa]);
        out
    }
}
