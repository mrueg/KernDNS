//! `kubernetes`: cluster DNS from the Kubernetes API, a port of CoreDNS's
//! `plugin/kubernetes` (DNS schema 1.1.0).
//!
//! ```text
//! kubernetes [ZONES...] {
//!     endpoint URL
//!     tls CERT KEY CACERT
//!     kubeconfig KUBECONFIG [CONTEXT]
//!     namespaces NAMESPACE...
//!     labels EXPRESSION
//!     namespace_labels EXPRESSION
//!     pods disabled|insecure|verified
//!     endpoint_pod_names
//!     ttl TTL
//!     noendpoints
//!     fallthrough [ZONES...]
//!     ignore empty_service
//!     multicluster [ZONES...]
//!     zonal
//!     startup_timeout DURATION
//!     apiserver_qps QPS
//!     apiserver_burst BURST
//!     apiserver_max_inflight MAX
//! }
//! ```
//!
//! Zone transfers go through `transfer` ([`xfr`]); with `metadata` the
//! plugin publishes the `kubernetes/*` metadata ([`KubernetesMetadata`]).

mod autopath;
pub mod client;
pub mod controller;
pub mod external;
pub mod mcs;
pub mod metrics;
pub mod object;
pub mod parse;
pub mod xfr;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use kerndns_core::duration::parse_duration;
use kerndns_core::plugin::{Metadata, MetadataProvider};
use kerndns_core::proto::op::{Message, MessageType, OpCode, ResponseCode};
use kerndns_core::proto::rr::{Record, RecordType};
use kerndns_core::transfer::TransferRegistry;
use kerndns_core::zones::{self, Fall, extract_address_from_reverse};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Protocol, Request, ResponseWriter,
    SetupError, async_trait, next_or_failure,
};
use kerndns_plugins::backend::{self, BackendError, BackendResult, Options, Service, ServiceBackend, State};

use controller::{DnsController, KubeController};
use parse::{POD, RecordRequest, SVC, parse_request, trim_zone};

pub const DNS_SCHEMA_VERSION: &str = "1.1.0";
const DEFAULT_TTL: u32 = 5;
/// Fake key prefix used in `Service.key`.
const COREDNS: &str = "c";
const DEFAULT_NS_NAME: &str = "ns.dns.";

/// Name errors of the plugin (`errNoItems`, `errNsNotExposed`, `errInvalidRequest`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NoItems,
    NsNotExposed,
    InvalidRequest,
}

impl Error {
    pub fn message(self) -> &'static str {
        match self {
            Error::NoItems => "no items found",
            Error::NsNotExposed => "namespace is not exposed",
            Error::InvalidRequest => "invalid query name",
        }
    }
}

impl From<Error> for BackendError {
    fn from(e: Error) -> Self {
        BackendError::NameError(e.message())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PodMode {
    Disabled,
    Insecure,
    Verified,
}

/// Resolves names outside the cluster zones; tests replace it.
pub type UpstreamFn = Arc<dyn Fn(&str, RecordType) -> Option<Message> + Send + Sync>;

/// The plugin's configuration and API state.
pub struct Kubernetes {
    pub zones: Vec<String>,
    primary_zone: usize,
    pub namespaces: HashSet<String>,
    pub pod_mode: PodMode,
    pub endpoint_name_mode: bool,
    pub fall: Fall,
    pub ttl: u32,
    pub ignore_empty_service: bool,
    pub local_ips: RwLock<Vec<IpAddr>>,
    api: RwLock<Option<Arc<dyn DnsController>>>,
    pub upstream_override: Option<UpstreamFn>,
    /// The local search path from `/etc/resolv.conf`, for `autopath`.
    pub auto_path_search: Vec<String>,
    /// `multicluster`: zones answered from ServiceImports.
    pub multicluster_zones: Vec<String>,
    /// `zonal`: zone-scoped names for headless services.
    pub zonal: bool,
}

impl Kubernetes {
    pub fn new(zones: Vec<String>) -> Self {
        let primary_zone = zones.iter().position(|z| !is_reverse(z)).unwrap_or(0);
        Self {
            zones,
            primary_zone,
            namespaces: HashSet::new(),
            pod_mode: PodMode::Disabled,
            endpoint_name_mode: false,
            fall: Fall::default(),
            ttl: DEFAULT_TTL,
            ignore_empty_service: false,
            local_ips: RwLock::new(Vec::new()),
            api: RwLock::new(None),
            upstream_override: None,
            auto_path_search: Vec::new(),
            multicluster_zones: Vec::new(),
            zonal: false,
        }
    }

    /// `isMultiClusterZone` (`plugin.Zones.Contains`: the zone or below).
    pub fn is_multicluster_zone(&self, zone: &str) -> bool {
        let zone = zone.to_ascii_lowercase();
        self.multicluster_zones.iter().any(|z| zones::is_subdomain(z, &zone))
    }

    pub fn set_api(&self, api: Arc<dyn DnsController>) {
        *self.api.write().unwrap() = Some(api);
    }

    fn api(&self) -> Option<Arc<dyn DnsController>> {
        self.api.read().unwrap().clone()
    }

    fn has_synced(&self) -> bool {
        self.api().is_some_and(|a| a.has_synced())
    }

    /// A request-less state for `zone`, for what CoreDNS calls with an
    /// empty `request.Request` (the SOA of a transfer).
    pub(crate) fn dummy_state(&self, zone: &str) -> State {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        let name = kerndns_core::proto::rr::Name::from_ascii(zone).unwrap_or_default();
        msg.add_query(kerndns_core::proto::op::Query::query(name, RecordType::SOA));
        let any: std::net::SocketAddr = ([0, 0, 0, 0], 0).into();
        State::new(Request::new(msg, any, any, Protocol::Tcp), zone.to_string())
    }

    fn primary_zone(&self) -> &str {
        &self.zones[self.primary_zone]
    }

    fn namespace_exposed(&self, ns: &str) -> bool {
        let configured = self.namespaces.is_empty() || self.namespaces.contains(ns);
        configured && self.api().is_some_and(|a| a.namespace_exists(ns))
    }

    fn endpoint_hostname(&self, addr: &object::EndpointAddress) -> String {
        endpoint_hostname(addr, self.endpoint_name_mode)
    }

    /// `findPods`.
    fn find_pods(&self, r: &RecordRequest, zone: &str) -> Result<Vec<Service>, Error> {
        if self.pod_mode == PodMode::Disabled {
            return Err(Error::NoItems);
        }
        let namespace = &r.namespace;
        if !self.namespace_exposed(namespace) {
            return Err(Error::NoItems);
        }
        let podname = &r.service;
        if podname.is_empty() {
            return Ok(Vec::new());
        }
        let zone_path = backend::path(zone, COREDNS);
        let ip = if podname.matches('-').count() == 3 && !podname.contains("--") {
            podname.replace('-', ".")
        } else {
            podname.replace('-', ":")
        };
        let key = format!("{zone_path}/{POD}/{namespace}/{podname}");
        if self.pod_mode == PodMode::Insecure {
            if backend::parse_ip(&ip).is_none() {
                return Err(Error::NoItems);
            }
            return Ok(vec![Service {
                key,
                host: ip,
                ttl: self.ttl,
                ..Default::default()
            }]);
        }
        let mut pods = Vec::new();
        for p in self.api().map(|a| a.pod_index(&ip)).unwrap_or_default() {
            if p.pod_ips.contains(&ip) && p.namespace.eq_ignore_ascii_case(namespace) {
                pods.push(Service {
                    key: key.clone(),
                    host: ip.clone(),
                    ttl: self.ttl,
                    ..Default::default()
                });
            }
        }
        if pods.is_empty() { Err(Error::NoItems) } else { Ok(pods) }
    }

    /// `findServices`.
    fn find_services(&self, r: &RecordRequest, zone: &str) -> Result<Vec<Service>, Error> {
        if !self.namespace_exposed(&r.namespace) {
            return Err(Error::NoItems);
        }
        if r.service.is_empty() {
            return Ok(Vec::new());
        }
        let Some(api) = self.api() else {
            return Err(Error::NoItems);
        };
        let idx = object::Service::key(&r.service, &r.namespace);
        let zone_path = backend::path(zone, COREDNS);
        let mut found = false;
        let mut services = Vec::new();
        let mut endpoints: Option<Vec<Arc<object::Endpoints>>> = None;

        for svc in api.svc_index(&idx) {
            if !svc.namespace.eq_ignore_ascii_case(&r.namespace) || !svc.name.eq_ignore_ascii_case(&r.service) {
                continue;
            }
            if self.ignore_empty_service && !svc.is_external_name() && !svc.headless() {
                let pods: usize = api
                    .ep_index(&idx)
                    .iter()
                    .flat_map(|e| &e.subsets)
                    .map(|s| s.addresses.len())
                    .sum();
                if pods == 0 {
                    continue;
                }
            }
            // zone-scoped names exist for headless services only
            if !r.zone.is_empty() && !svc.headless() {
                continue;
            }
            if svc.is_external_name() {
                if !r.endpoint.is_empty() || !r.port.is_empty() || !r.protocol.is_empty() {
                    continue;
                }
                let s = Service {
                    key: format!("{zone_path}/{SVC}/{}/{}", svc.namespace, svc.name),
                    host: svc.external_name.clone(),
                    ttl: self.ttl,
                    ..Default::default()
                };
                if s.host_type() == backend::HostType::Cname {
                    services.push(s);
                    found = true;
                }
                continue;
            }
            if svc.headless() || !r.endpoint.is_empty() {
                if !r.zone.is_empty() {
                    // the name exists: no endpoints in the zone is NODATA
                    found = true;
                }
                let eps = endpoints.get_or_insert_with(|| api.ep_index(&idx));
                let mut add_for_zone = |topo_zone: &str| {
                    let mut added = 0;
                    for ep in eps.iter() {
                        if object::Service::key(&svc.name, &svc.namespace) != ep.index {
                            continue;
                        }
                        for sub in &ep.subsets {
                            for addr in &sub.addresses {
                                if !topo_zone.is_empty()
                                    && ep.zones.get(&addr.ip).map(String::as_str) != Some(topo_zone)
                                {
                                    continue;
                                }
                                let hostname = self.endpoint_hostname(addr);
                                if !r.endpoint.is_empty() && !r.endpoint.eq_ignore_ascii_case(&hostname) {
                                    continue;
                                }
                                for p in &sub.ports {
                                    if !match_port_and_protocol(&r.port, &p.name, &r.protocol, &p.protocol) {
                                        continue;
                                    }
                                    services.push(Service {
                                        host: addr.ip.clone(),
                                        port: p.port,
                                        ttl: self.ttl,
                                        key: format!("{zone_path}/{SVC}/{}/{}/{hostname}", svc.namespace, svc.name),
                                        ..Default::default()
                                    });
                                    found = true;
                                    added += 1;
                                }
                            }
                        }
                    }
                    added
                };
                // `prefer` falls back to the whole service
                if add_for_zone(&r.zone) == 0 && r.zone_prefer {
                    add_for_zone("");
                }
                continue;
            }
            for p in &svc.ports {
                if !match_port_and_protocol(&r.port, &p.name, &r.protocol, &p.protocol) {
                    continue;
                }
                found = true;
                for ip in &svc.cluster_ips {
                    services.push(Service {
                        host: ip.clone(),
                        port: p.port,
                        ttl: self.ttl,
                        key: format!("{zone_path}/{SVC}/{}/{}", svc.namespace, svc.name),
                        ..Default::default()
                    });
                }
            }
        }
        if found { Ok(services) } else { Err(Error::NoItems) }
    }

    /// `findMultiClusterServices`: like [`Self::find_services`] from
    /// ServiceImports and multicluster EndpointSlices.
    fn find_multicluster_services(&self, r: &RecordRequest, zone: &str) -> Result<Vec<Service>, Error> {
        if !self.namespace_exposed(&r.namespace) {
            return Err(Error::NoItems);
        }
        if r.service.is_empty() {
            return Ok(Vec::new());
        }
        let Some(api) = self.api() else {
            return Err(Error::NoItems);
        };
        let idx = object::Service::key(&r.service, &r.namespace);
        let zone_path = backend::path(zone, COREDNS);
        let mut found = false;
        let mut services = Vec::new();
        let mut endpoints: Option<Vec<Arc<object::MultiClusterEndpoints>>> = None;

        for svc in api.svc_import_index(&idx) {
            if !svc.namespace.eq_ignore_ascii_case(&r.namespace) || !svc.name.eq_ignore_ascii_case(&r.service) {
                continue;
            }
            if self.ignore_empty_service && !svc.headless() {
                let pods: usize = api
                    .mc_ep_index(&idx)
                    .iter()
                    .flat_map(|e| &e.endpoints.subsets)
                    .map(|s| s.addresses.len())
                    .sum();
                if pods == 0 {
                    continue;
                }
            }
            if svc.headless() || !r.endpoint.is_empty() {
                let eps = endpoints.get_or_insert_with(|| api.mc_ep_index(&idx));
                for ep in eps.iter() {
                    if object::Service::key(&svc.name, &svc.namespace) != ep.endpoints.index {
                        continue;
                    }
                    for sub in &ep.endpoints.subsets {
                        for addr in &sub.addresses {
                            let hostname = self.endpoint_hostname(addr);
                            if !r.endpoint.is_empty()
                                && (!r.cluster.eq_ignore_ascii_case(&ep.cluster_id)
                                    || !r.endpoint.eq_ignore_ascii_case(&hostname))
                            {
                                continue;
                            }
                            for p in &sub.ports {
                                if !match_port_and_protocol(&r.port, &p.name, &r.protocol, &p.protocol) {
                                    continue;
                                }
                                services.push(Service {
                                    host: addr.ip.clone(),
                                    port: p.port,
                                    ttl: self.ttl,
                                    key: format!(
                                        "{zone_path}/{SVC}/{}/{}/{}/{hostname}",
                                        svc.namespace, svc.name, ep.cluster_id
                                    ),
                                    ..Default::default()
                                });
                                found = true;
                            }
                        }
                    }
                }
                continue;
            }
            for p in &svc.ports {
                if !match_port_and_protocol(&r.port, &p.name, &r.protocol, &p.protocol) {
                    continue;
                }
                found = true;
                for ip in &svc.cluster_ips {
                    services.push(Service {
                        host: ip.clone(),
                        port: p.port,
                        ttl: self.ttl,
                        key: format!("{zone_path}/{SVC}/{}/{}", svc.namespace, svc.name),
                        ..Default::default()
                    });
                }
            }
        }
        if found { Ok(services) } else { Err(Error::NoItems) }
    }

    /// `Records`.
    fn records_for(&self, st: &State) -> Result<Vec<Service>, Error> {
        let multicluster = self.is_multicluster_zone(&st.zone);
        let r = parse_request(st.name_ref(), &st.zone, multicluster, self.zonal)?;
        if r.pod_or_svc.is_empty() {
            return Ok(Vec::new());
        }
        if is_reverse(st.name_ref()) {
            return Err(Error::NoItems);
        }
        if !self.namespace_exposed(&r.namespace) {
            return Err(Error::NsNotExposed);
        }
        if r.pod_or_svc == POD {
            self.find_pods(&r, &st.zone)
        } else if !multicluster {
            self.find_services(&r, &st.zone)
        } else {
            self.find_multicluster_services(&r, &st.zone)
        }
    }

    /// `nsAddrs`: the addresses this server is reachable at, as A/AAAA
    /// records named after the service fronting it (or `ns.dns.<zone>`).
    fn ns_addrs(&self, zone: &str) -> Vec<(String, IpAddr)> {
        self.ns_addrs_ext(false, false, zone)
    }

    /// `nsAddrs(external, headless, zone)`.
    pub fn ns_addrs_ext(&self, external: bool, headless: bool, zone: &str) -> Vec<(String, IpAddr)> {
        let local = self.local_ips.read().unwrap().clone();
        let mut out = Vec::new();
        let mut found = false;
        if let Some(api) = self.api() {
            for ip in &local {
                for ep in api.ep_index_reverse(&ip.to_string()) {
                    found = true;
                    for svc in api.svc_index(&ep.index) {
                        if external {
                            let name = format!("{}.{}.{zone}", svc.name, svc.namespace);
                            if headless && svc.headless() {
                                for sub in &ep.subsets {
                                    for a in &sub.addresses {
                                        if let Some(ip) = backend::parse_ip(&a.ip) {
                                            out.push((format!("{}.{name}", self.endpoint_hostname(a)), ip));
                                        }
                                    }
                                }
                            } else {
                                for x in &svc.external_ips {
                                    if let Some(ip) = backend::parse_ip(x) {
                                        out.push((name.clone(), ip));
                                    }
                                }
                            }
                            continue;
                        }
                        let name = format!("{}.{}.{SVC}.{zone}", svc.name, svc.namespace);
                        if svc.headless() {
                            for sub in &ep.subsets {
                                for a in &sub.addresses {
                                    if let Some(ip) = backend::parse_ip(&a.ip) {
                                        out.push((format!("{}.{name}", self.endpoint_hostname(a)), ip));
                                    }
                                }
                            }
                        } else {
                            for cip in &svc.cluster_ips {
                                if let Some(ip) = backend::parse_ip(cip) {
                                    out.push((name.clone(), ip));
                                }
                            }
                        }
                    }
                }
            }
        }
        if !found {
            out = local
                .iter()
                .map(|ip| (format!("{DEFAULT_NS_NAME}{zone}"), *ip))
                .collect();
        }
        out
    }

    /// `serviceRecordForIP`.
    fn service_record_for_ip(&self, ip: &str) -> Vec<Service> {
        let Some(api) = self.api() else { return Vec::new() };
        for svc in api.svc_index_reverse(ip) {
            if !self.namespaces.is_empty() && !self.namespace_exposed(&svc.namespace) {
                continue;
            }
            let domain = format!("{}.{}.{SVC}.{}", svc.name, svc.namespace, self.primary_zone());
            return vec![Service {
                host: domain,
                ttl: self.ttl,
                ..Default::default()
            }];
        }
        let mut out = Vec::new();
        for ep in api.ep_index_reverse(ip) {
            if !self.namespaces.is_empty() && !self.namespace_exposed(&ep.namespace) {
                continue;
            }
            for sub in &ep.subsets {
                for a in &sub.addresses {
                    if a.ip == ip {
                        let domain = format!(
                            "{}.{}.{SVC}.{}",
                            self.endpoint_hostname(a),
                            ep.index,
                            self.primary_zone()
                        );
                        out.push(Service {
                            host: domain,
                            ttl: self.ttl,
                            ..Default::default()
                        });
                    }
                }
            }
        }
        out
    }
}

/// `endpointHostname`: the endpoint's hostname, its pod name, or its address with dashes.
pub fn endpoint_hostname(addr: &object::EndpointAddress, endpoint_name_mode: bool) -> String {
    if !addr.hostname.is_empty() {
        return addr.hostname.clone();
    }
    if endpoint_name_mode && !addr.target_ref_name.is_empty() {
        return addr.target_ref_name.clone();
    }
    if addr.ip.contains('.') {
        return addr.ip.replace('.', "-");
    }
    if addr.ip.contains(':') {
        let h = addr.ip.replace(':', "-");
        return if h.ends_with('-') { format!("{h}0") } else { h };
    }
    String::new()
}

fn match_port_and_protocol(a_port: &str, b_port: &str, a_proto: &str, b_proto: &str) -> bool {
    (a_port.is_empty() || a_port.eq_ignore_ascii_case(b_port))
        && (a_proto.is_empty() || a_proto.eq_ignore_ascii_case(b_proto))
}

/// A reverse zone name (`dnsutil.IsReverse` > 0).
fn is_reverse(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("in-addr.arpa.") || n.ends_with("ip6.arpa.")
}

/// `isDefaultNS`: `ns.dns.<zone>`.
fn is_default_ns(name: &str, zone: &str) -> bool {
    name.starts_with(DEFAULT_NS_NAME) && name[DEFAULT_NS_NAME.len()..].eq_ignore_ascii_case(zone)
}

#[async_trait]
impl ServiceBackend for Kubernetes {
    async fn services(&self, _ctx: &Context, st: &State, _exact: bool, _opt: Options) -> BackendResult<Vec<Service>> {
        match st.qtype() {
            RecordType::TXT => {
                let t = trim_zone(&st.name(), &st.zone).unwrap_or_default();
                if t == "dns-version" {
                    return Ok(vec![Service {
                        text: DNS_SCHEMA_VERSION.into(),
                        ttl: 28800,
                        key: backend::path(&st.qname(), COREDNS),
                        ..Default::default()
                    }]);
                }
                let services = self.records_for(st);
                return match services {
                    Ok(s) if !s.is_empty() => Ok(Vec::new()),
                    // a zone-scoped name that exists but is empty is NODATA
                    // for every type
                    Ok(_)
                        if self.zonal
                            && parse_request(st.name_ref(), &st.zone, self.is_multicluster_zone(&st.zone), true)
                                .is_ok_and(|r| !r.zone.is_empty()) =>
                    {
                        Ok(Vec::new())
                    }
                    _ => Err(Error::NoItems.into()),
                };
            }
            RecordType::NS => {
                return Ok(self
                    .ns_addrs(&st.zone)
                    .into_iter()
                    .map(|(n, ip)| Service {
                        host: ip.to_string(),
                        key: backend::path(&n, COREDNS),
                        ttl: self.ttl,
                        ..Default::default()
                    })
                    .collect());
            }
            _ => {}
        }
        if is_default_ns(&st.name(), &st.zone) {
            let want_v6 = st.qtype() == RecordType::AAAA;
            return Ok(self
                .ns_addrs(&st.zone)
                .into_iter()
                .filter(|(_, ip)| (st.qtype() == RecordType::A && ip.is_ipv4()) || (want_v6 && ip.is_ipv6()))
                .map(|(_, ip)| Service {
                    host: ip.to_string(),
                    key: backend::path(&st.qname(), COREDNS),
                    ttl: self.ttl,
                    ..Default::default()
                })
                .collect());
        }
        let s = self.records_for(st).map_err(BackendError::from)?;
        if st.qtype() != RecordType::SRV {
            return Ok(s);
        }
        Ok(s.into_iter()
            .filter(|x| x.host_type() != backend::HostType::Cname)
            .collect())
    }

    async fn reverse(&self, ctx: &Context, st: &State, exact: bool, _opt: Options) -> BackendResult<Vec<Service>> {
        let Some(ip) = extract_address_from_reverse(&st.name()) else {
            return self.records(ctx, st, exact).await.map(|_| Vec::new());
        };
        let r = self.service_record_for_ip(&ip.to_string());
        if r.is_empty() {
            Err(Error::NoItems.into())
        } else {
            Ok(r)
        }
    }

    async fn lookup(&self, ctx: &Context, st: &State, name: &str, qtype: RecordType) -> Option<Message> {
        if let Some(f) = &self.upstream_override {
            return f(&name.to_ascii_lowercase(), qtype);
        }
        let n = kerndns_core::proto::rr::Name::from_ascii(name).ok()?;
        kerndns_core::upstream::lookup(ctx, &st.req, &n, qtype)
            .await
            .ok()
            .flatten()
    }

    async fn records(&self, _ctx: &Context, st: &State, _exact: bool) -> BackendResult<Vec<Service>> {
        self.records_for(st).map_err(Into::into)
    }

    fn serial(&self, st: &State) -> u32 {
        let multicluster = self.is_multicluster_zone(&st.zone);
        self.api()
            .map(|a| {
                if multicluster {
                    a.modified_multicluster() as u32
                } else {
                    a.modified() as u32
                }
            })
            .unwrap_or(0)
    }

    fn min_ttl(&self, _st: &State) -> u32 {
        self.ttl
    }
}

/// The handler.
pub struct KubernetesHandler {
    pub k: Arc<Kubernetes>,
    pub next: Next,
}

#[async_trait]
impl Handler for KubernetesHandler {
    fn name(&self) -> &'static str {
        "kubernetes"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let k = &*self.k;
        let qname = req.qname().to_ascii();
        let Some(zone) = zones::matches(&k.zones, &qname.to_ascii_lowercase()) else {
            return next_or_failure("kubernetes", &self.next, ctx, w, req).await;
        };
        // keep the case of the query
        let zone = if zone == "." {
            ".".to_string()
        } else {
            qname[qname.len() - zone.len()..].to_string()
        };
        let st = State::new(req.clone(), zone.clone());
        let opt = Options::default();
        let b: &dyn ServiceBackend = k;

        let mut truncated = false;
        let mut extra = Vec::new();
        let result: BackendResult<Vec<Record>> = match req.qtype() {
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
            RecordType::SOA => {
                if qname == zone {
                    Ok(backend::soa(b, &zone, &st))
                } else {
                    Ok(Vec::new())
                }
            }
            RecordType::AXFR | RecordType::IXFR => return Ok(ResponseCode::Refused),
            RecordType::NS if st.name() == zone.to_ascii_lowercase() => {
                backend::ns(b, ctx, &zone, &st, opt).await.map(|(r, x)| {
                    extra = x;
                    r
                })
            }
            _ => {
                // other types: NODATA if the name exists, NXDOMAIN if not
                let fake = st.with_question(&qname, RecordType::A);
                backend::a(b, ctx, &zone, &fake, opt).await.map(|_| Vec::new())
            }
        };

        let records = match result {
            Err(BackendError::NameError(_)) => {
                if k.fall.through(&st.name()) {
                    return next_or_failure("kubernetes", &self.next, ctx, w, req).await;
                }
                let rcode = if k.has_synced() {
                    ResponseCode::NXDomain
                } else {
                    ResponseCode::ServFail
                };
                return backend::backend_error(b, &zone, rcode, &st, w, "kubernetes").await;
            }
            Err(BackendError::Other(e)) => return Err(PluginError::servfail("kubernetes", e)),
            Ok(r) => r,
        };
        if records.is_empty() {
            return backend::backend_error(b, &zone, ResponseCode::NoError, &st, w, "kubernetes").await;
        }
        let mut m = req.reply();
        m.metadata.truncation = truncated;
        m.metadata.authoritative = true;
        m.answers = records;
        m.additionals = extra;
        w.write_msg(m)
            .await
            .map_err(|e| PluginError::servfail("kubernetes", e.to_string()))?;
        Ok(ResponseCode::NoError)
    }
}

/// Non-loopback addresses to report as the server's own (`boundIPs`).
fn bound_ips(listen_hosts: &[String]) -> Vec<IpAddr> {
    let hosts: Vec<IpAddr> = if listen_hosts.is_empty() || listen_hosts[0].is_empty() {
        if_addrs::get_if_addrs()
            .map(|v| v.into_iter().map(|i| i.ip()).collect())
            .unwrap_or_default()
    } else {
        listen_hosts.iter().filter_map(|h| h.parse().ok()).collect()
    };
    hosts.into_iter().filter(|ip| !ip.is_loopback()).collect()
}

/// The `kubernetes/*` metadata (`Kubernetes.Metadata`).
pub struct KubernetesMetadata(pub Arc<Kubernetes>);

impl MetadataProvider for KubernetesMetadata {
    fn metadata(&self, ctx: &mut Context, req: &Request) {
        let k = &self.0;
        let md = &mut ctx.metadata;
        if let Some(pod) = k.pod_with_ip(&req.ip().to_string()) {
            md.insert("kubernetes/client-namespace".into(), pod.namespace.clone());
            md.insert("kubernetes/client-pod-name".into(), pod.name.clone());
            for (l, v) in &pod.labels {
                md.insert(format!("kubernetes/client-label/{l}"), v.clone());
            }
        }
        let name = req.name();
        let Some(zone) = zones::matches(&k.zones, &name) else {
            return;
        };
        // CoreDNS checks the multicluster zones against the request's zone,
        // which the server leaves empty when it collects metadata: names in
        // multicluster zones are parsed as plain cluster names
        let multicluster = false;
        let r = match parse_request(&name, zone, multicluster, k.zonal) {
            Ok(r) => r,
            Err(e) => {
                md.insert("kubernetes/parse-error".into(), e.message().into());
                return;
            }
        };
        md.insert("kubernetes/port-name".into(), r.port);
        md.insert("kubernetes/protocol".into(), r.protocol);
        md.insert("kubernetes/endpoint".into(), r.endpoint);
        if k.zonal {
            md.insert("kubernetes/zone".into(), r.zone);
        }
        md.insert("kubernetes/service".into(), r.service);
        md.insert("kubernetes/namespace".into(), r.namespace);
        md.insert("kubernetes/kind".into(), r.pod_or_svc);
    }
}

pub struct Setup;

/// Settings that only matter for connecting to the API.
#[derive(Default)]
struct ClientSettings {
    endpoint: Option<String>,
    tls: Option<(String, String, String)>,
    kubeconfig: Option<(String, Option<String>)>,
    startup_timeout: Option<Duration>,
    opts: controller::Options,
}

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "kubernetes"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let err = |m: String| SetupError::new("kubernetes", m);
        let mut k: Option<Kubernetes> = None;
        let mut cs = ClientSettings {
            opts: controller::Options {
                watch_endpoints: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let server_keys = c.server_block_keys();
        while c.next() {
            if k.is_some() {
                return Err(err("this plugin can only be used once per Server Block".into()));
            }
            let args = c.remaining_args();
            let zones = zones::origins_from_args_or_server_block(&args, &server_keys);
            if zones.iter().all(|z| is_reverse(z)) {
                return Err(err("non-reverse zone name must be used".into()));
            }
            let mut kk = Kubernetes::new(zones);
            kk.auto_path_search = autopath::search_from_resolv_conf();
            while c.next_block() {
                let opt = c.val().to_string();
                let a = c.remaining_args();
                match opt.as_str() {
                    "endpoint_pod_names" => {
                        if !a.is_empty() {
                            return Err(c.arg_err());
                        }
                        kk.endpoint_name_mode = true;
                    }
                    "pods" => {
                        kk.pod_mode = match a.as_slice() {
                            [m] if m == "disabled" => PodMode::Disabled,
                            [m] if m == "insecure" => PodMode::Insecure,
                            [m] if m == "verified" => PodMode::Verified,
                            [m] => {
                                return Err(err(format!(
                                    "wrong value for pods: {m},  must be one of: disabled, verified, insecure"
                                )));
                            }
                            _ => return Err(c.arg_err()),
                        };
                    }
                    "namespaces" => {
                        if a.is_empty() {
                            return Err(c.arg_err());
                        }
                        kk.namespaces.extend(a);
                    }
                    "endpoint" => {
                        let Some(e) = a.first() else { return Err(c.arg_err()) };
                        if a.len() > 1 {
                            kerndns_core::warning!(
                                plugin = "kubernetes",
                                "Multiple endpoints have been deprecated, only the first specified endpoint '{e}' is used"
                            );
                        }
                        cs.endpoint = Some(e.clone());
                    }
                    "tls" => match a.as_slice() {
                        [cert, key, ca] => cs.tls = Some((cert.clone(), key.clone(), ca.clone())),
                        _ => return Err(c.arg_err()),
                    },
                    "labels" | "namespace_labels" => {
                        if a.is_empty() {
                            return Err(c.arg_err());
                        }
                        let sel = a.join(" ");
                        if opt == "labels" {
                            cs.opts.label_selector = Some(sel);
                        } else {
                            cs.opts.namespace_label_selector = Some(sel);
                        }
                    }
                    "fallthrough" => kk.fall.set_zones_from_args(&a),
                    "ttl" => {
                        let Some(t) = a.first() else { return Err(c.arg_err()) };
                        let t: i64 = t
                            .parse()
                            .map_err(|e| err(format!("strconv.Atoi: parsing {t:?}: {e}")))?;
                        if !(0..=3600).contains(&t) {
                            return Err(c.errf(format!("ttl must be in range [0, 3600]: {t}")));
                        }
                        kk.ttl = t as u32;
                    }
                    "noendpoints" => {
                        if !a.is_empty() {
                            return Err(c.arg_err());
                        }
                        cs.opts.watch_endpoints = false;
                    }
                    "ignore" => match a.first().map(String::as_str) {
                        Some("empty_service") => kk.ignore_empty_service = true,
                        Some(other) => return Err(err(format!("unable to parse ignore value: '{other}'"))),
                        None => {}
                    },
                    "kubeconfig" => match a.as_slice() {
                        [path] => cs.kubeconfig = Some((path.clone(), None)),
                        [path, ctx] => cs.kubeconfig = Some((path.clone(), Some(ctx.clone()))),
                        _ => return Err(c.arg_err()),
                    },
                    "startup_timeout" => {
                        let Some(d) = a.first() else { return Err(c.arg_err()) };
                        cs.startup_timeout = Some(
                            parse_duration(d).map_err(|e| err(format!("failed to parse startup_timeout: {d}, {e}")))?,
                        );
                    }
                    "zonal" => {
                        if !a.is_empty() {
                            return Err(c.arg_err());
                        }
                        kk.zonal = true;
                    }
                    "multicluster" => kk.multicluster_zones = zones::origins_from_args_or_server_block(&a, &[]),
                    "apiserver_qps" => {
                        let [q] = a.as_slice() else { return Err(c.arg_err()) };
                        let qps: f32 = q.parse().map_err(|_| {
                            c.errf(format!(
                                "invalid apiserver_qps {q:?}: strconv.ParseFloat: parsing {q:?}: invalid syntax"
                            ))
                        })?;
                        if qps < 0.0 {
                            return Err(c.errf("apiserver_qps must be >= 0"));
                        }
                        cs.opts.limits.qps = qps;
                    }
                    "apiserver_burst" | "apiserver_max_inflight" => {
                        let [n] = a.as_slice() else { return Err(c.arg_err()) };
                        let v: i64 = n.parse().map_err(|_| {
                            c.errf(format!(
                                "invalid {opt} {n:?}: strconv.Atoi: parsing {n:?}: invalid syntax"
                            ))
                        })?;
                        if v < 0 {
                            return Err(c.errf(format!("{opt} must be >= 0")));
                        }
                        if opt == "apiserver_burst" {
                            cs.opts.limits.burst = v as usize;
                        } else {
                            cs.opts.limits.max_inflight = v as usize;
                        }
                    }
                    other => {
                        let msg = format!("unknown property '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
            if !kk.namespaces.is_empty() && cs.opts.namespace_label_selector.is_some() {
                return Err(c.errf("namespaces and namespace_labels cannot both be set"));
            }
            for z in &kk.multicluster_zones {
                if !kk.zones.contains(z) {
                    let msg = format!(
                        "is not authoritative for the multicluster zone {z} (authoritative zones: [{}])",
                        kk.zones.join(" ")
                    );
                    return Err(c.errf(msg));
                }
            }
            if kk.zonal && !cs.opts.watch_endpoints {
                return Err(c.errf("zonal requires the endpoint cache; remove noendpoints"));
            }
            k = Some(kk);
        }
        let Some(k) = k else { return Err(c.arg_err()) };
        cs.opts.watch_pods = k.pod_mode == PodMode::Verified;
        cs.opts.zonal = k.zonal;
        cs.opts.multicluster = !k.multicluster_zones.is_empty();
        metrics::init();
        let k = Arc::new(k);
        // k8s_external (set up earlier in the block) reads it from here
        external::slot(c.config).set(k.clone());
        // autopath @kubernetes (set up earlier in the block) finds it here
        kerndns_plugins::autopath::AutoPathers::of(c.config).register("kubernetes", k.clone());
        // zone transfers through `transfer`
        TransferRegistry::of(c.config).add_source(Arc::new(xfr::KubeTransfer(k.clone())));
        // kubernetes/* metadata for `metadata`
        Metadata::of(c.config).add_provider(Arc::new(KubernetesMetadata(k.clone())));

        let listen_hosts = c.config.listen_hosts.clone();
        let tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::default();
        let (k2, t2) = (k.clone(), tasks.clone());
        c.on_startup(move || {
            *k2.local_ips.write().unwrap() = bound_ips(&listen_hosts);
            // connecting is async; startup hooks run inside the runtime
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(start_api(&k2, cs, &t2)))
        });
        c.on_shutdown(move || {
            for t in tasks.lock().unwrap().drain(..) {
                t.abort();
            }
        });
        let k3 = k.clone();
        kerndns_core::readiness::register("kubernetes", move || k3.has_synced());
        c.add_plugin(move |next| Arc::new(KubernetesHandler { k: k.clone(), next }));
        Ok(())
    }
}

/// Build the client, start the watchers and wait for the first sync (up to
/// `startup_timeout`, default 5s), like `InitKubeCache` + `onStart`.
async fn start_api(
    k: &Arc<Kubernetes>,
    cs: ClientSettings,
    tasks: &Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
) -> Result<(), String> {
    let config = client_config(&cs).await?;
    let host = config
        .cluster_url
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let client = kube::client::ClientBuilder::try_from(config)
        .map_err(|e| format!("failed to create kubernetes notification controller: {e}"))?
        .with_layer(&client::ClientLayer::new(cs.opts.limits, &host))
        .build();
    let ctl = KubeController::new(cs.opts.clone());
    tasks.lock().unwrap().extend(ctl.run(client));
    k.set_api(ctl.clone());

    let timeout = cs.startup_timeout.unwrap_or(Duration::from_secs(5));
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_log = tokio::time::Instant::now();
    while !ctl.has_synced() {
        if tokio::time::Instant::now() >= deadline {
            kerndns_core::warning!(plugin = "kubernetes", "starting server with unsynced Kubernetes API");
            return Ok(());
        }
        if last_log.elapsed() >= Duration::from_millis(500) {
            kerndns_core::info!(
                plugin = "kubernetes",
                "waiting for Kubernetes API before starting server"
            );
            last_log = tokio::time::Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

async fn client_config(cs: &ClientSettings) -> Result<kube::Config, String> {
    use kube::config::{KubeConfigOptions, Kubeconfig};
    if let Some((path, context)) = &cs.kubeconfig {
        let kc = Kubeconfig::read_from(path).map_err(|e| e.to_string())?;
        let opts = KubeConfigOptions {
            context: context.clone(),
            ..Default::default()
        };
        return kube::Config::from_custom_kubeconfig(kc, &opts)
            .await
            .map_err(|e| e.to_string());
    }
    let Some(endpoint) = &cs.endpoint else {
        // in-cluster, like rest.InClusterConfig
        return kube::Config::incluster().map_err(|e| e.to_string());
    };
    let uri = endpoint
        .parse()
        .map_err(|e| format!("invalid endpoint {endpoint}: {e}"))?;
    let mut config = kube::Config::new(uri);
    if let Some((cert, key, ca)) = &cs.tls {
        config.root_cert_file = Some(ca.into());
        config.auth_info.client_certificate = Some(cert.clone());
        config.auth_info.client_key = Some(key.clone());
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerndns_core::corefile::{Dispenser, parse};
    use kerndns_core::{BlockConfig, Hooks, ZoneAddr};

    /// Run the setup of `kubernetes` in `.:53 { ... }`; the parsed plugin
    /// or the error.
    fn setup(directive: &str) -> Result<Arc<Kubernetes>, String> {
        let blocks = parse(&format!(".:53 {{\n{directive}\n}}"), "Corefile").expect("parses");
        let mut cfg = BlockConfig::new(ZoneAddr::parse(".:53", "53").unwrap());
        let mut hooks = Hooks::default();
        let res = {
            let mut c = Controller::new(
                "kubernetes",
                Dispenser::new(blocks[0].tokens_for("kubernetes")),
                &mut cfg,
                &mut hooks,
                ".".into(),
            );
            Setup.setup(&mut c).map_err(|e| e.to_string())
        };
        res.map(|_| external::slot(&mut cfg).get().cloned().expect("set up"))
    }

    /// setup_test.go TestKubernetesParseMulticluster.
    #[test]
    fn parse_multicluster() {
        let k = setup("kubernetes coredns.local clusterset.local {\n multicluster clusterset.local\n}").unwrap();
        assert_eq!(k.multicluster_zones, ["clusterset.local."]);
        let e = setup("kubernetes coredns.local {\n multicluster clusterset.local\n}")
            .err()
            .unwrap();
        assert!(
            e.contains("Error during parsing: is not authoritative for the multicluster zone clusterset.local."),
            "{e}"
        );
        let e = setup("kubernetes coredns.local clusterset.local {\n multicluster clusterset.local test.local\n}")
            .err()
            .unwrap();
        assert!(
            e.contains("is not authoritative for the multicluster zone test.local."),
            "{e}"
        );
        let k = setup("kubernetes coredns.local {\n multicluster\n}").unwrap();
        assert!(k.multicluster_zones.is_empty());
    }

    /// setup_test.go TestKubernetesParseAPIRateLimiting.
    #[test]
    fn parse_api_limits() {
        assert!(
            setup(
                "kubernetes coredns.local {\n apiserver_qps 50.0\n apiserver_burst 100\n apiserver_max_inflight 25\n}"
            )
            .is_ok()
        );
        for (opt, err) in [
            ("apiserver_qps -10", "apiserver_qps must be >= 0"),
            ("apiserver_burst -5", "apiserver_burst must be >= 0"),
            ("apiserver_max_inflight -1", "apiserver_max_inflight must be >= 0"),
            ("apiserver_qps fast", "invalid apiserver_qps \"fast\""),
            ("apiserver_burst", "Wrong argument count"),
        ] {
            let e = setup(&format!("kubernetes coredns.local {{\n {opt}\n}}"))
                .err()
                .unwrap();
            assert!(e.contains(err), "{opt}: {e}");
        }
    }

    /// setup_test.go TestKubernetesParseZonal.
    #[test]
    fn parse_zonal() {
        assert!(setup("kubernetes coredns.local {\n zonal\n}").unwrap().zonal);
        assert!(setup("kubernetes coredns.local {\n zonal us-west-2a\n}").is_err());
        let e = setup("kubernetes coredns.local {\n zonal\n noendpoints\n}")
            .err()
            .unwrap();
        assert!(
            e.contains("zonal requires the endpoint cache; remove noendpoints"),
            "{e}"
        );
        assert!(!setup("kubernetes coredns.local").unwrap().zonal);
    }
}
