//! The Kubernetes API side: watches Services, EndpointSlices, Namespaces,
//! (with `pods verified`) Pods and (with `multicluster`) ServiceImports and
//! multicluster EndpointSlices, converts every object to the minimal
//! form in [`crate::object`] and keeps the indexes the plugin queries. A
//! port of `plugin/kubernetes/controller.go` built on kube-rs watchers.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, RwLock};

use futures_util::StreamExt;
use k8s_openapi::api::core::v1 as core;
use k8s_openapi::api::discovery::v1 as discovery;
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};

use crate::object::{Endpoints, MultiClusterEndpoints, Pod, Service, ServiceImport, convert};

/// What the plugin needs from the API (`dnsController`).
pub trait DnsController: Send + Sync {
    /// Services by `name.namespace`.
    fn svc_index(&self, idx: &str) -> Vec<Arc<Service>>;
    /// Services with this cluster IP.
    fn svc_index_reverse(&self, ip: &str) -> Vec<Arc<Service>>;
    /// Services with this external IP.
    fn svc_ext_index_reverse(&self, ip: &str) -> Vec<Arc<Service>>;
    fn pod_index(&self, ip: &str) -> Vec<Arc<Pod>>;
    /// EndpointSlices of the service `name.namespace`.
    fn ep_index(&self, idx: &str) -> Vec<Arc<Endpoints>>;
    /// EndpointSlices containing this address.
    fn ep_index_reverse(&self, ip: &str) -> Vec<Arc<Endpoints>>;
    fn namespace_exists(&self, name: &str) -> bool;
    fn has_synced(&self) -> bool;
    /// Unix time of the last DNS-relevant change (the SOA serial).
    fn modified(&self) -> i64;
    /// Unix time of the last change to services' external IPs or ports
    /// (`ModifiedExternal`, the `k8s_external` SOA serial).
    fn modified_external(&self) -> i64 {
        self.modified()
    }
    /// Unix time of the last change to multicluster services
    /// (`ModifiedMultiCluster`, the SOA serial of `multicluster` zones).
    fn modified_multicluster(&self) -> i64 {
        self.modified()
    }
    fn service_list(&self) -> Vec<Arc<Service>>;
    fn endpoints_list(&self) -> Vec<Arc<Endpoints>>;
    /// ServiceImports by `name.namespace` (`multicluster`).
    fn svc_import_index(&self, _idx: &str) -> Vec<Arc<ServiceImport>> {
        Vec::new()
    }
    fn service_import_list(&self) -> Vec<Arc<ServiceImport>> {
        Vec::new()
    }
    /// Multicluster EndpointSlices of the ServiceImport `name.namespace`.
    fn mc_ep_index(&self, _idx: &str) -> Vec<Arc<MultiClusterEndpoints>> {
        Vec::new()
    }
}

/// Objects keyed by `namespace/name`, with secondary indexes. The key is
/// allocated once and shared by `objs` and every index entry.
struct Index<T> {
    objs: HashMap<Arc<str>, Arc<T>>,
    by: HashMap<Box<str>, Vec<Arc<str>>>,
    by_ip: HashMap<Box<str>, Vec<Arc<str>>>,
    by_ip2: HashMap<Box<str>, Vec<Arc<str>>>,
}

impl<T> Default for Index<T> {
    fn default() -> Self {
        Self {
            objs: HashMap::new(),
            by: HashMap::new(),
            by_ip: HashMap::new(),
            by_ip2: HashMap::new(),
        }
    }
}

fn add_key(m: &mut HashMap<Box<str>, Vec<Arc<str>>>, k: &str, v: &Arc<str>) {
    let e = match m.get_mut(k) {
        Some(e) => e,
        None => m.entry(Box::from(k)).or_default(),
    };
    if !e.iter().any(|x| x == v) {
        e.push(v.clone());
    }
}

fn remove_key(m: &mut HashMap<Box<str>, Vec<Arc<str>>>, k: &str, v: &str) {
    if let Some(e) = m.get_mut(k) {
        e.retain(|x| &**x != v);
        if e.is_empty() {
            m.remove(k);
        }
    }
}

/// How an object contributes to the indexes.
trait Indexed {
    fn index_key(&self) -> Option<String>;
    fn ips(&self) -> Vec<String>;
    fn ips2(&self) -> Vec<String> {
        Vec::new()
    }
}

impl Indexed for Service {
    fn index_key(&self) -> Option<String> {
        Some(self.index.clone())
    }
    fn ips(&self) -> Vec<String> {
        self.cluster_ips.clone()
    }
    fn ips2(&self) -> Vec<String> {
        self.external_ips.clone()
    }
}

impl Indexed for Endpoints {
    fn index_key(&self) -> Option<String> {
        Some(self.index.clone())
    }
    fn ips(&self) -> Vec<String> {
        self.index_ip.clone()
    }
}

impl Indexed for ServiceImport {
    fn index_key(&self) -> Option<String> {
        Some(self.index.clone())
    }
    fn ips(&self) -> Vec<String> {
        Vec::new()
    }
}

impl Indexed for MultiClusterEndpoints {
    fn index_key(&self) -> Option<String> {
        Some(self.endpoints.index.clone())
    }
    fn ips(&self) -> Vec<String> {
        Vec::new()
    }
}

impl Indexed for Pod {
    fn index_key(&self) -> Option<String> {
        None
    }
    fn ips(&self) -> Vec<String> {
        self.pod_ips.clone()
    }
}

/// What an event changed, for the SOA serials (`detectChanges`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Change {
    pub internal: bool,
    pub external: bool,
    pub multicluster: bool,
}

impl Change {
    const NONE: Change = Change {
        internal: false,
        external: false,
        multicluster: false,
    };
    const INTERNAL: Change = Change {
        internal: true,
        external: false,
        multicluster: false,
    };
    const MULTICLUSTER: Change = Change {
        internal: false,
        external: false,
        multicluster: true,
    };
}

/// How an update counts for the serials: CoreDNS's `serviceModified`,
/// `endpointsEquivalent` and `podModified`.
pub trait Modified {
    fn modified(old: &Self, new: &Self) -> Change;
}

impl Modified for Service {
    fn modified(old: &Self, new: &Self) -> Change {
        let external = old.external_ips != new.external_ips;
        let internal = old.external_name != new.external_name;
        if internal && external {
            return Change {
                internal,
                external,
                multicluster: false,
            };
        }
        let ports_changed = old.ports.len() != new.ports.len()
            || old
                .ports
                .iter()
                .zip(&new.ports)
                .any(|(a, b)| a.name != b.name || a.port != b.port || a.protocol != b.protocol);
        if ports_changed {
            return Change {
                internal: true,
                external: true,
                multicluster: false,
            };
        }
        Change {
            internal,
            external,
            multicluster: false,
        }
    }
}

fn endpoints_equivalent(old: &Endpoints, new: &Endpoints) -> bool {
    {
        let same_subset = |a: &crate::object::EndpointSubset, b: &crate::object::EndpointSubset| {
            a.addresses.len() == b.addresses.len()
                && a.ports.len() == b.ports.len()
                && a.addresses
                    .iter()
                    .zip(&b.addresses)
                    .all(|(x, y)| x.ip == y.ip && x.hostname == y.hostname)
                && a.ports
                    .iter()
                    .zip(&b.ports)
                    .all(|(x, y)| x.name == y.name && x.port == y.port && x.protocol == y.protocol)
        };
        old.subsets.len() == new.subsets.len()
            && old.zones == new.zones
            && old.subsets.iter().zip(&new.subsets).all(|(a, b)| same_subset(a, b))
    }
}

impl Modified for Endpoints {
    fn modified(old: &Self, new: &Self) -> Change {
        if endpoints_equivalent(old, new) {
            Change::NONE
        } else {
            Change::INTERNAL
        }
    }
}

impl Modified for MultiClusterEndpoints {
    fn modified(old: &Self, new: &Self) -> Change {
        if endpoints_equivalent(&old.endpoints, &new.endpoints) && old.cluster_id == new.cluster_id {
            Change::NONE
        } else {
            Change::MULTICLUSTER
        }
    }
}

impl Modified for ServiceImport {
    fn modified(old: &Self, new: &Self) -> Change {
        let same = old.type_ == new.type_
            && old.ports.len() == new.ports.len()
            && old
                .ports
                .iter()
                .zip(&new.ports)
                .all(|(a, b)| a.name == b.name && a.port == b.port && a.protocol == b.protocol);
        if same { Change::NONE } else { Change::MULTICLUSTER }
    }
}

impl Modified for Pod {
    fn modified(old: &Self, new: &Self) -> Change {
        if old.pod_ips == new.pod_ips {
            Change::NONE
        } else {
            Change::INTERNAL
        }
    }
}

impl<T: Indexed + PartialEq + Modified> Index<T> {
    /// Insert or replace; returns what changed for the serials (an add
    /// changes the internal one).
    fn put(&mut self, key: String, obj: T, add: Change) -> Change {
        let mut change = add;
        if let Some(old) = self.objs.get(key.as_str()) {
            if **old == obj {
                return Change::NONE;
            }
            change = T::modified(old, &obj);
            self.remove(&key);
        }
        let key: Arc<str> = Arc::from(key);
        if let Some(i) = obj.index_key() {
            add_key(&mut self.by, &i, &key);
        }
        for ip in obj.ips() {
            add_key(&mut self.by_ip, &ip, &key);
        }
        for ip in obj.ips2() {
            add_key(&mut self.by_ip2, &ip, &key);
        }
        self.objs.insert(key, Arc::new(obj));
        change
    }

    fn remove(&mut self, key: &str) -> bool {
        let Some(old) = self.objs.remove(key) else { return false };
        if let Some(i) = old.index_key() {
            remove_key(&mut self.by, &i, key);
        }
        for ip in old.ips() {
            remove_key(&mut self.by_ip, &ip, key);
        }
        for ip in old.ips2() {
            remove_key(&mut self.by_ip2, &ip, key);
        }
        true
    }

    fn lookup(&self, m: &HashMap<Box<str>, Vec<Arc<str>>>, k: &str) -> Vec<Arc<T>> {
        m.get(k)
            .map(|keys| keys.iter().filter_map(|key| self.objs.get(&**key).cloned()).collect())
            .unwrap_or_default()
    }
}

#[derive(Default)]
struct State {
    svcs: Index<Service>,
    eps: Index<Endpoints>,
    pods: Index<Pod>,
    namespaces: HashSet<String>,
    imports: Index<ServiceImport>,
    mc_eps: Index<MultiClusterEndpoints>,
}

/// Which resources to watch and how (`dnsControlOpts`).
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub watch_endpoints: bool,
    pub watch_pods: bool,
    /// `labels`: applies to Services, EndpointSlices and Pods.
    pub label_selector: Option<String>,
    /// `namespace_labels`: only these namespaces are exposed.
    pub namespace_label_selector: Option<String>,
    /// `zonal`: keep the endpoints' topology zones.
    pub zonal: bool,
    /// `multicluster`: watch ServiceImports and multicluster EndpointSlices.
    pub multicluster: bool,
    /// The API client's rate and in-flight limits.
    pub limits: crate::client::Limits,
}

/// The kube-rs implementation of [`DnsController`].
pub struct KubeController {
    state: RwLock<State>,
    synced: [AtomicBool; 6],
    modified: AtomicI64,
    ext_modified: AtomicI64,
    mc_modified: AtomicI64,
    opts: Options,
}

const SVC: usize = 0;
const EP: usize = 1;
const POD: usize = 2;
const NS: usize = 3;
const IMPORT: usize = 4;
const MC_EP: usize = 5;

/// Pods that have finished or are unknown are never answered for.
const POD_FIELD_SELECTOR: &str = "status.phase!=Succeeded,status.phase!=Failed,status.phase!=Unknown";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn obj_key(meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta) -> String {
    format!(
        "{}/{}",
        meta.namespace.as_deref().unwrap_or(""),
        meta.name.as_deref().unwrap_or("")
    )
}

impl KubeController {
    pub fn new(opts: Options) -> Arc<Self> {
        let c = Arc::new(Self {
            state: RwLock::new(State::default()),
            synced: Default::default(),
            modified: AtomicI64::new(0),
            ext_modified: AtomicI64::new(0),
            mc_modified: AtomicI64::new(0),
            opts,
        });
        if !c.opts.watch_endpoints {
            c.synced[EP].store(true, Ordering::Relaxed);
        }
        if !c.opts.watch_pods {
            c.synced[POD].store(true, Ordering::Relaxed);
        }
        if !c.opts.multicluster {
            c.synced[IMPORT].store(true, Ordering::Relaxed);
            c.synced[MC_EP].store(true, Ordering::Relaxed);
        }
        c
    }

    fn touch(&self) {
        self.modified.store(now(), Ordering::Relaxed);
    }

    fn record(&self, c: Change) {
        if c.internal {
            self.touch();
        }
        if c.external {
            self.ext_modified.store(now(), Ordering::Relaxed);
        }
        if c.multicluster {
            self.mc_modified.store(now(), Ordering::Relaxed);
        }
    }

    /// `EndpointLatencyRecorder`: the DNS programming latency of an
    /// EndpointSlice change, if the slice has a trigger time and exactly
    /// one service.
    fn record_latency(&self, o: &discovery::EndpointSlice) {
        let Some(tt) = o
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(crate::metrics::LAST_CHANGE_TRIGGER_TIME))
        else {
            return;
        };
        let svc = o
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(convert::SERVICE_NAME_LABEL))
            .map(String::as_str)
            .unwrap_or("");
        let ns = o.metadata.namespace.as_deref().unwrap_or("");
        let svcs = self.svc_index(&Service::key(svc, ns));
        if let [s] = svcs.as_slice() {
            crate::metrics::record_programming_latency(tt, s.headless(), std::time::SystemTime::now());
        }
    }

    /// Start the watchers; they run until the returned handles are aborted.
    pub fn run(self: &Arc<Self>, client: Client) -> Vec<tokio::task::JoinHandle<()>> {
        let mut tasks = Vec::new();
        let cfg = |sel: &Option<String>| {
            // fewer list round trips than the default 500 per page; each page
            // is converted and dropped right away, so memory stays bounded
            let c = watcher::Config::default().page_size(5000);
            match sel {
                Some(s) => c.labels(s),
                None => c,
            }
        };

        let me = self.clone();
        let api: Api<core::Service> = Api::all(client.clone());
        let c = cfg(&self.opts.label_selector);
        tasks.push(tokio::spawn(async move {
            me.watch(
                api,
                c,
                SVC,
                Change::INTERNAL,
                |st: &mut State, o: &core::Service| {
                    st.svcs.put(obj_key(&o.metadata), convert::service(o), Change::INTERNAL)
                },
                |st, k| st.svcs.remove(k),
                |live, new| std::mem::swap(&mut live.svcs, &mut new.svcs),
                |_, _| {},
            )
            .await
        }));

        if self.opts.watch_endpoints {
            let me = self.clone();
            let api: Api<discovery::EndpointSlice> = Api::all(client.clone());
            let c = cfg(&self.opts.label_selector);
            let zonal = self.opts.zonal;
            tasks.push(tokio::spawn(async move {
                me.watch(
                    api,
                    c,
                    EP,
                    Change::INTERNAL,
                    move |st: &mut State, o: &discovery::EndpointSlice| {
                        st.eps.put(
                            obj_key(&o.metadata),
                            convert::endpoint_slice(o, zonal),
                            Change::INTERNAL,
                        )
                    },
                    |st, k| st.eps.remove(k),
                    |live, new| std::mem::swap(&mut live.eps, &mut new.eps),
                    |me, o| me.record_latency(o),
                )
                .await
            }));
        }

        if self.opts.watch_pods {
            let me = self.clone();
            let api: Api<core::Pod> = Api::all(client.clone());
            let c = cfg(&self.opts.label_selector).fields(POD_FIELD_SELECTOR);
            tasks.push(tokio::spawn(async move {
                me.watch(
                    api,
                    c,
                    POD,
                    Change::INTERNAL,
                    |st: &mut State, o: &core::Pod| match convert::pod(o) {
                        Some(p) => st.pods.put(obj_key(&o.metadata), p, Change::INTERNAL),
                        // like CoreDNS, a terminating pod is skipped: it
                        // stays until it is deleted
                        None => Change::NONE,
                    },
                    |st, k| st.pods.remove(k),
                    |live, new| std::mem::swap(&mut live.pods, &mut new.pods),
                    |_, _| {},
                )
                .await
            }));
        }

        if self.opts.multicluster {
            // like CoreDNS, ServiceImports are selected by the namespace
            // label selector
            let me = self.clone();
            let api: Api<crate::mcs::ServiceImport> = Api::all(client.clone());
            let c = cfg(&self.opts.namespace_label_selector);
            tasks.push(tokio::spawn(async move {
                me.watch(
                    api,
                    c,
                    IMPORT,
                    Change::MULTICLUSTER,
                    |st: &mut State, o: &crate::mcs::ServiceImport| {
                        st.imports
                            .put(obj_key(&o.metadata), convert::service_import(o), Change::MULTICLUSTER)
                    },
                    |st, k| st.imports.remove(k),
                    |live, new| std::mem::swap(&mut live.imports, &mut new.imports),
                    |_, _| {},
                )
                .await
            }));

            let me = self.clone();
            let api: Api<discovery::EndpointSlice> = Api::all(client.clone());
            let sel = match &self.opts.label_selector {
                Some(s) => format!("{s},{}", convert::MCS_SERVICE_NAME_LABEL),
                None => convert::MCS_SERVICE_NAME_LABEL.to_string(),
            };
            let c = cfg(&Some(sel));
            tasks.push(tokio::spawn(async move {
                me.watch(
                    api,
                    c,
                    MC_EP,
                    Change::MULTICLUSTER,
                    |st: &mut State, o: &discovery::EndpointSlice| {
                        st.mc_eps.put(
                            obj_key(&o.metadata),
                            convert::multicluster_endpoint_slice(o),
                            Change::MULTICLUSTER,
                        )
                    },
                    |st, k| st.mc_eps.remove(k),
                    |live, new| std::mem::swap(&mut live.mc_eps, &mut new.mc_eps),
                    |me, o| me.record_latency(o),
                )
                .await
            }));
        }

        let me = self.clone();
        let api: Api<core::Namespace> = Api::all(client);
        let c = cfg(&self.opts.namespace_label_selector);
        tasks.push(tokio::spawn(async move {
            me.watch(
                api,
                c,
                NS,
                Change::INTERNAL,
                |st: &mut State, o: &core::Namespace| {
                    // namespaces don't count for the serials
                    st.namespaces.insert(o.metadata.name.clone().unwrap_or_default());
                    Change::NONE
                },
                |st, k| st.namespaces.remove(k.trim_start_matches('/')),
                |live, new| std::mem::swap(&mut live.namespaces, &mut new.namespaces),
                |_, _| {},
            )
            .await
        }));
        tasks
    }

    /// Consume one watcher, applying events to the state. A re-list
    /// (`Init` .. `InitDone`) builds a fresh index from the converted
    /// objects (full API objects are never kept) and then replaces the
    /// live one with `swap`. A sync or delete counts as the `change`
    /// given; `after` runs for every object seen, outside the lock.
    #[allow(clippy::too_many_arguments)]
    async fn watch<K>(
        self: Arc<Self>,
        api: Api<K>,
        cfg: watcher::Config,
        slot: usize,
        change: Change,
        apply: impl Fn(&mut State, &K) -> Change + Send,
        delete: impl Fn(&mut State, &str) -> bool + Send,
        swap: impl Fn(&mut State, &mut State) + Send,
        after: impl Fn(&Self, &K) + Send,
    ) where
        K: kube::Resource<DynamicType = ()> + Clone + serde::de::DeserializeOwned + std::fmt::Debug + Send + 'static,
    {
        let mut stream = watcher::watcher(api, cfg).default_backoff().boxed();
        let mut staging: Option<State> = None;
        while let Some(ev) = stream.next().await {
            let ev = match ev {
                Ok(ev) => ev,
                Err(e) => {
                    kerndns_core::warning!(plugin = "kubernetes", "watch error: {e}");
                    continue;
                }
            };
            match ev {
                Event::Init => staging = Some(State::default()),
                Event::InitApply(o) => {
                    apply(staging.get_or_insert_with(State::default), &o);
                    after(&self, &o);
                }
                Event::InitDone => {
                    let mut st = staging.take().unwrap_or_default();
                    swap(&mut self.state.write().unwrap(), &mut st);
                    drop(st);
                    self.record(change);
                    self.synced[slot].store(true, Ordering::Relaxed);
                    // a (re-)list parsed every object of this kind; give the
                    // transient memory back instead of holding it at its peak
                    release_free_memory();
                }
                Event::Apply(o) => {
                    let c = apply(&mut self.state.write().unwrap(), &o);
                    self.record(c);
                    after(&self, &o);
                }
                Event::Delete(o) => {
                    let key = obj_key(o.meta());
                    if delete(&mut self.state.write().unwrap(), &key) {
                        self.record(change);
                    }
                    after(&self, &o);
                }
            }
        }
    }
}

/// Return free heap memory to the OS (glibc keeps it otherwise).
fn release_free_memory() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        unsafe extern "C" {
            fn malloc_trim(pad: usize) -> i32;
        }
        // SAFETY: malloc_trim only releases memory the allocator holds as free.
        unsafe {
            malloc_trim(0);
        }
    }
}

impl DnsController for KubeController {
    fn svc_index(&self, idx: &str) -> Vec<Arc<Service>> {
        let st = self.state.read().unwrap();
        st.svcs.lookup(&st.svcs.by, idx)
    }
    fn svc_index_reverse(&self, ip: &str) -> Vec<Arc<Service>> {
        let st = self.state.read().unwrap();
        st.svcs.lookup(&st.svcs.by_ip, ip)
    }
    fn svc_ext_index_reverse(&self, ip: &str) -> Vec<Arc<Service>> {
        let st = self.state.read().unwrap();
        st.svcs.lookup(&st.svcs.by_ip2, ip)
    }
    fn pod_index(&self, ip: &str) -> Vec<Arc<Pod>> {
        let st = self.state.read().unwrap();
        st.pods.lookup(&st.pods.by_ip, ip)
    }
    fn ep_index(&self, idx: &str) -> Vec<Arc<Endpoints>> {
        let st = self.state.read().unwrap();
        st.eps.lookup(&st.eps.by, idx)
    }
    fn ep_index_reverse(&self, ip: &str) -> Vec<Arc<Endpoints>> {
        let st = self.state.read().unwrap();
        st.eps.lookup(&st.eps.by_ip, ip)
    }
    fn namespace_exists(&self, name: &str) -> bool {
        self.state.read().unwrap().namespaces.contains(name)
    }
    fn has_synced(&self) -> bool {
        self.synced.iter().all(|s| s.load(Ordering::Relaxed))
    }
    fn modified(&self) -> i64 {
        self.modified.load(Ordering::Relaxed)
    }
    fn modified_external(&self) -> i64 {
        self.ext_modified.load(Ordering::Relaxed)
    }
    fn modified_multicluster(&self) -> i64 {
        self.mc_modified.load(Ordering::Relaxed)
    }
    fn svc_import_index(&self, idx: &str) -> Vec<Arc<ServiceImport>> {
        let st = self.state.read().unwrap();
        st.imports.lookup(&st.imports.by, idx)
    }
    fn service_import_list(&self) -> Vec<Arc<ServiceImport>> {
        self.state.read().unwrap().imports.objs.values().cloned().collect()
    }
    fn mc_ep_index(&self, idx: &str) -> Vec<Arc<MultiClusterEndpoints>> {
        let st = self.state.read().unwrap();
        st.mc_eps.lookup(&st.mc_eps.by, idx)
    }
    fn service_list(&self) -> Vec<Arc<Service>> {
        self.state.read().unwrap().svcs.objs.values().cloned().collect()
    }
    fn endpoints_list(&self) -> Vec<Arc<Endpoints>> {
        self.state.read().unwrap().eps.objs.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_updates() {
        let mut idx: Index<Service> = Index::default();
        let s = |ip: &str| Service {
            name: "a".into(),
            namespace: "ns".into(),
            index: "a.ns".into(),
            cluster_ips: vec![ip.into()],
            ..Default::default()
        };
        assert_eq!(
            idx.put("ns/a".into(), s("10.0.0.1"), Change::INTERNAL),
            Change::INTERNAL,
            "an add"
        );
        assert_eq!(
            idx.put("ns/a".into(), s("10.0.0.1"), Change::INTERNAL),
            Change::NONE,
            "no change"
        );
        // like CoreDNS, a new cluster IP doesn't change the serial
        assert_eq!(idx.put("ns/a".into(), s("10.0.0.2"), Change::INTERNAL), Change::NONE);
        assert!(idx.lookup(&idx.by_ip, "10.0.0.1").is_empty());
        assert_eq!(idx.lookup(&idx.by_ip, "10.0.0.2").len(), 1);
        assert_eq!(idx.lookup(&idx.by, "a.ns").len(), 1);
        assert!(idx.remove("ns/a"));
        assert!(idx.lookup(&idx.by, "a.ns").is_empty());
    }
}
