//! Replays CoreDNS's own kubernetes handler test suites against the Rust
//! port. `testdata/upstream_cases.json` is produced by running those suites
//! against the Go plugin (`cargo xtask k8s-cases`): it holds the fake API
//! objects, each query, the upstream lookups the Go plugin made and the
//! exact response it wrote. The Rust handler gets the same data and must
//! write the same response.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use kerndns_core::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use kerndns_core::proto::rr::{Name, Record, RecordType};
use kerndns_core::proto::serialize::binary::{BinDecodable, BinDecoder};
use kerndns_core::{CaptureWriter, Context, Handler, HandlerResult, Protocol, Request, ResponseWriter, async_trait};
use kerndns_kubernetes::controller::DnsController;
use kerndns_kubernetes::object::{Endpoints, Pod, Service};
use kerndns_kubernetes::{Kubernetes, KubernetesHandler, PodMode};
use serde::Deserialize;

#[derive(Deserialize)]
struct Msg {
    rcode: u16,
    aa: bool,
    tc: bool,
    answer: Vec<String>,
    ns: Vec<String>,
    extra: Vec<String>,
}

#[derive(Deserialize)]
struct Lookup {
    name: String,
    qtype: u16,
    response: Msg,
}

#[derive(Deserialize)]
struct Case {
    qname: String,
    qtype: u16,
    #[serde(rename = "do")]
    do_bit: bool,
    upstream: Vec<Lookup>,
    response: Option<Msg>,
    error: String,
}

#[derive(Deserialize)]
struct Suite {
    name: String,
    zones: Vec<String>,
    namespaces: Option<Vec<String>>,
    pod_mode: String,
    ignore_empty_service: bool,
    not_synced: bool,
    local_ips: Option<Vec<String>>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Data {
    services: HashMap<String, Vec<Service>>,
    endpoints: HashMap<String, Vec<Endpoints>>,
    pods: Vec<Pod>,
    missing_namespaces: Vec<String>,
    suites: Vec<Suite>,
    transfers: Vec<Xfr>,
}

/// One `Transfer` call and the records it streamed.
#[derive(Deserialize)]
struct Xfr {
    name: String,
    zones: Vec<String>,
    namespaces: Vec<String>,
    local_ips: Vec<String>,
    zone: String,
    serial: u32,
    error: String,
    records: Vec<String>,
}

/// `APIConnServeTest`.
struct Fake {
    services: HashMap<String, Vec<Arc<Service>>>,
    endpoints: HashMap<String, Vec<Arc<Endpoints>>>,
    pods: Vec<Arc<Pod>>,
    missing: HashSet<String>,
    synced: bool,
}

impl DnsController for Fake {
    fn svc_index(&self, idx: &str) -> Vec<Arc<Service>> {
        self.services.get(idx).cloned().unwrap_or_default()
    }
    fn svc_index_reverse(&self, _: &str) -> Vec<Arc<Service>> {
        Vec::new()
    }
    fn svc_ext_index_reverse(&self, _: &str) -> Vec<Arc<Service>> {
        Vec::new()
    }
    fn pod_index(&self, ip: &str) -> Vec<Arc<Pod>> {
        self.pods
            .iter()
            .filter(|p| p.pod_ips.iter().any(|i| i == ip))
            .cloned()
            .collect()
    }
    fn ep_index(&self, idx: &str) -> Vec<Arc<Endpoints>> {
        self.endpoints.get(idx).cloned().unwrap_or_default()
    }
    fn ep_index_reverse(&self, _: &str) -> Vec<Arc<Endpoints>> {
        Vec::new()
    }
    fn namespace_exists(&self, name: &str) -> bool {
        !self.missing.contains(name)
    }
    fn has_synced(&self) -> bool {
        self.synced
    }
    fn modified(&self) -> i64 {
        3
    }
    fn service_list(&self) -> Vec<Arc<Service>> {
        self.services.values().flatten().cloned().collect()
    }
    fn endpoints_list(&self) -> Vec<Arc<Endpoints>> {
        self.endpoints.values().flatten().cloned().collect()
    }
}

/// `test.NextHandler(dns.RcodeSuccess, nil)`: claims success, writes nothing.
struct Next;

#[async_trait]
impl Handler for Next {
    fn name(&self) -> &'static str {
        "next"
    }
    async fn serve_dns(&self, _: &mut Context, _: &mut dyn ResponseWriter, _: &Request) -> HandlerResult {
        Ok(ResponseCode::NoError)
    }
}

fn decode(hex: &str) -> Record {
    let bytes = data_encoding::HEXLOWER.decode(hex.as_bytes()).unwrap();
    Record::read(&mut BinDecoder::new(&bytes)).unwrap()
}

/// Records as sorted, lowercased text, like `test.SortAndCheck`.
fn norm(rrs: impl IntoIterator<Item = Record>) -> Vec<String> {
    let mut v: Vec<String> = rrs.into_iter().map(|r| r.to_string().to_ascii_lowercase()).collect();
    v.sort();
    v
}

fn to_msg(m: &Msg) -> Message {
    let mut out = Message::new(0, MessageType::Response, OpCode::Query);
    out.metadata.response_code = ResponseCode::from(0, m.rcode as u8);
    out.metadata.authoritative = m.aa;
    out.metadata.truncation = m.tc;
    out.answers = m.answer.iter().map(|h| decode(h)).collect();
    out.authorities = m.ns.iter().map(|h| decode(h)).collect();
    out.additionals = m.extra.iter().map(|h| decode(h)).collect();
    out
}

/// The fake API objects of `APIConnServeTest`, ready for [`Fake`].
struct Objects {
    services: HashMap<String, Vec<Arc<Service>>>,
    endpoints: HashMap<String, Vec<Arc<Endpoints>>>,
    pods: Vec<Arc<Pod>>,
    missing: HashSet<String>,
}

impl Objects {
    fn fake(&self, synced: bool) -> Fake {
        Fake {
            services: self.services.clone(),
            endpoints: self.endpoints.clone(),
            pods: self.pods.clone(),
            missing: self.missing.clone(),
            synced,
        }
    }
}

fn load() -> (Objects, Vec<Suite>, Vec<Xfr>) {
    let data: Data =
        serde_json::from_str(include_str!("../testdata/upstream_cases.json")).expect("valid upstream_cases.json");
    let wrap = |m: HashMap<String, Vec<Service>>| {
        m.into_iter()
            .map(|(k, v)| {
                let v = v
                    .into_iter()
                    .map(|mut s| {
                        if s.index.is_empty() {
                            s.index = k.clone();
                        }
                        Arc::new(s)
                    })
                    .collect();
                (k, v)
            })
            .collect()
    };
    let services: HashMap<String, Vec<Arc<Service>>> = wrap(data.services);
    let endpoints: HashMap<String, Vec<Arc<Endpoints>>> = data
        .endpoints
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().map(Arc::new).collect()))
        .collect();
    let pods: Vec<Arc<Pod>> = data.pods.into_iter().map(Arc::new).collect();
    let missing: HashSet<String> = data.missing_namespaces.into_iter().collect();
    let objects = Objects {
        services,
        endpoints,
        pods,
        missing,
    };
    (objects, data.suites, data.transfers)
}

/// xfr_test.go: every Transfer call streams the same records, in the same
/// order, as the Go plugin.
#[test]
fn upstream_kubernetes_transfers() {
    let (objects, _, transfers) = load();
    assert!(!transfers.is_empty());
    let mut failures = Vec::new();
    for x in &transfers {
        let mut k = Kubernetes::new(x.zones.clone());
        k.namespaces = x.namespaces.iter().cloned().collect();
        *k.local_ips.write().unwrap() = x.local_ips.iter().map(|s| s.parse().unwrap()).collect();
        k.set_api(Arc::new(objects.fake(true)));
        let got = k.transfer(&x.zone, x.serial);
        match (&got, x.error.is_empty()) {
            (Err(e), false) => {
                assert_eq!(
                    *e,
                    kerndns_core::transfer::TransferError::NotAuthoritative,
                    "{}",
                    x.name
                );
                continue;
            }
            (Err(e), true) => {
                failures.push(format!("{}: Rust failed with {e:?}", x.name));
                continue;
            }
            (Ok(_), false) => {
                failures.push(format!("{}: Go failed with {:?}, Rust transferred", x.name, x.error));
                continue;
            }
            (Ok(_), true) => {}
        }
        let want: Vec<String> = x.records.iter().map(|h| decode(h).to_string()).collect();
        let got: Vec<String> = got.unwrap().into_iter().flatten().map(|r| r.to_string()).collect();
        if want != got {
            failures.push(format!(
                "{}:\n    go:   {}\n    rust: {}",
                x.name,
                want.join("\n          "),
                got.join("\n          ")
            ));
        }
    }
    assert!(failures.is_empty(), "transfers differ:\n  {}", failures.join("\n  "));
}

#[tokio::test]
async fn upstream_kubernetes_cases() {
    let (objects, suites, _) = load();
    let mut failures = Vec::new();
    let mut total = 0;
    for suite in &suites {
        for (i, case) in suite.cases.iter().enumerate() {
            total += 1;
            let fake = objects.fake(!suite.not_synced);
            let mut k = Kubernetes::new(suite.zones.clone());
            k.namespaces = suite.namespaces.clone().unwrap_or_default().into_iter().collect();
            k.pod_mode = match suite.pod_mode.as_str() {
                "insecure" => PodMode::Insecure,
                "verified" => PodMode::Verified,
                _ => PodMode::Disabled,
            };
            k.ignore_empty_service = suite.ignore_empty_service;
            *k.local_ips.write().unwrap() = suite
                .local_ips
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|s| s.parse().unwrap())
                .collect();
            let lookups: HashMap<(String, u16), Message> = case
                .upstream
                .iter()
                .map(|l| ((l.name.clone(), l.qtype), to_msg(&l.response)))
                .collect();
            k.upstream_override = Some(Arc::new(move |name: &str, t: RecordType| {
                lookups.get(&(name.to_string(), u16::from(t))).cloned()
            }));
            k.set_api(Arc::new(fake));
            let h = KubernetesHandler {
                k: Arc::new(k),
                next: Some(Arc::new(Next)),
            };

            let mut m = Message::new(1, MessageType::Query, OpCode::Query);
            m.metadata.recursion_desired = true;
            // test.Case.Msg() makes the name fully qualified
            let qname = if case.qname.ends_with('.') {
                case.qname.clone()
            } else {
                format!("{}.", case.qname)
            };
            m.add_query(Query::query(
                Name::from_ascii(&qname).unwrap(),
                RecordType::from(case.qtype),
            ));
            if case.do_bit {
                let mut e = Edns::new();
                e.set_max_payload(4096);
                e.set_dnssec_ok(true);
                m.edns = Some(e);
            }
            let req = Request::new(
                m,
                "127.0.0.1:53".parse().unwrap(),
                "10.240.0.1:40212".parse().unwrap(),
                Protocol::Udp,
            );
            let mut w = CaptureWriter::new();
            let mut ctx = Context::new(".", "dns://:53");
            let res = h.serve_dns(&mut ctx, &mut w, &req).await;

            let label = format!("{} #{i} {} {}", suite.name, case.qname, RecordType::from(case.qtype));
            if !case.error.is_empty() {
                if res.is_ok() && w.msg().is_some() {
                    failures.push(format!("{label}: Go returned error {:?}, Rust answered", case.error));
                }
                continue;
            }
            match (&case.response, w.msg()) {
                (None, None) => {}
                (None, Some(_)) => failures.push(format!("{label}: Go wrote nothing, Rust answered")),
                (Some(_), None) => failures.push(format!("{label}: Go answered, Rust wrote nothing ({res:?})")),
                (Some(want), Some(got)) => {
                    let want = to_msg(want);
                    let mut diffs = Vec::new();
                    if want.metadata.response_code != got.metadata.response_code {
                        diffs.push(format!(
                            "rcode {} != {}",
                            want.metadata.response_code, got.metadata.response_code
                        ));
                    }
                    if want.metadata.authoritative != got.metadata.authoritative {
                        diffs.push("aa".into());
                    }
                    if want.metadata.truncation != got.metadata.truncation {
                        diffs.push("tc".into());
                    }
                    for (sec, a, b) in [
                        ("answer", &want.answers, &got.answers),
                        ("ns", &want.authorities, &got.authorities),
                        ("extra", &want.additionals, &got.additionals),
                    ] {
                        let (a, b) = (norm(a.clone()), norm(b.clone()));
                        if a != b {
                            diffs.push(format!("{sec}:\n      go:   {a:?}\n      rust: {b:?}"));
                        }
                    }
                    if !diffs.is_empty() {
                        failures.push(format!("{label}: {}", diffs.join("; ")));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {total} upstream cases differ:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    eprintln!("{total} upstream cases match the Go plugin");
}
