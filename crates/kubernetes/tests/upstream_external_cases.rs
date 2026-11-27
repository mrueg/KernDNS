//! Replays CoreDNS's own k8s_external test cases (external_test.go,
//! apex_test.go, transfer_test.go) against the Rust port.
//! `testdata/upstream_external_cases.json` is produced by running them
//! against the Go plugin (`cargo xtask k8s-cases`).

use std::collections::HashMap;
use std::sync::Arc;

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use kerndns_core::proto::rr::{Name, Record, RecordType};
use kerndns_core::proto::serialize::binary::{BinDecodable, BinDecoder};
use kerndns_core::transfer::Transferer;
use kerndns_core::{CaptureWriter, Context, Handler, HandlerResult, Protocol, Request, ResponseWriter, async_trait};
use kerndns_kubernetes::Kubernetes;
use kerndns_kubernetes::controller::DnsController;
use kerndns_kubernetes::external::External;
use kerndns_kubernetes::object::{Endpoints, Pod, Service};
use serde::Deserialize;

#[derive(Deserialize)]
struct Msg {
    rcode: u16,
    aa: bool,
    answer: Vec<String>,
    ns: Vec<String>,
    extra: Vec<String>,
}

#[derive(Deserialize)]
struct Case {
    qname: String,
    qtype: u16,
    response: Option<Msg>,
    error: String,
}

#[derive(Deserialize)]
struct Suite {
    name: String,
    zones: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Xfr {
    name: String,
    zone: String,
    serial: u32,
    records: Vec<String>,
}

#[derive(Deserialize)]
struct Data {
    services: HashMap<String, Vec<Service>>,
    endpoints: HashMap<String, Vec<Endpoints>>,
    serial: u32,
    suites: Vec<Suite>,
    transfers: Vec<Xfr>,
}

/// The `external` fake API of k8s_external's tests.
struct Fake {
    services: HashMap<String, Vec<Arc<Service>>>,
    endpoints: HashMap<String, Vec<Arc<Endpoints>>>,
    serial: u32,
}

impl DnsController for Fake {
    fn svc_index(&self, idx: &str) -> Vec<Arc<Service>> {
        self.services.get(idx).cloned().unwrap_or_default()
    }
    fn svc_index_reverse(&self, _: &str) -> Vec<Arc<Service>> {
        Vec::new()
    }
    fn svc_ext_index_reverse(&self, ip: &str) -> Vec<Arc<Service>> {
        self.services
            .values()
            .flatten()
            .filter(|s| s.external_ips.iter().any(|x| x == ip))
            .cloned()
            .collect()
    }
    fn pod_index(&self, _: &str) -> Vec<Arc<Pod>> {
        Vec::new()
    }
    fn ep_index(&self, idx: &str) -> Vec<Arc<Endpoints>> {
        self.endpoints.get(idx).cloned().unwrap_or_default()
    }
    fn ep_index_reverse(&self, _: &str) -> Vec<Arc<Endpoints>> {
        Vec::new()
    }
    fn namespace_exists(&self, _: &str) -> bool {
        true
    }
    fn has_synced(&self) -> bool {
        true
    }
    fn modified(&self) -> i64 {
        self.serial as i64
    }
    fn service_list(&self) -> Vec<Arc<Service>> {
        self.services.values().flatten().cloned().collect()
    }
    fn endpoints_list(&self) -> Vec<Arc<Endpoints>> {
        self.endpoints.values().flatten().cloned().collect()
    }
}

/// `test.NextHandler(dns.RcodeSuccess, nil)`.
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

fn norm<'a>(rrs: impl IntoIterator<Item = &'a Record>) -> Vec<String> {
    let mut v: Vec<String> = rrs.into_iter().map(|r| r.to_string().to_ascii_lowercase()).collect();
    v.sort();
    v
}

fn setup(data: &Data, zones: Vec<String>) -> External {
    let services = data
        .services
        .iter()
        .map(|(k, v)| {
            let v = v
                .iter()
                .map(|s| {
                    let mut s = s.clone();
                    if s.index.is_empty() {
                        s.index = k.clone();
                    }
                    Arc::new(s)
                })
                .collect();
            (k.clone(), v)
        })
        .collect();
    let endpoints = data
        .endpoints
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().cloned().map(Arc::new).collect()))
        .collect();
    let mut k = Kubernetes::new(vec!["cluster.local.".into()]);
    k.namespaces = ["testns".to_string()].into_iter().collect();
    // externalAddress of the Go tests: 127.0.0.1
    *k.local_ips.write().unwrap() = vec!["127.0.0.1".parse().unwrap()];
    k.upstream_override = Some(Arc::new(|_: &str, _: RecordType| None));
    k.set_api(Arc::new(Fake {
        services,
        endpoints,
        serial: data.serial,
    }));
    External::new(zones, true, Arc::new(k), Some(Arc::new(Next)))
}

fn load() -> Data {
    serde_json::from_str(include_str!("../testdata/upstream_external_cases.json"))
        .expect("valid upstream_external_cases.json")
}

#[tokio::test]
async fn upstream_k8s_external_cases() {
    let data = load();
    let mut failures = Vec::new();
    let mut total = 0;
    for suite in &data.suites {
        let e = setup(&data, suite.zones.clone());
        for (i, case) in suite.cases.iter().enumerate() {
            total += 1;
            let mut m = Message::new(1, MessageType::Query, OpCode::Query);
            m.metadata.recursion_desired = true;
            m.add_query(Query::query(
                Name::from_ascii(&case.qname).unwrap(),
                RecordType::from(case.qtype),
            ));
            let req = Request::new(
                m,
                "127.0.0.1:53".parse().unwrap(),
                "10.240.0.1:40212".parse().unwrap(),
                Protocol::Udp,
            );
            let mut w = CaptureWriter::new();
            let mut ctx = Context::new(".", "dns://:53");
            let res = e.serve_dns(&mut ctx, &mut w, &req).await;
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
                    let mut diffs = Vec::new();
                    if ResponseCode::from(0, want.rcode as u8) != got.metadata.response_code {
                        diffs.push(format!("rcode {} != {}", want.rcode, got.metadata.response_code));
                    }
                    if want.aa != got.metadata.authoritative {
                        diffs.push("aa".into());
                    }
                    for (sec, a, b) in [
                        ("answer", &want.answer, &got.answers),
                        ("ns", &want.ns, &got.authorities),
                        ("extra", &want.extra, &got.additionals),
                    ] {
                        let a: Vec<Record> = a.iter().map(|h| decode(h)).collect();
                        let (a, b) = (norm(&a), norm(b));
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
        "{} of {total} k8s_external cases differ:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// transfer_test.go: the same records (Go streams headless services in
/// map order, so compare as multisets).
#[test]
fn upstream_k8s_external_transfers() {
    let data = load();
    let e = setup(&data, vec!["example.com.".into()]);
    let t = e.transferer();
    for x in &data.transfers {
        let want: Vec<Record> = x.records.iter().map(|h| decode(h)).collect();
        let got: Vec<Record> = t.transfer(&x.zone, x.serial).unwrap().into_iter().flatten().collect();
        assert_eq!(norm(&got), norm(&want), "{}", x.name);
        assert_eq!(got.first(), want.first(), "{}: starts with the SOA", x.name);
        assert_eq!(got.last(), want.last(), "{}: ends with the SOA", x.name);
    }
}
