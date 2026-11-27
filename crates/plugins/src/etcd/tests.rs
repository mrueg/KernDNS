//! CoreDNS's etcd plugin tests (`plugin/etcd/*_test.go`), with an
//! in-memory key-value store in place of a live etcd.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::{RData, Record, RecordType};
use kerndns_core::{Handler, result_rcode};

use super::client::{Code, KeyValue, Kv, RangeResponse, RpcError};
use super::*;
use crate::file::zonefile::new_rr;
use crate::testutil::{query, reply, serve, with_controller};

/// etcd's key space: keys in order, prefix ranges, leases.
#[derive(Default)]
struct MemKv {
    keys: Mutex<BTreeMap<String, (Vec<u8>, i64)>>,
    leases: HashMap<i64, i64>,
}

#[async_trait]
impl Kv for MemKv {
    async fn get(&self, key: &str, prefix: bool, _: Instant) -> Result<RangeResponse, RpcError> {
        let keys = self.keys.lock().unwrap();
        let kvs: Vec<KeyValue> = keys
            .iter()
            .filter(|(k, _)| if prefix { k.starts_with(key) } else { *k == key })
            .map(|(k, (v, lease))| KeyValue {
                key: k.as_bytes().to_vec(),
                value: v.clone(),
                lease: *lease,
            })
            .collect();
        Ok(RangeResponse {
            count: kvs.len() as i64,
            kvs,
        })
    }

    async fn lease_ttl(&self, lease: i64, _: Instant) -> Result<i64, RpcError> {
        self.leases
            .get(&lease)
            .copied()
            .ok_or_else(|| RpcError::new(Code::NOT_FOUND, "etcdserver: requested lease not found"))
    }
}

/// A service as `json.Marshal` writes it (every field `omitempty`), and
/// the name whose key it goes under.
struct Svc {
    key: &'static str,
    host: &'static str,
    port: i32,
    priority: i32,
    text: String,
    mail: bool,
    target_strip: usize,
    group: &'static str,
}

const SVC: Svc = Svc {
    key: "",
    host: "",
    port: 0,
    priority: 0,
    text: String::new(),
    mail: false,
    target_strip: 0,
    group: "",
};

impl Svc {
    fn json(&self) -> String {
        let mut f = Vec::new();
        if !self.host.is_empty() {
            f.push(format!("\"host\":\"{}\"", self.host));
        }
        if self.port != 0 {
            f.push(format!("\"port\":{}", self.port));
        }
        if self.priority != 0 {
            f.push(format!("\"priority\":{}", self.priority));
        }
        if !self.text.is_empty() {
            f.push(format!("\"text\":\"{}\"", self.text));
        }
        if self.mail {
            f.push("\"mail\":true".into());
        }
        if self.target_strip != 0 {
            f.push(format!("\"targetstrip\":{}", self.target_strip));
        }
        if !self.group.is_empty() {
            f.push(format!("\"group\":\"{}\"", self.group));
        }
        format!("{{{}}}", f.join(","))
    }
}

fn host(key: &'static str, host: &'static str) -> Svc {
    Svc { key, host, ..SVC }
}

fn hostp(key: &'static str, h: &'static str, port: i32) -> Svc {
    Svc { port, ..host(key, h) }
}

fn text(key: &'static str, text: &str) -> Svc {
    Svc {
        key,
        text: text.into(),
        ..SVC
    }
}

fn mem(services: &[Svc]) -> Arc<MemKv> {
    let kv = MemKv::default();
    set(&kv, services);
    Arc::new(kv)
}

fn set(kv: &MemKv, services: &[Svc]) {
    let mut keys = kv.keys.lock().unwrap();
    for s in services {
        let (path, _) = msg::path_with_wildcard(s.key, "skydns");
        keys.insert(path, (s.json().into_bytes(), 0));
    }
}

/// `newEtcdPlugin`.
fn plugin(kv: Arc<dyn Kv>) -> Etcd {
    Etcd::new(
        [
            "skydns.test.",
            "skydns_extra.test.",
            "skydns_zonea.test.",
            "skydns_zoneb.test.",
            "skydns_zonec.test.",
            "skydns_zoned.test.",
            "in-addr.arpa.",
        ]
        .map(String::from)
        .to_vec(),
        kv,
    )
}

fn handler(e: Etcd) -> EtcdHandler {
    EtcdHandler {
        e: Arc::new(e),
        next: None,
    }
}

/// `test.Case`.
struct Case {
    qname: &'static str,
    qtype: RecordType,
    rcode: ResponseCode,
    answer: &'static [&'static str],
    ns: &'static [&'static str],
    extra: &'static [&'static str],
}

const CASE: Case = Case {
    qname: "",
    qtype: RecordType::A,
    rcode: ResponseCode::NoError,
    answer: &[],
    ns: &[],
    extra: &[],
};

fn rr(s: &str) -> Record {
    new_rr(s)
        .unwrap_or_else(|e| panic!("{s}: {e}"))
        .unwrap_or_else(|| panic!("{s}: no record"))
}

fn sort_key(r: &Record) -> String {
    format!("{} {} {}", r.name.to_ascii(), r.record_type(), r.data)
}

/// `test.Section`: owner (case-sensitive), TTL unless the expected one is
/// 303, type, and the data CoreDNS compares for the type.
fn check_section(what: &str, got: &[Record], want: &[&str], sorted: bool) -> Result<(), String> {
    let mut want: Vec<Record> = want.iter().map(|s| rr(s)).collect();
    let mut got = got.to_vec();
    if got.len() != want.len() {
        return Err(format!(
            "{what} contained {} results, {} expected: {}",
            got.len(),
            want.len(),
            got.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(" | ")
        ));
    }
    if sorted {
        got.sort_by_key(sort_key);
        want.sort_by_key(sort_key);
    }
    for (i, (a, b)) in got.iter().zip(&want).enumerate() {
        let same = a.name.to_ascii() == b.name.to_ascii()
            && (b.ttl == 303 || a.ttl == b.ttl)
            && a.record_type() == b.record_type()
            && match (&a.data, &b.data) {
                (RData::SOA(x), RData::SOA(y)) => x.mname == y.mname,
                (RData::TXT(x), RData::TXT(y)) => x.txt_data.concat() == y.txt_data.concat(),
                (x, y) => x == y,
            };
        if !same {
            return Err(format!("{what} RR {i}: got {a}, want {b}"));
        }
    }
    Ok(())
}

impl Case {
    async fn check(&self, h: &dyn Handler, sorted: bool) -> Result<(), String> {
        let req = query(self.qname, self.qtype, "10.240.0.1:40212");
        let (rc, w) = serve(h, &req).await;
        let m = w
            .msg()
            .cloned()
            .ok_or_else(|| format!("no response, result {:?}", result_rcode(&rc)))?;
        if m.metadata.response_code != self.rcode {
            return Err(format!(
                "rcode is {:?}, expected {:?}",
                m.metadata.response_code, self.rcode
            ));
        }
        check_section("answer", &m.answers, self.answer, sorted)?;
        check_section("authority", &m.authorities, self.ns, sorted)?;
        check_section("additional", &m.additionals, self.extra, sorted)
    }
}

async fn run(h: &dyn Handler, cases: &[Case], sorted: bool) {
    let mut failed = Vec::new();
    for (i, tc) in cases.iter().enumerate() {
        if let Err(e) = tc.check(h, sorted).await {
            failed.push(format!("test {i} ({} {}): {e}", tc.qname, tc.qtype));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

const SOA_NODATA: &[&str] = &["skydns.test. 30 SOA ns.dns.skydns.test. hostmaster.skydns.test. 0 0 0 0 0"];

/// lookup_test.go `services` (keys written as DNS names).
fn services() -> Vec<Svc> {
    vec![
        hostp("a.server1.dev.region1.skydns.test.", "dev.server1", 8080),
        hostp("a.server1.prod.region1.skydns.test.", "10.0.0.1", 8080),
        hostp("b.server1.prod.region1.skydns.test.", "10.0.0.2", 8080),
        hostp("b.server6.prod.region1.skydns.test.", "::1", 8080),
        // TXT records in server1
        text("a.txt.server1.prod.region1.skydns.test.", "sometext"),
        text("b.txt.server1.prod.region1.skydns.test.", "moretext"),
        // unresolvable internal name
        host("cname.prod.region1.skydns.test.", "unresolvable.skydns.test"),
        // priority
        Svc {
            priority: 333,
            ..hostp("priority.skydns.test.", "priority.server1", 8080)
        },
        // subdomain
        hostp("a.sub.region1.skydns.test.", "sub.server1", 0),
        hostp("b.sub.region1.skydns.test.", "sub.server2", 80),
        hostp("c.sub.region1.skydns.test.", "10.0.0.1", 8080),
        // target strip
        Svc {
            target_strip: 1,
            ..hostp("a.targetstrip.skydns.test.", "10.0.0.1", 8080)
        },
        // CNAME loop
        host("b.cname.skydns.test.", "a.cname.skydns.test"),
        host("a.cname.skydns.test.", "b.cname.skydns.test"),
        // nameservers
        host("a.ns.dns.skydns.test.", "10.0.0.2"),
        host("b.ns.dns.skydns.test.", "10.0.0.3"),
        Svc {
            target_strip: 1,
            ..host("ns1.c.ns.dns.skydns.test.", "10.0.0.4")
        },
        Svc {
            target_strip: 1,
            ..host("ns2.c.ns.dns.skydns.test.", "10.0.0.5")
        },
        // zone name as A record (basic, return all)
        host("x.skydns_zonea.test.", "10.0.0.2"),
        host("y.skydns_zonea.test.", "10.0.0.3"),
        // zone name as A (single entry)
        host("x.skydns_zoneb.test.", "10.0.0.2"),
        host("y.skydns_zoneb.test.", "10.0.0.3"),
        host("apex.dns.skydns_zoneb.test.", "10.0.0.4"),
        // a zone record (rr multiple entries)
        host("x.skydns_zonec.test.", "10.0.0.2"),
        host("y.skydns_zonec.test.", "10.0.0.3"),
        host("a1.apex.dns.skydns_zonec.test.", "10.0.0.4"),
        host("a2.apex.dns.skydns_zonec.test.", "10.0.0.5"),
        // AAAA zone record (rr multiple entries mixed with A)
        host("x.skydns_zoned.test.", "10.0.0.2"),
        host("y.skydns_zoned.test.", "10.0.0.3"),
        host("a1.apex.dns.skydns_zoned.test.", "10.0.0.4"),
        host("a2.apex.dns.skydns_zoned.test.", "10.0.0.5"),
        host("a3.apex.dns.skydns_zoned.test.", "2003::8:1"),
        host("a4.apex.dns.skydns_zoned.test.", "2003::8:2"),
        // reverse
        host("1.0.0.10.in-addr.arpa.", "reverse.example.com"),
    ]
}

/// lookup_test.go `dnsTestCases`.
fn lookup_cases() -> Vec<Case> {
    use RecordType::*;
    vec![
        // SRV
        Case {
            qname: "a.server1.dev.region1.skydns.test.",
            qtype: SRV,
            answer: &["a.server1.dev.region1.skydns.test. 300 SRV 10 100 8080 dev.server1."],
            ..CASE
        },
        // SRV (case test)
        Case {
            qname: "a.SERVer1.dEv.region1.skydns.tEst.",
            qtype: SRV,
            answer: &["a.SERVer1.dEv.region1.skydns.tEst. 300 SRV 10 100 8080 dev.server1."],
            ..CASE
        },
        // NXDOMAIN
        Case {
            qname: "doesnotexist.skydns.test.",
            rcode: ResponseCode::NXDomain,
            ns: SOA_NODATA,
            ..CASE
        },
        // A
        Case {
            qname: "a.server1.prod.region1.skydns.test.",
            answer: &["a.server1.prod.region1.skydns.test. 300 A 10.0.0.1"],
            ..CASE
        },
        // SRV where the target is an IP address
        Case {
            qname: "a.server1.prod.region1.skydns.test.",
            qtype: SRV,
            answer: &["a.server1.prod.region1.skydns.test. 300 SRV 10 100 8080 a.server1.prod.region1.skydns.test."],
            extra: &["a.server1.prod.region1.skydns.test. 300 A 10.0.0.1"],
            ..CASE
        },
        // AAAA
        Case {
            qname: "b.server6.prod.region1.skydns.test.",
            qtype: AAAA,
            answer: &["b.server6.prod.region1.skydns.test. 300 AAAA ::1"],
            ..CASE
        },
        // multiple A records
        Case {
            qname: "server1.prod.region1.skydns.test.",
            answer: &[
                "server1.prod.region1.skydns.test. 300 A 10.0.0.1",
                "server1.prod.region1.skydns.test. 300 A 10.0.0.2",
            ],
            ..CASE
        },
        // priority
        Case {
            qname: "priority.skydns.test.",
            qtype: SRV,
            answer: &["priority.skydns.test. 300 SRV 333 100 8080 priority.server1."],
            ..CASE
        },
        // subdomain
        Case {
            qname: "sub.region1.skydns.test.",
            qtype: SRV,
            answer: &[
                "sub.region1.skydns.test. 300 IN SRV 10 33 0 sub.server1.",
                "sub.region1.skydns.test. 300 IN SRV 10 33 80 sub.server2.",
                "sub.region1.skydns.test. 300 IN SRV 10 33 8080 c.sub.region1.skydns.test.",
            ],
            extra: &["c.sub.region1.skydns.test. 300 IN A 10.0.0.1"],
            ..CASE
        },
        // SRV target strip
        Case {
            qname: "targetstrip.skydns.test.",
            qtype: SRV,
            answer: &["targetstrip.skydns.test. 300 IN SRV 10 100 8080 targetstrip.skydns.test."],
            extra: &["targetstrip.skydns.test. 300 IN A 10.0.0.1"],
            ..CASE
        },
        // CNAME (unresolvable internal name)
        Case {
            qname: "cname.prod.region1.skydns.test.",
            ns: SOA_NODATA,
            ..CASE
        },
        // TXT
        Case {
            qname: "txt.server1.prod.region1.skydns.test.",
            qtype: TXT,
            answer: &[
                "txt.server1.prod.region1.skydns.test. 303 IN TXT moretext",
                "txt.server1.prod.region1.skydns.test. 303 IN TXT sometext",
            ],
            ..CASE
        },
        // wildcard
        Case {
            qname: "*.region1.skydns.test.",
            qtype: SRV,
            answer: &[
                "*.region1.skydns.test. 300 IN SRV 10 12 0 sub.server1.",
                "*.region1.skydns.test. 300 IN SRV 10 12 0 unresolvable.skydns.test.",
                "*.region1.skydns.test. 300 IN SRV 10 12 80 sub.server2.",
                "*.region1.skydns.test. 300 IN SRV 10 12 8080 a.server1.prod.region1.skydns.test.",
                "*.region1.skydns.test. 300 IN SRV 10 12 8080 b.server1.prod.region1.skydns.test.",
                "*.region1.skydns.test. 300 IN SRV 10 12 8080 b.server6.prod.region1.skydns.test.",
                "*.region1.skydns.test. 300 IN SRV 10 12 8080 c.sub.region1.skydns.test.",
                "*.region1.skydns.test. 300 IN SRV 10 12 8080 dev.server1.",
            ],
            extra: &[
                "a.server1.prod.region1.skydns.test. 300 IN A 10.0.0.1",
                "b.server1.prod.region1.skydns.test. 300 IN A 10.0.0.2",
                "b.server6.prod.region1.skydns.test. 300 IN AAAA ::1",
                "c.sub.region1.skydns.test. 300 IN A 10.0.0.1",
            ],
            ..CASE
        },
        Case {
            qname: "prod.*.skydns.test.",
            qtype: SRV,
            answer: &[
                "prod.*.skydns.test. 300 IN SRV 10 25 0 unresolvable.skydns.test.",
                "prod.*.skydns.test. 300 IN SRV 10 25 8080 a.server1.prod.region1.skydns.test.",
                "prod.*.skydns.test. 300 IN SRV 10 25 8080 b.server1.prod.region1.skydns.test.",
                "prod.*.skydns.test. 300 IN SRV 10 25 8080 b.server6.prod.region1.skydns.test.",
            ],
            extra: &[
                "a.server1.prod.region1.skydns.test. 300 IN A 10.0.0.1",
                "b.server1.prod.region1.skydns.test. 300 IN A 10.0.0.2",
                "b.server6.prod.region1.skydns.test. 300 IN AAAA ::1",
            ],
            ..CASE
        },
        Case {
            qname: "prod.any.skydns.test.",
            qtype: SRV,
            answer: &[
                "prod.any.skydns.test. 300 IN SRV 10 25 0 unresolvable.skydns.test.",
                "prod.any.skydns.test. 300 IN SRV 10 25 8080 a.server1.prod.region1.skydns.test.",
                "prod.any.skydns.test. 300 IN SRV 10 25 8080 b.server1.prod.region1.skydns.test.",
                "prod.any.skydns.test. 300 IN SRV 10 25 8080 b.server6.prod.region1.skydns.test.",
            ],
            extra: &[
                "a.server1.prod.region1.skydns.test. 300 IN A 10.0.0.1",
                "b.server1.prod.region1.skydns.test. 300 IN A 10.0.0.2",
                "b.server6.prod.region1.skydns.test. 300 IN AAAA ::1",
            ],
            ..CASE
        },
        // CNAME loop detection
        Case {
            qname: "a.cname.skydns.test.",
            ns: &["skydns.test. 30 SOA ns.dns.skydns.test. hostmaster.skydns.test. 1407441600 28800 7200 604800 60"],
            ..CASE
        },
        // NODATA
        Case {
            qname: "a.server1.dev.region1.skydns.test.",
            qtype: TXT,
            ns: SOA_NODATA,
            ..CASE
        },
        Case {
            qname: "a.server1.dev.region1.skydns.test.",
            qtype: HINFO,
            ns: SOA_NODATA,
            ..CASE
        },
        // NXDOMAIN
        Case {
            qname: "a.server1.nonexistent.region1.skydns.test.",
            qtype: HINFO,
            rcode: ResponseCode::NXDomain,
            ns: SOA_NODATA,
            ..CASE
        },
        Case {
            qname: "skydns.test.",
            qtype: SOA,
            answer: &[
                "skydns.test. 30 IN SOA ns.dns.skydns.test. hostmaster.skydns.test. 1460498836 14400 3600 604800 60",
            ],
            ..CASE
        },
        // NS
        Case {
            qname: "skydns.test.",
            qtype: NS,
            answer: &[
                "skydns.test. 300 NS a.ns.dns.skydns.test.",
                "skydns.test. 300 NS b.ns.dns.skydns.test.",
                "skydns.test. 300 NS c.ns.dns.skydns.test.",
            ],
            extra: &[
                "a.ns.dns.skydns.test. 300 A 10.0.0.2",
                "b.ns.dns.skydns.test. 300 A 10.0.0.3",
                "c.ns.dns.skydns.test. 300 A 10.0.0.4",
                "c.ns.dns.skydns.test. 300 A 10.0.0.5",
            ],
            ..CASE
        },
        Case {
            qname: "a.skydns.test.",
            qtype: NS,
            rcode: ResponseCode::NXDomain,
            ns: &["skydns.test. 30 IN SOA ns.dns.skydns.test. hostmaster.skydns.test. 1460498836 14400 3600 604800 60"],
            ..CASE
        },
        // A records for the NS records
        Case {
            qname: "ns.dns.skydns.test.",
            answer: &[
                "ns.dns.skydns.test. 300 A 10.0.0.2",
                "ns.dns.skydns.test. 300 A 10.0.0.3",
                "ns.dns.skydns.test. 300 A 10.0.0.4",
                "ns.dns.skydns.test. 300 A 10.0.0.5",
            ],
            ..CASE
        },
        Case {
            qname: "skydns_extra.test.",
            qtype: SOA,
            answer: &[
                "skydns_extra.test. 30 IN SOA ns.dns.skydns_extra.test. hostmaster.skydns_extra.test. 1460498836 14400 3600 604800 60",
            ],
            ..CASE
        },
        // zone records, backward compatible
        Case {
            qname: "skydns_zonea.test.",
            answer: &["skydns_zonea.test. 300 A 10.0.0.2", "skydns_zonea.test. 300 A 10.0.0.3"],
            ..CASE
        },
        // a single A zone record
        Case {
            qname: "skydns_zoneb.test.",
            answer: &["skydns_zoneb.test. 300 A 10.0.0.4"],
            ..CASE
        },
        // multiple A zone records
        Case {
            qname: "skydns_zonec.test.",
            answer: &["skydns_zonec.test. 300 A 10.0.0.4", "skydns_zonec.test. 300 A 10.0.0.5"],
            ..CASE
        },
        // mixed A and AAAA
        Case {
            qname: "skydns_zoned.test.",
            answer: &["skydns_zoned.test. 300 A 10.0.0.4", "skydns_zoned.test. 300 A 10.0.0.5"],
            ..CASE
        },
        Case {
            qname: "skydns_zoned.test.",
            qtype: AAAA,
            answer: &[
                "skydns_zoned.test. 300 AAAA 2003::8:1",
                "skydns_zoned.test. 300 AAAA 2003::8:2",
            ],
            ..CASE
        },
        // reverse
        Case {
            qname: "1.0.0.10.in-addr.arpa.",
            qtype: PTR,
            answer: &["1.0.0.10.in-addr.arpa. 300 PTR reverse.example.com."],
            ..CASE
        },
    ]
}

#[tokio::test]
async fn lookup() {
    let h = handler(plugin(mem(&services())));
    run(&h, &lookup_cases(), true).await;
}

#[tokio::test]
async fn lookup_no_apex_fallback() {
    let kv = mem(&[host("x.child.strict.test.", "10.0.0.1")]);
    let mut e = plugin(kv.clone());
    e.zones = vec!["strict.test.".into()];
    let ask = |h: EtcdHandler| async move {
        let (rc, w) = serve(&h, &query("strict.test.", RecordType::A, "10.240.0.1:40212")).await;
        assert!(rc.is_ok(), "unexpected lookup error: {rc:?}");
        w.msg().cloned().unwrap()
    };
    let legacy = ask(handler(e)).await;
    assert_eq!(legacy.metadata.response_code, ResponseCode::NoError);
    assert_eq!(legacy.answers.len(), 1);

    let mut e = plugin(kv.clone());
    e.zones = vec!["strict.test.".into()];
    e.no_apex_fallback = true;
    let strict = ask(handler(e)).await;
    assert_eq!(strict.metadata.response_code, ResponseCode::NXDomain);
    assert!(strict.answers.is_empty());

    set(&kv, &[host("x.apex.dns.strict.test.", "192.0.2.1")]);
    let mut e = plugin(kv);
    e.zones = vec!["strict.test.".into()];
    e.no_apex_fallback = true;
    let m = ask(handler(e)).await;
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].to_string(), "strict.test. 300 IN A 192.0.2.1");
}

#[tokio::test]
async fn cname_lookup() {
    use RecordType::*;
    let services = vec![
        host("a.server1.dev.region1.skydns.test.", "cname1.region2.skydns.test"),
        host("cname1.region2.skydns.test.", "cname2.region2.skydns.test"),
        host("cname2.region2.skydns.test.", "cname3.region2.skydns.test"),
        host("cname3.region2.skydns.test.", "cname4.region2.skydns.test"),
        host("cname4.region2.skydns.test.", "cname5.region2.skydns.test"),
        host("cname5.region2.skydns.test.", "cname6.region2.skydns.test"),
        host("cname6.region2.skydns.test.", "endpoint.region2.skydns.test"),
        host("endpoint.region2.skydns.test.", "10.240.0.1"),
        host("region2.skydns.test.", "mainendpoint.region2.skydns.test"),
        host("cname3.region3.skydns.test.", "cname2.region3.skydns.test"),
        host("cname2.region3.skydns.test.", "cname1.region3.skydns.test"),
        host("cname1.region3.skydns.test.", "endpoint.region3.skydns.test"),
        text("endpoint.region3.skydns.test.", "SOME-RECORD-TEXT"),
    ];
    let cases = [
        Case {
            qname: "a.server1.dev.region1.skydns.test.",
            qtype: SRV,
            answer: &["a.server1.dev.region1.skydns.test. 300 IN SRV 10 100 0 cname1.region2.skydns.test."],
            extra: &[
                "cname1.region2.skydns.test. 300 IN CNAME cname2.region2.skydns.test.",
                "cname2.region2.skydns.test. 300 IN CNAME cname3.region2.skydns.test.",
                "cname3.region2.skydns.test. 300 IN CNAME cname4.region2.skydns.test.",
                "cname4.region2.skydns.test. 300 IN CNAME cname5.region2.skydns.test.",
                "cname5.region2.skydns.test. 300 IN CNAME cname6.region2.skydns.test.",
                "cname6.region2.skydns.test. 300 IN CNAME endpoint.region2.skydns.test.",
                "endpoint.region2.skydns.test. 300 IN A 10.240.0.1",
            ],
            ..CASE
        },
        Case {
            qname: "region2.skydns.test.",
            qtype: CNAME,
            answer: &["region2.skydns.test. 300 IN CNAME mainendpoint.region2.skydns.test."],
            ..CASE
        },
        Case {
            qname: "endpoint.region3.skydns.test.",
            qtype: CNAME,
            ns: &["skydns.test. 303 IN SOA ns.dns.skydns.test. hostmaster.skydns.test. 1546424605 7200 1800 86400 30"],
            ..CASE
        },
        Case {
            qname: "cname3.region3.skydns.test.",
            qtype: TXT,
            answer: &[
                "cname3.region3.skydns.test. 300 IN CNAME cname2.region3.skydns.test.",
                "cname2.region3.skydns.test. 300 IN CNAME cname1.region3.skydns.test.",
                "cname1.region3.skydns.test. 300 IN CNAME endpoint.region3.skydns.test.",
                "endpoint.region3.skydns.test. 300 IN TXT \"SOME-RECORD-TEXT\"",
            ],
            ..CASE
        },
    ];
    // TestCnameLookup checks the order of the records
    run(&handler(plugin(mem(&services))), &cases, false).await;
}

#[tokio::test]
async fn group_lookup() {
    let g = |key, h, group| Svc { group, ..host(key, h) };
    let services = vec![
        g("a.dom.skydns.test.", "127.0.0.1", "g1"),
        g("b.sub.dom.skydns.test.", "127.0.0.2", "g1"),
        g("a.dom2.skydns.test.", "127.0.0.1", "g1"),
        g("b.sub.dom2.skydns.test.", "127.0.0.2", ""),
        g("a.dom1.skydns.test.", "127.0.0.1", "g1"),
        g("b.sub.dom1.skydns.test.", "127.0.0.2", "g2"),
        Svc {
            group: "g1",
            ..text("a.dom3.skydns.test.", "foo")
        },
        Svc {
            group: "g1",
            ..text("b.sub.dom3.skydns.test.", "bar")
        },
    ];
    let cases = [
        // hits the group 'g1' and only includes those A records
        Case {
            qname: "dom.skydns.test.",
            answer: &[
                "dom.skydns.test. 300 IN A 127.0.0.1",
                "dom.skydns.test. 300 IN A 127.0.0.2",
            ],
            ..CASE
        },
        // one has a group, the other has not: include the non-group always
        Case {
            qname: "dom2.skydns.test.",
            answer: &[
                "dom2.skydns.test. 300 IN A 127.0.0.1",
                "dom2.skydns.test. 300 IN A 127.0.0.2",
            ],
            ..CASE
        },
        // the groups differ
        Case {
            qname: "dom1.skydns.test.",
            answer: &["dom1.skydns.test. 300 IN A 127.0.0.1"],
            ..CASE
        },
        // hits the group 'g1' and only includes those TXT records
        Case {
            qname: "dom3.skydns.test.",
            qtype: RecordType::TXT,
            answer: &["dom3.skydns.test. 300 IN TXT bar", "dom3.skydns.test. 300 IN TXT foo"],
            ..CASE
        },
    ];
    run(&handler(plugin(mem(&services))), &cases, true).await;
}

#[tokio::test]
async fn multi_lookup() {
    let services = vec![
        hostp("a.server1.dev.region1.skydns.test.", "dev.server1", 8080),
        hostp("a.server1.dev.region1.miek.nl.", "dev.server1", 8080),
        hostp("a.server1.dev.region1.example.org.", "dev.server1", 8080),
    ];
    let mut e = plugin(mem(&services));
    e.zones = vec!["skydns.test.".into(), "miek.nl.".into()];
    let h = EtcdHandler {
        e: Arc::new(e),
        // test.ErrorHandler
        next: reply(|req| req.error_reply(ResponseCode::ServFail)),
    };
    let cases = [
        Case {
            qname: "a.server1.dev.region1.skydns.test.",
            qtype: RecordType::SRV,
            answer: &["a.server1.dev.region1.skydns.test. 300 SRV 10 100 8080 dev.server1."],
            ..CASE
        },
        Case {
            qname: "a.server1.dev.region1.miek.nl.",
            qtype: RecordType::SRV,
            answer: &["a.server1.dev.region1.miek.nl. 300 SRV 10 100 8080 dev.server1."],
            ..CASE
        },
        Case {
            qname: "a.server1.dev.region1.example.org.",
            qtype: RecordType::SRV,
            rcode: ResponseCode::ServFail,
            ..CASE
        },
    ];
    run(&h, &cases, true).await;
}

#[tokio::test]
async fn other_lookup() {
    let mx = |key, h, priority| Svc {
        priority,
        mail: true,
        ..host(key, h)
    };
    let large400 = "0".repeat(400);
    let services = vec![
        hostp("a.server1.dev.region1.skydns.test.", "dev.server1", 8080),
        // mx
        mx("a.mail.skydns.test.", "mx.skydns.test", 50),
        mx("b.mail.skydns.test.", "mx.miek.nl", 50),
        mx("a.mx.skydns.test.", "a.ipaddr.skydns.test", 30),
        mx("a.mx2.skydns.test.", "a.ipaddr.skydns.test", 0),
        mx("b.mx2.skydns.test.", "b.ipaddr.skydns.test", 0),
        mx("a.mx3.skydns.test.", "a.ipaddr.skydns.test", 20),
        mx("b.mx3.skydns.test.", "a.ipaddr.skydns.test", 30),
        host("a.ipaddr.skydns.test.", "172.16.1.1"),
        host("b.ipaddr.skydns.test.", "172.16.1.2"),
        // txt
        text("a1.txt.skydns.test.", "abc"),
        text("a2.txt.skydns.test.", "abc abc"),
        // txt sizes
        text("large400.skydns.test.", &large400),
        text("large600.skydns.test.", &"0".repeat(600)),
        text("large2000.skydns.test.", &"0".repeat(2000)),
        // duplicate ip address
        hostp("http.multiport.http.skydns.test.", "10.11.11.10", 80),
        hostp("https.multiport.http.skydns.test.", "10.11.11.10", 443),
    ];
    // miekg/dns splits the 400 bytes when parsing; only the text is compared
    let large = format!(
        "large400.skydns.test. 300 IN TXT \"{}\" \"{}\"",
        &large400[..255],
        &large400[255..]
    );
    let large: &'static str = Box::leak(large.into_boxed_str());
    let large: &'static [&'static str] = Box::leak(vec![large].into_boxed_slice());
    let cases = [
        // NODATA: not a mail record
        Case {
            qname: "a.server1.dev.region1.skydns.test.",
            qtype: RecordType::MX,
            ns: SOA_NODATA,
            ..CASE
        },
        Case {
            qname: "a.mail.skydns.test.",
            qtype: RecordType::MX,
            answer: &["a.mail.skydns.test. 300 IN MX 50 mx.skydns.test."],
            extra: &[
                "a.ipaddr.skydns.test. 300 IN A 172.16.1.1",
                "mx.skydns.test. 300 IN CNAME a.ipaddr.skydns.test.",
            ],
            ..CASE
        },
        Case {
            qname: "mx2.skydns.test.",
            qtype: RecordType::MX,
            answer: &[
                "mx2.skydns.test. 300 IN MX 10 a.ipaddr.skydns.test.",
                "mx2.skydns.test. 300 IN MX 10 b.ipaddr.skydns.test.",
            ],
            extra: &[
                "a.ipaddr.skydns.test. 300 A 172.16.1.1",
                "b.ipaddr.skydns.test. 300 A 172.16.1.2",
            ],
            ..CASE
        },
        // different priority, same host
        Case {
            qname: "mx3.skydns.test.",
            qtype: RecordType::MX,
            answer: &[
                "mx3.skydns.test. 300 IN MX 20 a.ipaddr.skydns.test.",
                "mx3.skydns.test. 300 IN MX 30 a.ipaddr.skydns.test.",
            ],
            extra: &["a.ipaddr.skydns.test. 300 A 172.16.1.1"],
            ..CASE
        },
        Case {
            qname: "a1.txt.skydns.test.",
            qtype: RecordType::TXT,
            answer: &["a1.txt.skydns.test. 300 IN TXT \"abc\""],
            ..CASE
        },
        Case {
            qname: "a2.txt.skydns.test.",
            qtype: RecordType::TXT,
            answer: &["a2.txt.skydns.test. 300 IN TXT \"abc abc\""],
            ..CASE
        },
        // large TXT, less than 512 bytes
        Case {
            qname: "large400.skydns.test.",
            qtype: RecordType::TXT,
            answer: large,
            ..CASE
        },
        // duplicate IP address
        Case {
            qname: "multiport.http.skydns.test.",
            answer: &["multiport.http.skydns.test. 300 IN A 10.11.11.10"],
            ..CASE
        },
    ];
    run(&handler(plugin(mem(&services))), &cases, true).await;
}

// ttl_test.go (without a client, leases are ignored), plus the lease bounds
#[tokio::test]
async fn ttl() {
    struct T {
        name: &'static str,
        lease: i64,
        service_ttl: u32,
        min: u32,
        max: u32,
        want: u32,
    }
    let tests = [
        T {
            name: "no client, large lease ID falls back to default",
            lease: 0x12345678FFFFFFFF,
            service_ttl: 0,
            min: 0,
            max: 0,
            want: DEFAULT_TTL,
        },
        T {
            name: "no client, zero lease ID falls back to default",
            lease: 0,
            service_ttl: 0,
            min: 0,
            max: 0,
            want: DEFAULT_TTL,
        },
        T {
            name: "no client, service TTL takes precedence",
            lease: 120,
            service_ttl: 300,
            min: 0,
            max: 0,
            want: 300,
        },
        T {
            name: "no client, smaller service TTL wins",
            lease: 600,
            service_ttl: 120,
            min: 0,
            max: 0,
            want: 120,
        },
        T {
            name: "custom bounds, no client",
            lease: 0x12345678FFFFFFFF,
            service_ttl: 0,
            min: 60,
            max: 3600,
            want: DEFAULT_TTL,
        },
        T {
            name: "zero service TTL with lease ID",
            lease: 600,
            service_ttl: 0,
            min: 0,
            max: 0,
            want: DEFAULT_TTL,
        },
    ];
    for t in &tests {
        let mut e = plugin(Arc::new(MemKv::default()));
        (e.min_lease_ttl, e.max_lease_ttl) = (t.min, t.max);
        assert_eq!(e.ttl(t.lease, t.service_ttl).await, t.want, "{}", t.name);
    }

    // with leases: (lease TTL, service TTL, min, max) -> TTL
    let kv = MemKv {
        leases: [(1, 10), (2, 600), (3, 100_000), (4, -1)].into(),
        ..Default::default()
    };
    let mut e = plugin(Arc::new(kv));
    for (lease, serv, min, max, want) in [
        (1, 0, 0, 0, 30),    // clamped to the default minimum
        (1, 0, 5, 0, 10),    // within custom bounds
        (2, 0, 0, 0, 600),   // the lease's TTL
        (2, 120, 0, 0, 120), // the smaller one
        (2, 0, 0, 300, 300), // clamped to the maximum
        (3, 0, 0, 0, 86400), // clamped to the default maximum
        (4, 0, 0, 0, 300),   // expired lease: the default
        (99, 45, 0, 0, 45),  // unknown lease: the service's
    ] {
        (e.min_lease_ttl, e.max_lease_ttl) = (min, max);
        assert_eq!(
            e.ttl(lease, serv).await,
            want,
            "lease {lease} service {serv} bounds {min}-{max}"
        );
    }
}

#[tokio::test]
async fn leases_in_answers() {
    let kv = mem(&[host("a.skydns.test.", "10.0.0.1")]);
    let kv = Arc::new(MemKv {
        keys: Mutex::new(kv.keys.lock().unwrap().clone()),
        leases: [(7, 3600)].into(),
    });
    kv.keys.lock().unwrap().get_mut("/skydns/test/skydns/a").unwrap().1 = 7;
    let mut e = plugin(kv);
    e.max_lease_ttl = 60;
    let cases = [Case {
        qname: "a.skydns.test.",
        answer: &["a.skydns.test. 60 IN A 10.0.0.1"],
        ..CASE
    }];
    run(&handler(e), &cases, true).await;
}

#[tokio::test]
async fn errors_and_fallthrough() {
    let kv = mem(&[]);
    kv.keys
        .lock()
        .unwrap()
        .insert("/skydns/test/skydns/bad".into(), (b"{\"port\":\"x\"}".to_vec(), 0));
    // a record that is not valid JSON: SERVFAIL with the SOA, and an error
    let h = handler(plugin(kv.clone()));
    let (rc, w) = serve(&h, &query("bad.skydns.test.", RecordType::A, "10.240.0.1:40212")).await;
    let m = w.msg().unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(m.authorities.len(), 1);
    assert!(rc.unwrap_err().msg.starts_with("/skydns/test/skydns/bad: "));

    // fallthrough: NXDOMAIN goes to the next plugin
    let mut e = plugin(kv);
    e.fall.set_zones_from_args(&[]);
    let h = EtcdHandler {
        e: Arc::new(e),
        next: reply(|req| req.error_reply(ResponseCode::Refused)),
    };
    let (_, w) = serve(&h, &query("nx.skydns.test.", RecordType::A, "10.240.0.1:40212")).await;
    assert_eq!(w.msg().unwrap().metadata.response_code, ResponseCode::Refused);
    // any SOA query in the zone gets the zone's SOA
    let (_, w) = serve(&h, &query("nx.skydns.test.", RecordType::SOA, "10.240.0.1:40212")).await;
    let m = w.msg().unwrap();
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].name.to_ascii(), "skydns.test.");
}

// setup_test.go
#[test]
fn setup() {
    struct T {
        input: &'static str,
        should_err: bool,
        path: &'static str,
        endpoints: &'static [&'static str],
        err: &'static str,
        username: &'static str,
        password: &'static str,
    }
    let tests = [
        T {
            input: "etcd",
            should_err: false,
            path: "skydns",
            endpoints: &["http://localhost:2379"],
            err: "",
            username: "",
            password: "",
        },
        T {
            input: "etcd {\n\tendpoint http://localhost:2379 http://localhost:3379 http://localhost:4379\n}",
            should_err: false,
            path: "skydns",
            endpoints: &[
                "http://localhost:2379",
                "http://localhost:3379",
                "http://localhost:4379",
            ],
            err: "",
            username: "",
            password: "",
        },
        T {
            input: "etcd skydns.local {\n\tendpoint localhost:300\n}\n",
            should_err: false,
            path: "skydns",
            endpoints: &["localhost:300"],
            err: "",
            username: "",
            password: "",
        },
        T {
            input: "etcd {\n\tendpoints localhost:300\n}\n",
            should_err: true,
            path: "",
            endpoints: &[""],
            err: "unknown property 'endpoints'",
            username: "",
            password: "",
        },
        T {
            input: "etcd {\n\tendpoint http://localhost:2379\n\tcredentials username password\n}\n",
            should_err: false,
            path: "skydns",
            endpoints: &["http://localhost:2379"],
            err: "",
            username: "username",
            password: "password",
        },
        T {
            input: "etcd {\n\tendpoint http://localhost:2379\n\tcredentials username\n}\n",
            should_err: true,
            path: "skydns",
            endpoints: &["http://localhost:2379"],
            err: "credentials requires 2 arguments",
            username: "username",
            password: "",
        },
        T {
            input: "etcd {\n\tendpoint http://localhost:2379\n\tcredentials\n}\n",
            should_err: true,
            path: "skydns",
            endpoints: &["http://localhost:2379"],
            err: "Wrong argument count",
            username: "",
            password: "",
        },
        T {
            input: "etcd {\n\tendpoint http://localhost:2379\n\tmin-lease-ttl 60\n}\n",
            should_err: false,
            path: "skydns",
            endpoints: &["http://localhost:2379"],
            err: "",
            username: "",
            password: "",
        },
        T {
            input: "etcd {\n\tendpoint http://localhost:2379\n\tmax-lease-ttl 1h\n}\n",
            should_err: false,
            path: "skydns",
            endpoints: &["http://localhost:2379"],
            err: "",
            username: "",
            password: "",
        },
        T {
            input: "etcd {\n\tendpoint http://localhost:2379\n\tmin-lease-ttl 120\n\tmax-lease-ttl 7200\n}\n",
            should_err: false,
            path: "skydns",
            endpoints: &["http://localhost:2379"],
            err: "",
            username: "",
            password: "",
        },
    ];
    for (i, t) in tests.iter().enumerate() {
        let r = with_controller("etcd", t.input, parse);
        match (r, t.should_err) {
            (Ok(_), true) => panic!("test {i}: expected an error for {}", t.input),
            (Err(e), true) => {
                assert!(e.to_string().contains(t.err), "test {i}: {e}, want {}", t.err);
            }
            (Err(e), false) => panic!("test {i}: unexpected error {e} for {}", t.input),
            (Ok(e), false) => {
                assert_eq!(e.path_prefix, t.path, "test {i}");
                assert_eq!(e.endpoints, t.endpoints, "test {i}");
                assert_eq!(
                    (e.username.as_str(), e.password.as_str()),
                    (t.username, t.password),
                    "test {i}"
                );
                if t.input.contains("min-lease-ttl 60") {
                    assert_eq!(e.min_lease_ttl, 60);
                }
                if t.input.contains("max-lease-ttl 1h") {
                    assert_eq!(e.max_lease_ttl, 3600);
                }
                if t.input.contains("min-lease-ttl 120") {
                    assert_eq!((e.min_lease_ttl, e.max_lease_ttl), (120, 7200));
                }
            }
        }
    }

    // more errors and defaults
    let e = with_controller("etcd", "etcd", parse).unwrap();
    assert_eq!(e.zones, vec!["."]);
    assert_eq!((e.min_lease_ttl, e.max_lease_ttl), (30, 86400));
    for (input, want) in [
        ("etcd {\n\tpath\n}", "Wrong argument count"),
        ("etcd {\n\tendpoint\n}", "Wrong argument count"),
        (
            "etcd {\n\tmin-lease-ttl 1y\n}",
            "invalid min-lease-ttl value: invalid TTL format",
        ),
        (
            "etcd {\n\tmax-lease-ttl -5s\n}",
            "invalid max-lease-ttl value: TTL must be non-negative",
        ),
        ("etcd {\n\tmin-lease-ttl\n}", "Wrong argument count"),
        // stubzones takes no arguments: the next token is a property
        ("etcd {\n\tstubzones foo\n}", "unknown property 'foo'"),
        ("etcd {\n\ttls a b c d\n}", "maximum of three arguments"),
        ("etcd {\n\ttls /nonexistent/ca.pem\n}", "/nonexistent/ca.pem"),
    ] {
        let err = with_controller("etcd", input, parse)
            .err()
            .unwrap_or_else(|| panic!("{input}"));
        assert!(err.to_string().contains(want), "{input}: {err}");
    }
    let e = with_controller(
        "etcd",
        "etcd skydns.local. other.org {\n\tstubzones\n\tupstream 8.8.8.8\n\tdebug\n\tpath /skydns\n\tfallthrough in-addr.arpa\n}",
        parse,
    )
    .unwrap();
    assert_eq!(e.zones, vec!["skydns.local.", "other.org."]);
    assert_eq!(e.path_prefix, "/skydns");
    assert_eq!(e.fall.zones, vec!["in-addr.arpa."]);
}

#[test]
fn setup_no_apex_fallback() {
    for (input, want) in [
        ("etcd", Some(false)),
        ("etcd {\nno_apex_fallback\n}", Some(true)),
        ("etcd {\nno_apex_fallback unexpected\n}", None),
    ] {
        let r = with_controller("etcd", input, parse);
        match want {
            Some(w) => assert_eq!(r.unwrap().no_apex_fallback, w, "{input}"),
            None => assert!(r.is_err(), "{input}"),
        }
    }
}

#[test]
fn ttl_parsing() {
    for (input, want) in [
        ("30", Some(30)),
        ("300", Some(300)),
        ("30s", Some(30)),
        ("90s", Some(90)),
        ("5m", Some(300)),
        ("1m", Some(60)),
        ("1h", Some(3600)),
        ("2h", Some(7200)),
        ("2h30m", Some(9000)),
        ("1h30m45s", Some(5445)),
        ("0", Some(0)),
        ("0s", Some(0)),
        ("", Some(0)),
        ("-30s", None),
        ("abc", None),
        ("1y", None),
        // more of Go's ParseDuration
        ("1.5m", Some(90)),
        ("1500ms", Some(1)),
        ("+10s", Some(10)),
        ("10", Some(10)),
        ("4294967296", None),
        ("h", None),
        (".s", None),
    ] {
        assert_eq!(parse_ttl(input).ok(), want, "{input:?}");
    }
}
