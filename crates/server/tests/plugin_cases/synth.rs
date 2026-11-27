//! Plugins that synthesize answers from other answers: dns64.

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::{RData, RecordType};
use serde_json::Value;

use crate::harness::*;

/// A next plugin that answers AAAA queries with `aaaa` and A queries
/// with `a` (the Go tests' fakeHandler and fakeUpstream: KernDNS's
/// upstream is the server itself, so the A lookup reaches the next plugin).
fn by_type(tag: &str, aaaa: Value, a: Value) {
    set_reply(tag, move |req| {
        let v = if req.qtype() == RecordType::A { &a } else { &aaaa };
        if v.is_null() {
            return (None, ResponseCode::ServFail);
        }
        let mut m = msg_from(v);
        if m.queries.is_empty() {
            m.queries = req.msg.queries.clone();
        }
        m.metadata.id = req.msg.metadata.id;
        let rc = m.metadata.response_code;
        (Some(m), rc)
    });
}

fn synthesized(m: &kerndns_core::proto::op::Message) -> bool {
    m.answers
        .iter()
        .any(|a| matches!(&a.data, RData::AAAA(ip) if ip.0.segments()[..2] == [0x64, 0xff9b]))
}

/// siit_test.go: TestSIIT, the whole response like TestDNS64 (the A query
/// goes to the next plugin, the AAAA lookup through the server).
pub async fn siit(r: &mut Run) {
    let id = "TestSIIT/cases";
    for (row, v) in r.rows(id) {
        let tag = format!("siit-{row}");
        // by_type answers A with its second and AAAA with its first argument
        by_type(&tag, v["aResp"].clone(), v["initResp"].clone());
        let s = Server::new(&format!(
            ".:53 {{\n siit {{\n  ipv6_prefix 64:ff9b::/96\n  eam 10.0.0.1 64:dead::1\n  eam 10.0.0.2 64:dead::2\n }}\n nomad {tag} reply\n}}"
        ))
        .await;
        let served = s.serve_from(msg_from(&v["req"]), "[::1]:40212").await;
        let res = (|| {
            let m = served.written().ok_or("no response")?;
            if served.rcode != Some(m.metadata.response_code) {
                return Err(format!(
                    "ServeDNS should return real result code {:?} != {}",
                    served.rcode, m.metadata.response_code
                ));
            }
            same_msg(&msg_from(&v["resp"]), m)
        })();
        r.check(id, &row, res);
    }
}

/// dns64_test.go.
pub async fn dns64(r: &mut Run) {
    // TestDNS64: the whole response must be what CoreDNS writes
    let id = "TestDNS64/cases";
    for (row, v) in r.rows(id) {
        let tag = format!("dns64-{row}");
        by_type(&tag, v["initResp"].clone(), v["aResp"].clone());
        let s = Server::new(&format!(".:53 {{\n dns64 64:ff9b::/96\n nomad {tag} reply\n}}")).await;
        let served = s.serve_from(msg_from(&v["req"]), "[::1]:40212").await;
        let res = (|| {
            let m = served.written().ok_or("no response")?;
            if served.rcode != Some(m.metadata.response_code) {
                return Err(format!(
                    "ServeDNS should return real result code {:?} != {}",
                    served.rcode, m.metadata.response_code
                ));
            }
            same_msg(&msg_from(&v["resp"]), m)
        })();
        r.check(id, &row, res);
    }

    // TestRequestShouldIntercept: intercepted requests get a synthesized
    // AAAA when the next plugin has none
    let id = "TestRequestShouldIntercept/tests";
    for (row, v) in r.rows(id) {
        let tag = format!("dns64-intercept-{row}");
        let nodata =
            serde_json::json!({"MsgHdr": {"Response": true}, "Ns": ["example.com. 3600 IN SOA foo. bar. 1 1 1 1 1"]});
        let a = serde_json::json!({"MsgHdr": {"Response": true}, "Answer": ["example.com. 3600 IN A 192.0.2.1"]});
        by_type(&tag, nodata, a);
        let allow = if v["allowIpv4"].as_bool() == Some(true) {
            " {\n  allow_ipv4\n }"
        } else {
            ""
        };
        let s = Server::new(&format!(".:53 {{\n dns64{allow}\n nomad {tag} reply\n}}")).await;
        let ip = str_of(&v["remoteIP"]);
        let remote = if ip.contains(':') {
            format!("[{ip}]:40212")
        } else {
            format!("{ip}:40212")
        };
        let served = s.serve_from(msg_from(&v["msg"]), &remote).await;
        let got = served.written().is_some_and(synthesized);
        let want = v["want"].as_bool().unwrap();
        r.check(
            id,
            &row,
            if got == want {
                Ok(())
            } else {
                Err(format!("Expected {want}, but got {got}"))
            },
        );
    }

    // TestResponseShould: whether a response gets translated
    let id = "TestResponseShould/tests";
    for (row, v) in r.rows(id) {
        let tag = format!("dns64-should-{row}");
        let mut resp = v["resp"].clone();
        resp["MsgHdr"]["Response"] = true.into();
        let a = serde_json::json!({"MsgHdr": {"Response": true}, "Answer": ["example.com. 3600 IN A 192.0.2.1"]});
        by_type(&tag, resp, a);
        let all = if v["translateAll"].as_bool() == Some(true) {
            " {\n  translate_all\n }"
        } else {
            ""
        };
        let s = Server::new(&format!(".:53 {{\n dns64{all}\n nomad {tag} reply\n}}")).await;
        let served = s.serve_from(question("example.com.", 28), "[::1]:40212").await;
        let got = served.written().is_some_and(synthesized);
        let want = v["expected"].as_bool().unwrap();
        r.check(
            id,
            &row,
            if got == want {
                Ok(())
            } else {
                Err(format!("Expected {want}, but got {got}"))
            },
        );
    }
}
