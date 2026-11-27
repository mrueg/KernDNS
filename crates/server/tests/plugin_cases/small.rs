//! Plugins with one or two small tables: any, chaos, whoami, minimal.

use kerndns_core::Protocol;
use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::{DNSClass, RData};

use crate::harness::*;

/// any_test.go: TestAnyNonANYQuery (non-ANY queries go to the next plugin).
pub async fn any(r: &mut Run) {
    let id = "TestAnyNonANYQuery/tests";
    for (row, v) in r.rows(id) {
        let tag = format!("any-{row}");
        let s = Server::new(&format!(".:53 {{\n any\n nomad {tag} rcode NOERROR\n}}")).await;
        s.serve(question("example.org.", u16_of(&v["qtype"]))).await;
        let res = if next_calls(&tag) == 1 {
            Ok(())
        } else {
            Err("Expected Next handler to be called for non-ANY query".into())
        };
        r.check(id, &row, res);
    }
}

/// chaos_test.go: TestChaos (CH TXT queries) and the setup table.
pub async fn chaos(r: &mut Run) {
    let id = "TestChaos/tests";
    let version = r.string("version").to_string();
    for (row, v) in r.rows(id) {
        let tag = format!("chaos-{row}");
        let s = Server::new(&format!(
            ".:53 {{\n chaos {version} \"Miek Gieben\"\n nomad {tag} rcode NOERROR\n}}"
        ))
        .await;
        let qtype = match u16_of(&v["qtype"]) {
            0 => 16,
            t => t,
        };
        let mut m = question(str_of(&v["qname"]), qtype);
        m.queries[0].set_query_class(DNSClass::CH);
        let served = s.serve(m).await;
        let res = (|| {
            let code = served.code().ok_or("no rcode")?;
            if code != u16_of(&v["expectedCode"]) {
                return Err(format!("Expected status code {}, but got {code}", v["expectedCode"]));
            }
            let want = str_of(&v["expectedReply"]);
            if !want.is_empty() {
                let m = served.written().ok_or("no response")?;
                let got = match m.answers.first().map(|a| &a.data) {
                    Some(RData::TXT(t)) => String::from_utf8_lossy(&t.txt_data[0]).into_owned(),
                    other => return Err(format!("no TXT answer: {other:?}")),
                };
                if got != want {
                    return Err(format!("Expected answer {want}, but got {got}"));
                }
            }
            Ok(())
        })();
        r.check(id, &row, res);
    }
    setup_rows(
        r,
        "TestSetupChaos/tests",
        "input",
        "shouldErr",
        Some("expectedErrContent"),
    );
}

/// whoami_test.go: TestWhoami (owner names of the additional section).
pub async fn whoami(r: &mut Run) {
    let id = "TestWhoami/tests";
    for (row, v) in r.rows(id) {
        let mut s = Server::new(".:53 {\n whoami\n}").await;
        // test.ResponseWriter is a UDP writer
        s.proto = Protocol::Udp;
        // "2003::1/64" isn't an address; the Go writer ends up without
        // one, which only the record data shows
        let remote = if str_of(&v["remote"]).is_empty() {
            REMOTE
        } else {
            "[2003::1]:40212"
        };
        let served = s
            .serve_from(question(str_of(&v["qname"]), u16_of(&v["qtype"])), remote)
            .await;
        let res = (|| {
            if served.code() != Some(u16_of(&v["expectedCode"])) {
                return Err(format!(
                    "Expected status code {}, got {:?}",
                    v["expectedCode"], served.rcode
                ));
            }
            let m = served.written().ok_or("no response")?;
            for (i, want) in v["expectedReply"].as_array().into_iter().flatten().enumerate() {
                let got = m.additionals.get(i).map(|r| r.name.to_string()).unwrap_or_default();
                if got != str_of(want) {
                    return Err(format!("Expected answer {want}, but got {got}"));
                }
            }
            Ok(())
        })();
        r.check(id, &row, res);
    }
}

/// header_test.go: a rule on one flag, the next plugin echoes the query
/// as the response; setup_test.go.
pub async fn header(r: &mut Run) {
    for (id, rules, selector) in [
        ("TestHeaderResponseRules/tests", "ResponseRules", "response"),
        ("TestHeaderQueryRules/tests", "QueryRules", "query"),
    ] {
        for (row, v) in r.rows(id) {
            let rule = &v["handler"][rules][0];
            let flag = str_of(&rule["Flag"]).to_string();
            let state = rule["State"].as_bool().unwrap();
            let tag = format!("header-{selector}-{row}");
            set_reply(&tag, |req| {
                let mut m = req.msg.clone();
                m.metadata.message_type = kerndns_core::proto::op::MessageType::Response;
                (Some(m), ResponseCode::NoError)
            });
            let s = Server::new(&format!(
                ".:53 {{\n header {{\n  {selector} {} {flag}\n }}\n nomad {tag} reply\n}}",
                if state { "set" } else { "clear" }
            ))
            .await;
            let mut q = question("example.org.", 1);
            // new(dns.Msg): no flags set
            q.metadata.recursion_desired = false;
            let served = s.serve(q).await;
            let res = (|| {
                let m = served.written().ok_or("no response")?;
                let got = match flag.as_str() {
                    "ra" => m.metadata.recursion_available,
                    "rd" => m.metadata.recursion_desired,
                    "aa" => m.metadata.authoritative,
                    f => return Err(format!("flag {f}")),
                };
                if got != v["expected"].as_bool().unwrap() {
                    return Err(format!("Expected flag state={}, but got {got}", v["expected"]));
                }
                Ok(())
            })();
            r.check(id, &row, res);
        }
    }
}

/// local_test.go: TestLocal (rcode, owner name and type of the first answer
/// and authority record).
pub async fn local(r: &mut Run) {
    let id = "testcases";
    let s = Server::new(".:53 {\n local\n nomad local rcode NOERROR\n}").await;
    for (row, v) in r.rows(id) {
        let served = s.serve(question(str_of(&v["question"]), u16_of(&v["qtype"]))).await;
        let res = (|| {
            let m = served.written().ok_or("no response")?;
            if u16::from(m.metadata.response_code) != u16_of(&v["rcode"]) {
                return Err(format!(
                    "expected rcode {}, got {}",
                    v["rcode"], m.metadata.response_code
                ));
            }
            for (sec, wv, got) in [
                ("answer", &v["answer"], &m.answers),
                ("authority", &v["ns"], &m.authorities),
            ] {
                match (wv.is_null(), got.first()) {
                    (true, Some(g)) => return Err(format!("expected no {sec} RR, got {g}")),
                    (true, None) => {}
                    (false, None) => return Err(format!("expected a {sec} RR")),
                    (false, Some(g)) => {
                        let w = match want(wv)? {
                            Want::Rr(w) => w,
                            Want::Opt { .. } => return Err("OPT".into()),
                        };
                        if w.record_type() != g.record_type() || w.name.to_string() != g.name.to_string() {
                            return Err(format!("expected {sec} {} {}, got {g}", w.name, w.record_type()));
                        }
                    }
                }
            }
            Ok(())
        })();
        r.check(id, &row, res);
    }
}

/// minimal_test.go: TestMinimizeResponse (a next plugin writes the original
/// response, `minimal` must leave the minimal one).
pub async fn minimal(r: &mut Run) {
    let id = "TestMinimizeResponse/tests";
    for (row, v) in r.rows(id) {
        let tag = format!("minimal-{row}");
        let orig = v["original"].clone();
        set_reply(&tag, move |req| {
            let mut m = req.reply();
            m.answers = records(&orig["Answer"]);
            m.authorities = records(&orig["Ns"]);
            m.additionals = records(&orig["Extra"]);
            let rc = orig["Rcode"].as_u64().unwrap_or(0) as u8;
            m.metadata.response_code = ResponseCode::from(0, rc);
            (Some(m), ResponseCode::NoError)
        });
        let s = Server::new(&format!(".:53 {{\n minimal\n nomad {tag} reply\n}}")).await;
        let served = s.serve(question("example.com", 1)).await;
        let res = (|| {
            let m = served.written().ok_or("no response")?;
            for (name, want, got) in [
                ("Answer", &v["minimal"]["Answer"], &m.answers),
                ("Ns", &v["minimal"]["Ns"], &m.authorities),
                ("Extra", &v["minimal"]["Extra"], &m.additionals),
            ] {
                let want: Vec<String> = records(want).iter().map(|r| r.to_string()).collect();
                let got: Vec<String> = got.iter().map(|r| r.to_string()).collect();
                if want != got {
                    return Err(format!("{name}: expected {want:?}, got {got:?}"));
                }
            }
            Ok(())
        })();
        r.check(id, &row, res);
    }
}
