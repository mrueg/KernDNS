//! plugin/rewrite: rule parsing tables and the name rewriting tables.
//!
//! The Go tests build `Rewrite{Rules, RevertPolicy: NoRevertPolicy()}` and
//! read the rewritten question from the response that `msgPrinter` (the
//! next handler) echoes. Through a Corefile the reverter always restores
//! the question, so the stand-in next plugin records the question it got:
//! the same value, observed where the Go test's next handler sees it.

use std::sync::{Arc, Mutex};

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::rdata::A;
use kerndns_core::proto::rr::{RData, Record};

use crate::harness::*;

/// `msgPrinter`: echo the request with an A record for its name; returns
/// the questions seen.
fn printer(tag: &str) -> Arc<Mutex<Vec<(String, u16, u16)>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    set_reply(tag, move |req| {
        let q = &req.msg.queries[0];
        s.lock().unwrap().push((
            q.name().to_string(),
            u16::from(q.query_type()),
            u16::from(q.query_class()),
        ));
        let mut m = req.msg.clone();
        m.metadata.message_type = kerndns_core::proto::op::MessageType::Response;
        if m.answers.is_empty() {
            m.answers = vec![Record::from_rdata(q.name().clone(), 5, RData::A(A::new(10, 0, 0, 1)))];
        }
        (Some(m), ResponseCode::NoError)
    });
    seen
}

fn args(v: &serde_json::Value) -> String {
    v.as_array()
        .into_iter()
        .flatten()
        .map(str_of)
        .collect::<Vec<_>>()
        .join(" ")
}

pub async fn drive(r: &mut Run) {
    // rule parsing: newRule(args...), newNameRule(next, args...), ...
    let o = SetupOpts {
        args_of: Some("rewrite"),
        ..Default::default()
    };
    setup_rows_with(r, "TestNewRule/tests", "args", "shouldError", None, &o);
    for (id, kind) in [
        ("TestNewNameRule/tests", "name"),
        ("TestNewTTLRule/tests", "ttl"),
        ("TestNewRCodeRule/tests", "rcode"),
    ] {
        for (row, v) in r.rows(id) {
            let text = format!("rewrite {} {kind} {}", str_of(&v["next"]), args(&v["args"]));
            let res = setup(&text);
            let want_fail = v["expectedFail"].as_bool().unwrap_or(false);
            let out = match (res, want_fail) {
                (Ok(()), false) | (Err(_), true) => Ok(()),
                (Ok(()), true) => Err(format!("expected {text:?} to fail")),
                (Err(e), false) => Err(format!("{text:?}: {e}")),
            };
            r.check(id, &row, out);
        }
    }

    // name rewriting: the question the next plugin gets, and for the
    // `answer` variants the owner name in the response
    for id in [
        "TestRewriteNamePrefixSuffix/tests",
        "TestRewriteNameNoRewrite/tests",
        "TestRewriteNamePrefixSuffixNoAutoAnswer/tests",
        "TestRewriteNamePrefixSuffixAutoAnswer/tests",
        "TestRewriteNameExactAnswer/tests",
        "TestRewriteNameRegexAnswer/tests",
    ] {
        for (row, v) in r.rows(id) {
            let tag = format!("rewrite-{id}-{row}");
            let seen = printer(&tag);
            let s = Server::new(&format!(
                ".:53 {{\n rewrite {} name {}\n nomad {tag} reply\n}}",
                str_of(&v["next"]),
                args(&v["args"])
            ))
            .await;
            let served = s.serve(question(str_of(&v["question"]), 1)).await;
            let res = (|| {
                let m = served.written().ok_or("no response")?;
                let got = seen.lock().unwrap().first().map(|q| q.0.clone()).unwrap_or_default();
                // with a `rewrite` field the question is the rewrite and
                // `expected` the answer's owner; without, `expected` is the
                // rewritten question
                let (want_q, want_answer) = match v.get("rewrite") {
                    Some(rw) => (str_of(rw), Some(str_of(&v["expected"]))),
                    None => (str_of(&v["expected"]), None),
                };
                if got != want_q {
                    return Err(format!("Expected rewrite to {want_q}, got {got}"));
                }
                if let Some(w) = want_answer {
                    let a = m.answers.first().map(|a| a.name.to_string()).unwrap_or_default();
                    if a != w {
                        return Err(format!("Expected answer rewrite to {w}, got {a}"));
                    }
                }
                Ok(())
            })();
            r.check(id, &row, res);
        }
    }

    // TestRewrite: the rules are built in the test; here as a Corefile
    let id = "TestRewrite/tests";
    let tag = "rewrite-rules";
    let seen = printer(tag);
    let s = Server::new(&format!(
        r".:53 {{
 rewrite stop name from.nl. to.nl.
 rewrite stop name regex (core)\.(dns)\.(rocks)\.(nl) {{2}}.{{1}}.{{3}}.{{4}} answer name (dns)\.(core)\.(rocks)\.(nl) {{2}}.{{1}}.{{3}}.{{4}}
 rewrite stop name exact from.exact.nl. to.nl.
 rewrite stop name prefix prefix to
 rewrite stop name suffix .suffix. .nl.
 rewrite stop name substring from.substring to
 rewrite stop name regex (f.*m)\.regex\.(nl) to.{{2}}
 rewrite continue name regex consul\.(rocks) core.dns.{{1}}
 rewrite stop name core.dns.rocks to.nl.
 rewrite continue class HS CH
 rewrite stop class CH IN
 rewrite stop type ANY HINFO
 chaos
 nomad {tag} reply
}}"
    ))
    .await;
    for (row, v) in r.rows(id) {
        seen.lock().unwrap().clear();
        let mut m = question(str_of(&v["from"]), u16_of(&v["fromT"]));
        m.queries[0].set_query_class(kerndns_core::proto::rr::DNSClass::from(u16_of(&v["fromC"])));
        s.serve(m).await;
        let got = seen.lock().unwrap().first().cloned();
        let want = (str_of(&v["to"]).to_string(), u16_of(&v["toT"]), u16_of(&v["toC"]));
        let res = match got {
            Some(g) if g == want => Ok(()),
            g => Err(format!("next got {g:?}, expected {want:?}")),
        };
        r.check(id, &row, res);
    }
}
