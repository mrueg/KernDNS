//! plugin/hosts: hosts_test.go.

use crate::harness::*;
use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::RData;
use serde_json::Value;

async fn hosts_server(r: &Run, opts: &[&str], tag: &str, next_rcode: &str) -> Server {
    let dir = TempDir::new();
    let path = dir.write("hosts", r.string("hostsExample"));
    let opts: Vec<&str> = opts.iter().copied().filter(|o| !o.is_empty()).collect();
    let block = if opts.is_empty() {
        String::new()
    } else {
        format!(" {{\n  {}\n }}", opts.join("\n  "))
    };
    Server::new(&format!(
        ".:53 {{\n hosts {path} .{block}\n nomad {tag} rcode {next_rcode}\n}}"
    ))
    .await
    .with_dir(dir)
}

/// `hosts FILE` with origin `.` (`testHostsfile`).
async fn file_server(text: &str) -> Server {
    let dir = TempDir::new();
    let path = dir.write("hosts", text);
    Server::new(&format!(
        ".:53 {{\n hosts {path}\n nomad hosts-static rcode NXDOMAIN\n}}"
    ))
    .await
    .with_dir(dir)
}

/// The addresses (A or AAAA) or names (PTR) the plugin answers, as text.
async fn answers(s: &Server, name: &str, t: u16) -> Vec<String> {
    let served = s.serve(question(name, t)).await;
    let Some(m) = served.written() else {
        return Vec::new();
    };
    m.answers
        .iter()
        .map(|a| match &a.data {
            RData::A(ip) => ip.to_string(),
            RData::AAAA(ip) => ip.to_string(),
            RData::PTR(p) => p.0.to_string(),
            d => format!("{d}"),
        })
        .collect()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|s| str_of(s).to_string()).collect())
        .unwrap_or_default()
}

/// `testStaticHost`: the name as is, normalized, lower- and uppercased,
/// for A and AAAA.
async fn static_host(s: &Server, ent: &Value) -> Result<(), String> {
    let name = str_of(&ent["in"]);
    let (v4, v6) = (strings(&ent["v4"]), strings(&ent["v6"]));
    for n in [name.to_string(), name.to_ascii_lowercase(), name.to_ascii_uppercase()] {
        for (t, want) in [(1, &v4), (28, &v6)] {
            let got = answers(s, &n, t).await;
            let want: Vec<String> = want
                .iter()
                .map(|w| w.parse::<std::net::IpAddr>().unwrap().to_string())
                .collect();
            if got != want {
                return Err(format!("lookup {n} type {t} = {got:?}; want {want:?}"));
            }
        }
    }
    Ok(())
}

/// `in-addr.arpa`/`ip6.arpa` name of an address.
fn reverse(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>().unwrap() {
        std::net::IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        std::net::IpAddr::V6(a) => {
            let mut s = String::new();
            for b in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s + "ip6.arpa."
        }
    }
}

pub async fn drive(r: &mut Run) {
    // TestLookupStaticHost
    let id = "lookupStaticHostTests";
    for (row, v) in r.rows(id) {
        let s = file_server(str_of(&v["file"])).await;
        for (i, ent) in v["ents"].as_array().unwrap().iter().enumerate() {
            let res = static_host(&s, ent).await;
            r.check(id, &format!("{row}.{i}"), res);
        }
    }
    // TestLookupWildcardHost
    let id = "TestLookupWildcardHost/tests";
    let s = file_server(r.string("TestLookupWildcardHost/hosts")).await;
    for (row, ent) in r.rows(id) {
        let res = static_host(&s, &ent).await;
        r.check(id, &row, res);
    }
    // TestLookupStaticAddr: PTR answers, names normalized
    let id = "lookupStaticAddrTests";
    for (row, v) in r.rows(id) {
        let s = file_server(str_of(&v["file"])).await;
        for (i, ent) in v["ents"].as_array().unwrap().iter().enumerate() {
            let want: Vec<String> = strings(&ent["out"]).iter().map(|n| n.to_ascii_lowercase()).collect();
            let got = answers(&s, &reverse(str_of(&ent["in"])), 12).await;
            let res = if got == want {
                Ok(())
            } else {
                Err(format!(
                    "lookupStaticAddr({}) = {got:?}; want {want:?}",
                    str_of(&ent["in"])
                ))
            };
            r.check(id, &format!("{row}.{i}"), res);
        }
    }
    setup_rows(r, "TestHostsParse/tests", "inputFileRules", "shouldErr", None);
    setup_rows(r, "TestHostsInlineParse/tests", "inputFileRules", "shouldErr", None);
    setup_rows(
        r,
        "TestHostsParseFallthroughUnsupported/tests",
        "input",
        "shouldErr",
        None,
    );

    // TestLookupA: fallthrough only for fallthrough-example.org., next
    // answers NXDOMAIN without writing
    let id = "hostsTestCases";
    for (row, v) in r.rows(id) {
        let tc = Case::from(&v);
        let is_fall = tc.qname == "fallthrough-example.org.";
        let tag = format!("hosts-a-{row}");
        let s = hosts_server(r, &[if is_fall { "fallthrough" } else { "" }], &tag, "NXDOMAIN").await;
        let served = s.serve(tc.msg()).await;
        let res = (|| {
            if is_fall && served.code() != Some(tc.rcode) {
                return Err(format!("Expected rcode is {}, but got {:?}", tc.rcode, served.rcode));
            }
            // like the Go test, only a written response is checked
            match served.written() {
                Some(m) => sort_and_check(m, &tc),
                None => Ok(()),
            }
        })();
        r.check(id, &row, res);
    }

    // TestFallthroughUnsupportedType: TXT queries, next answers REFUSED
    let id = "TestFallthroughUnsupportedType/tests";
    for (row, v) in r.rows(id) {
        let tag = format!("hosts-unsupported-{row}");
        let fall = fallthrough(&v["fall"]);
        let unsupported = if v["unsupported"].as_bool() == Some(true) {
            "fallthrough_unsupported"
        } else {
            ""
        };
        let s = hosts_server(r, &[&fall, unsupported], &tag, "REFUSED").await;
        let served = s.serve(question(str_of(&v["qname"]), 16)).await;
        let called = next_calls(&tag) > 0;
        let res = if v["expectFallthrough"].as_bool() == Some(true) {
            if called && served.rcode == Some(ResponseCode::Refused) && !served.wrote {
                Ok(())
            } else {
                Err(format!("expected fallthrough, got {:?} {:?}", served.rcode, served.msg))
            }
        } else {
            match served.written() {
                Some(m)
                    if served.rcode == Some(ResponseCode::NoError)
                        && m.metadata.authoritative
                        && m.answers.is_empty() =>
                {
                    Ok(())
                }
                _ => Err(format!(
                    "expected authoritative NODATA, got {:?} {:?}",
                    served.rcode, served.msg
                )),
            }
        };
        r.check(id, &row, res);
    }
}
