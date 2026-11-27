//! Plugins that wrap the next plugin: autopath, dnssec, nsid, erratic,
//! cache (setup tables).

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::rdata::SOA;
use kerndns_core::proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use kerndns_core::proto::rr::{Name, RData, Record};

use crate::harness::*;

/// autopath_test.go: search path example.org. example.com. com. and the
/// bare name; the next plugin answers b.example.org. NXDOMAIN, b.com. and
/// a.example.com. with an A record and anything else SERVFAIL without
/// writing (`nextHandler`).
pub async fn autopath(r: &mut Run) {
    let tag = "autopath";
    let default_a = r.string("defaultA").to_string();
    set_reply(tag, move |req| {
        let name = req.msg.queries[0].name().to_string();
        let mut m = req.reply();
        match name.as_str() {
            "b.example.org." => {
                m.metadata.response_code = ResponseCode::NXDomain;
                let soa = SOA::new(
                    Name::from_ascii("ns.example.org.").unwrap(),
                    Name::from_ascii("hostmaster.example.org.").unwrap(),
                    1,
                    3600,
                    600,
                    86400,
                    300,
                );
                m.authorities = vec![Record::from_rdata(
                    Name::from_ascii("example.org.").unwrap(),
                    3600,
                    RData::SOA(soa),
                )];
                (Some(m), ResponseCode::NXDomain)
            }
            "b.com." | "a.example.com." => {
                m.answers = records(&serde_json::json!([format!("{name}{default_a}")]));
                (Some(m), ResponseCode::NoError)
            }
            _ => (None, ResponseCode::ServFail),
        }
    });
    let dir = TempDir::new();
    let resolv = dir.write("resolv.conf", "search example.org example.com com\n");
    let s = Server::new(&format!(".:53 {{\n autopath {resolv}\n nomad {tag} reply\n}}"))
        .await
        .with_dir(dir);
    // TestAutoPath: Header and Section without sorting (the CNAME must
    // come first)
    let id = "autopathTestCases";
    for (row, v) in r.rows(id) {
        let tc = Case::from(&v);
        let served = s.serve(tc.msg()).await;
        let res = match served.written() {
            Some(m) => cname_order(m).and_then(|_| sort_and_check(m, &tc)),
            None => Err("no response".into()),
        };
        r.check(id, &row, res);
    }
    // TestAutoPathNoAnswer: the returned rcode is not a client write
    let id = "autopathNoAnswerTestCases";
    for (row, v) in r.rows(id) {
        let tc = Case::from(&v);
        let served = s.serve(tc.msg()).await;
        let res = match served.rcode {
            Some(rc) if !kerndns_core::client_write(rc) => Ok(()),
            rc => Err(format!("Expected no client write, got one for rcode {rc:?}")),
        };
        r.check(id, &row, res);
    }
}

/// dnssec handler_test.go: `dnssec miek.nl.` with the test key in front of
/// `file` (TestLookupZone) or of nothing (TestLookupDNSKEY: DNSKEY and DS
/// queries answered by dnssec itself); setup_test.go with the key files
/// the Go test writes into its working directory.
pub async fn dnssec(r: &mut Run) {
    let dir = TempDir::new();
    dir.write("Kmiek.nl.key", r.string("pubKey"));
    dir.write("Kmiek.nl.private", r.string("privKey"));
    let zone = dir.write("db.miek.nl", r.string("dbMiekNL"));
    let root = dir.0.to_string_lossy().into_owned();

    let s = Server::new(&format!(
        ".:53 {{\n root {root}\n dnssec miek.nl. {{\n  key file Kmiek.nl\n }}\n file {zone} miek.nl.\n nomad dnssec-zone error\n}}"
    ))
    .await;
    run_cases(r, "dnsTestCases", &s).await;

    let s = Server::new(&format!(
        ".:53 {{\n root {root}\n dnssec miek.nl. {{\n  key file Kmiek.nl\n }}\n nomad dnssec-key error\n}}"
    ))
    .await;
    let id = "dnssecTestCases";
    for (row, v) in r.rows(id) {
        let tc = Case::from(&v);
        let served = s.serve(tc.msg()).await;
        let res = (|| {
            let m = served.written().ok_or("no response")?;
            if !m.metadata.authoritative {
                return Err("Authoritative Answer should be true, got false".to_string());
            }
            sort_and_check(m, &tc)
        })();
        r.check(id, &row, res);
    }

    // TestSetupDnssec writes Kcluster.local.{key,private} and the ksk_ ones
    let keys = TempDir::new();
    keys.write("Kcluster.local.key", r.string("keypub"));
    keys.write("Kcluster.local.private", r.string("keypriv"));
    keys.write("ksk_Kcluster.local.key", r.string("kskpub"));
    keys.write("ksk_Kcluster.local.private", r.string("kskpriv"));
    let root = keys.0.to_string_lossy().into_owned();
    setup_rows_with(
        r,
        "TestSetupDnssec/tests",
        "input",
        "shouldErr",
        Some("expectedErrContent"),
        &SetupOpts {
            root: Some(&root),
            ..Default::default()
        },
    );
}

/// nsid_test.go: the NSID option in the response to a query that asks for
/// it, with whoami as the next plugin.
pub async fn nsid(r: &mut Run) {
    for id in ["TestNsid/tests", "TestNsidCache/tests"] {
        let s = Server::new(".:53 {\n nsid NSID\n whoami\n}").await;
        for (row, v) in r.rows(id) {
            let qtype = match u16_of(&v["qtype"]) {
                0 => 1,
                t => t,
            };
            let mut m = question(str_of(&v["qname"]), qtype);
            set_edns(&mut m, 4096, false);
            m.edns
                .as_mut()
                .unwrap()
                .options_mut()
                .insert(EdnsOption::Unknown(u16::from(EdnsCode::NSID), Vec::new()));
            let served = s.serve(m).await;
            let res = (|| {
                if served.code() != Some(u16_of(&v["expectedCode"])) {
                    return Err(format!(
                        "Expected status code {}, got {:?}",
                        v["expectedCode"], served.rcode
                    ));
                }
                let want = str_of(&v["expectedReply"]);
                if !want.is_empty() {
                    let m = served.written().ok_or("no response")?;
                    let got = match m.edns.as_ref().and_then(|e| e.option(EdnsCode::NSID)) {
                        Some(EdnsOption::Unknown(_, d)) => data_encoding::HEXLOWER.encode(d),
                        Some(EdnsOption::NSID(n)) => data_encoding::HEXLOWER.encode(n.as_ref()),
                        other => return Err(format!("no NSID option: {other:?}")),
                    };
                    if got != want {
                        return Err(format!("Expected answer {want}, but got {got}"));
                    }
                }
                Ok(())
            })();
            r.check(id, &row, res);
        }
    }
}

/// erratic setup_test.go: some inputs misspell the directive ("erraric");
/// `caddy.NewTestController` doesn't look at it, so neither does this.
fn erratic_setup(r: &mut Run) {
    let id = "TestParseErratic/tests";
    for (row, v) in r.rows(id) {
        let input = str_of(&v["input"]).replacen("erraric", "erratic", 1);
        let res = match (setup(&input), v["shouldErr"].as_bool().unwrap_or(false)) {
            (Ok(()), false) | (Err(_), true) => Ok(()),
            (Ok(()), true) => Err(format!("expected an error for {input:?}")),
            (Err(e), false) => Err(format!("unexpected error for {input:?}: {e}")),
        };
        r.check(id, &row, res);
    }
}

/// erratic_test.go: `drop 2` drops every second query (one plugin for the
/// whole table, as in Go); `truncate 2` likewise sets TC.
pub async fn erratic(r: &mut Run) {
    erratic_setup(r);
    let id = "TestErraticDrop/tests";
    let s = Server::new(".:53 {\n erratic {\n  drop 2\n }\n}").await;
    for (row, v) in r.rows(id) {
        let served = s.serve(question("example.org.", u16_of(&v["rrtype"]))).await;
        let res = if served.code() != Some(u16_of(&v["expectedCode"])) {
            Err(format!(
                "Expected status code {}, got {:?}",
                v["expectedCode"], served.rcode
            ))
        } else if v["drop"].as_bool() == Some(true) && served.wrote {
            Err("Expected dropped message".into())
        } else {
            Ok(())
        };
        r.check(id, &row, res);
    }
    let id = "TestErraticTruncate/tests";
    let s = Server::new(".:53 {\n erratic {\n  truncate 2\n }\n}").await;
    for (row, v) in r.rows(id) {
        let served = s.serve(question("example.org.", 1)).await;
        let res = (|| {
            if served.code() != Some(u16_of(&v["expectedCode"])) {
                return Err(format!(
                    "Expected status code {}, got {:?}",
                    v["expectedCode"], served.rcode
                ));
            }
            let m = served.written().ok_or("no response")?;
            let want = v["truncate"].as_bool() == Some(true);
            // like the Go test, only expected truncation is checked
            if want && !m.metadata.truncation {
                return Err(format!("Expected truncated={want}"));
            }
            Ok(())
        })();
        r.check(id, &row, res);
    }
}

/// cache: TestCacheInsertion (the next plugin answers with `in`, a second
/// query must come from the cache, and look like `out`, if and only if
/// `shouldCache`) and the setup tables wrapped in `cache { ... }`.
pub async fn cache(r: &mut Run) {
    let id = "TestCacheInsertion/cacheTestCases";
    for (row, v) in r.rows(id) {
        let tag = format!("cache-insert-{row}");
        let tin = Case::from(&v["in"]);
        let tout = Case::from(&v["out"]);
        let (ans, ns) = (v["in"]["Answer"].clone(), v["in"]["Ns"].clone());
        let ti = tin.clone();
        // cacheMsg: the request's flags and the sections of `in`
        set_reply(&tag, move |req| {
            let mut m = req.reply();
            m.metadata.recursion_available = ti.ra;
            m.metadata.authentic_data = ti.ad;
            m.metadata.checking_disabled = ti.cd;
            m.metadata.authoritative = ti.aa;
            m.metadata.truncation = ti.tc;
            m.metadata.response_code = ResponseCode::from(0, ti.rcode as u8);
            m.answers = records(&ans);
            m.authorities = records(&ns);
            // the Go message is the request: it keeps its OPT record
            m.edns = req.msg.edns.clone();
            let rc = m.metadata.response_code;
            (Some(m), rc)
        });
        let s = Server::new(&format!(
            ".:53 {{\n cache {{\n  success 9984 3600\n  denial 9984 3600\n  disable success pos-disabled.example.org.\n  disable denial neg-disabled.example.org.\n }}\n nomad {tag} reply\n}}"
        ))
        .await;
        let query = || {
            let mut m = tin.msg();
            m.metadata.checking_disabled = tin.cd;
            m.metadata.authentic_data = tin.ad;
            m
        };
        s.serve(query()).await;
        let served = s.serve(query()).await;
        let found = next_calls(&tag) == 1;
        let res = (|| {
            let should = v["shouldCache"].as_bool().unwrap_or(false);
            if found != should {
                return Err(format!("cached: {found}, should cache: {should}"));
            }
            if !found {
                return Ok(());
            }
            let m = served.written().ok_or("no response")?;
            let h = &m.metadata;
            for (name, got, want) in [
                ("Authoritative", h.authoritative, tout.aa),
                ("AuthenticatedData", h.authentic_data, tout.ad),
                ("RecursionAvailable", h.recursion_available, tout.ra),
                ("CheckingDisabled", h.checking_disabled, tout.cd),
            ] {
                if got != want {
                    return Err(format!("Expected {name} bit to be {want}, but got {got}"));
                }
            }
            sort_and_check(m, &tout)
        })();
        r.check(id, &row, res);
    }

    let o = SetupOpts {
        wrap: Some("cache {\n{}\n}"),
        ..Default::default()
    };
    for id in [
        "TestServeStale/tests",
        "TestServeStaleFailureRecheck/tests",
        "TestServeStalePolicy/tests",
        "TestServfail/tests",
        "TestDisable/tests",
        "TestKeepttl/tests",
    ] {
        setup_rows_with(r, id, "input", "shouldErr", None, &o);
    }
}
