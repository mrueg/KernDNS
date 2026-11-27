//! plugin/file: every test serves one zone, parsed from a string of the
//! Go tests, with `test.ErrorHandler()` as the next plugin (`nomad file
//! error`, see harness).

use std::path::Path;

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_plugins::file::zone;

use crate::harness::*;

/// `file` serving `zone` (a Go string) for `origin`, plus extra lines.
pub async fn zone_server(r: &Run, origin: &str, zone: &str, extra: &str, opts: &str) -> Server {
    let dir = TempDir::new();
    let path = dir.write("zone", &format!("{}\n{extra}\n", r.string(zone)));
    let block = if opts.is_empty() {
        String::new()
    } else {
        format!(" {{\n  {opts}\n }}")
    };
    Server::new(&format!(".:53 {{\n file {path} {origin}{block}\n nomad file error\n}}"))
        .await
        .with_dir(dir)
}

pub async fn drive(r: &mut Run) {
    let miek = r.string("testzone").to_string();
    for (table, zone, origin) in [
        ("dnsTestCases", "dbMiekNL", miek.as_str()),
        ("dnssecTestCases", "dbMiekNLSigned", miek.as_str()),
        ("delegationTestCases", "dbMiekNLDelegation", miek.as_str()),
        ("secureDelegationTestCases", "exampleOrgSigned", "example.org."),
        ("dsTestCases", "dbMiekNLDelegation", miek.as_str()),
        ("entTestCases", "dbMiekENTNL", miek.as_str()),
        ("atoomTestCases", "dbAtoomNetSigned", "atoom.net."),
        ("additionalTestCases", "dbAdditionalExample", "example.org."),
        ("svcbTestCases", "dbSVCBExample", "example.com."),
        ("wildcardTestCases", "dbDnssexNLSigned", "dnssex.nl."),
        ("wildcardDoubleTestCases", "exampleOrg", "example.org."),
        ("apexWildcardTestCases", "apexWildcard", "example.org."),
        ("multiWildcardTestCases", "doubleWildcard", "example.org."),
        ("wildcardAdditionalTestCases", "dbWildcardAdditional", "example.org."),
        ("closerENTWildcardTestCases", "closerENTWildcard", "example.org."),
        (
            "emptyNonTerminalWildcardTestCases",
            "emptyNonTerminalWildcard",
            "example.org.",
        ),
    ] {
        let s = zone_server(r, origin, zone, "", "").await;
        run_cases(r, table, &s).await;
    }

    // TestLookupOwnerNameWithDecimalEscape: one test.Case
    let origin = r.string("TestLookupOwnerNameWithDecimalEscape/origin").to_string();
    let s = zone_server(r, &origin, "dbEscapeOwner", "", "").await;
    run_cases(r, "TestLookupOwnerNameWithDecimalEscape/tc", &s).await;

    // TestLookUpNoDataResult: Lookup's result is NoData, seen from the
    // outside as NOERROR without answers and the SOA in the authority
    let id = "TestLookUpNoDataResult/noDataTestCases";
    let s = zone_server(r, &miek, "dbMiekNL", "", "").await;
    for (row, v) in r.rows(id) {
        let tc = Case::from(&v);
        let res = match s.serve(tc.msg()).await.written() {
            Some(m)
                if m.metadata.response_code == ResponseCode::NoError
                    && m.answers.is_empty()
                    && m.authorities.iter().any(|a| a.record_type() == RecordType::SOA) =>
            {
                Ok(())
            }
            other => Err(format!("expected NODATA, got {other:?}")),
        };
        r.check(id, &row, res);
    }

    // TestParseSOAOrigin: file.Parse with serials -1, 2 and 3
    let id = "TestParseSOAOrigin/tests";
    for (row, v) in r.rows(id) {
        let origin = str_of(&v["origin"]);
        let origin = if origin.ends_with('.') {
            origin.to_string()
        } else {
            format!("{origin}.")
        };
        let origin = Name::from_ascii(&origin).unwrap();
        let zone = format!(
            "{}{} 500 IN SOA ns.example. hostmaster.example. 3 3600 600 86400 300\n",
            str_of(&v["prefix"]),
            str_of(&v["owner"])
        );
        let want_err = v["wantErr"].as_bool().unwrap_or(false);
        let mut res = Ok(());
        for serial in [-1i64, 2, 3] {
            let got = zone::parse(&zone, &origin, Path::new("db.test"), serial);
            let r = match (&got, want_err, serial) {
                (Err(e), true, _) => {
                    let e = e.to_string();
                    if e.contains("SOA owner") && e.contains("db.test") {
                        Ok(())
                    } else {
                        Err(format!("expected SOA owner error with file name, got {e}"))
                    }
                }
                (Ok(_), true, _) => Err("accepted the SOA owner".to_string()),
                (Err(zone::LoadError::NoChange { .. }), false, 3) => Ok(()),
                (_, false, 3) => Err(format!("expected unchanged serial error, got {:?}", got.err())),
                (Ok(_), false, _) => Ok(()),
                (Err(e), false, _) => Err(e.to_string()),
            };
            if let Err(e) = r {
                res = Err(format!("serial={serial}: {e}"));
                break;
            }
        }
        r.check(id, &row, res);
    }

    // TestLookupFallthrough: only the rcode is checked
    let id = "TestLookupFallthrough/fallsWithTestCases";
    for (row, v) in r.rows(id) {
        let opts = fallthrough(&v["Fall"]);
        let s = zone_server(r, &miek, "dbMiekNL", "", &opts).await;
        for (i, c) in v["Cases"].as_array().unwrap().iter().enumerate() {
            let tc = Case::from(c);
            let res = match s.serve(tc.msg()).await.written() {
                Some(m) if u16::from(m.metadata.response_code) == tc.rcode => Ok(()),
                Some(m) => Err(format!("rcode is {}, expected {}", m.metadata.response_code, tc.rcode)),
                None => Err("no response".into()),
            };
            r.check(id, &format!("{row}.{i}"), res);
        }
    }

    // TestAliasToDelegation: SortAndCheck plus the AA bit
    let id = "TestAliasToDelegation/tests";
    let s = zone_server(r, "example.org.", "dbAliasDelegation", "", "").await;
    for (row, v) in r.rows(id) {
        let tc = Case {
            answer: v["answer"].as_array().cloned().unwrap_or_default(),
            ns: v["authority"].as_array().cloned().unwrap_or_default(),
            extra: v["additional"].as_array().cloned().unwrap_or_default(),
            ..Case::from(&serde_json::json!({"Qname": v["qname"], "Qtype": v["qtype"]}))
        };
        let res = async {
            let m = s
                .serve(tc.msg())
                .await
                .written()
                .cloned()
                .ok_or("no response written")?;
            sort_and_check(&m, &tc)?;
            let aa = v["authoritative"].as_bool().unwrap_or(false);
            if m.metadata.authoritative != aa {
                return Err(format!("Authoritative = {}, want {aa}", m.metadata.authoritative));
            }
            Ok(())
        }
        .await;
        r.check(id, &row, res);
    }

    // TestSignedAliasToDelegation: two CNAMEs inserted into the signed zone
    let id = "TestSignedAliasToDelegation/tests";
    let s = zone_server(
        r,
        "example.org.",
        "exampleOrgSigned",
        "alias.example.org. 1800 IN CNAME a.delegated.example.org.\nds-alias.example.org. 1800 IN CNAME delegated.example.org.",
        "",
    )
    .await;
    for (row, v) in r.rows(id) {
        let tc = Case {
            answer: v["answer"].as_array().cloned().unwrap_or_default(),
            ns: v["authority"].as_array().cloned().unwrap_or_default(),
            extra: v["additional"].as_array().cloned().unwrap_or_default(),
            ..Case::from(&serde_json::json!({"Qname": v["qname"], "Qtype": v["qtype"], "Do": true}))
        };
        let res = async {
            let m = s
                .serve(tc.msg())
                .await
                .written()
                .cloned()
                .ok_or("no response written")?;
            sort_and_check(&m, &tc)?;
            if !m.metadata.authoritative {
                return Err("Authoritative = false, want true".into());
            }
            Ok(())
        }
        .await;
        r.check(id, &row, res);
    }
}
