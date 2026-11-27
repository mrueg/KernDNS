//! Policy plugins: acl.

use kerndns_core::proto::rr::rdata::opt::EdnsOption;

use crate::harness::*;

/// The extended DNS error code of a response, if any.
pub fn ede(m: &kerndns_core::proto::op::Message) -> Option<u16> {
    m.edns.as_ref().and_then(|e| match e.option(15.into()) {
        Some(EdnsOption::Unknown(_, d)) if d.len() >= 2 => Some(u16::from_be_bytes([d[0], d[1]])),
        _ => None,
    })
}

/// forward setup tables whose shape the generic driver doesn't know.
pub async fn forward(r: &mut Run) {
    // TestNextAlternate: these must not parse
    let id = "TestNextAlternate/testsInvalid";
    for (row, v) in r.rows(id) {
        let res = match setup(str_of(&v)) {
            Err(_) => Ok(()),
            Ok(()) => Err(format!("expected an error for {:?}", str_of(&v))),
        };
        r.check(id, &row, res);
    }
    // an expected error message, empty for success
    setup_rows(
        r,
        "TestFailoverValidation/cases",
        "input",
        "wantError",
        Some("wantError"),
    );
    setup_rows(
        r,
        "TestSourceAddress/tests",
        "input",
        "expectedErr",
        Some("expectedErr"),
    );
}

/// tls acme_test.go: TestParseACMETLSErrors (setup fails with `want`).
pub async fn tls(r: &mut Run) {
    setup_rows(r, "TestParseACMETLSErrors/tests", "input", "want", Some("want"));
}

/// acl_test.go and setup_test.go.
pub async fn acl(r: &mut Run) {
    let id = "TestACLServeDNS/tests";
    for (row, v) in r.rows(id) {
        // the zones become the server block's keys and the writer's zone;
        // "eth0" (an IPv6 interface zone for "Address%ifname") can't be a
        // key the query routes to, and a SocketAddr has no zone name, so
        // that row runs in "." from the plain address
        let a = &v["args"];
        let key = match v["zones"].as_array().and_then(|z| z.first()).map(str_of) {
            Some(z) if z.contains('.') => z,
            _ => ".",
        };
        let s = Server::new(&format!(
            "{key}:53 {{\n {}\n nomad acl rcode NOERROR\n}}",
            str_of(&v["config"])
        ))
        .await;
        let ip = str_of(&a["sourceIP"]);
        let remote = if ip.contains(':') {
            format!("[{ip}]:40212")
        } else {
            format!("{ip}:40212")
        };
        let served = s
            .serve_from(question(str_of(&a["domain"]), u16_of(&a["qtype"])), &remote)
            .await;
        let res = (|| {
            // testResponseWriter: Rcode stays 0 if nothing is written
            let rcode = served.written().map_or(0, |m| u16::from(m.metadata.response_code));
            if rcode != u16_of(&v["wantRcode"]) {
                return Err(format!("Rcode = {rcode}, want {}", v["wantRcode"]));
            }
            if v["expectNoResponse"].as_bool() == Some(true) && served.wrote {
                return Err("responded to client when not expected".into());
            }
            let want_ede = u16_of(&v["wantExtendedErrorCode"]);
            if want_ede != 0 {
                let got = served.written().and_then(ede);
                if got != Some(want_ede) {
                    return Err(format!("Extended DNS Error = {got:?}, want {want_ede}"));
                }
            }
            Ok(())
        })();
        r.check(id, &row, res);
    }
    setup_rows(r, "TestSetup/tests", "config", "wantErr", None);
}
