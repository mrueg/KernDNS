//! Ported from `plugin/sign/*_test.go`, plus checks that the signed zone
//! verifies (hickory's verifier, and `ldns-verify-zone` when installed)
//! and loads back into `file`.

use std::path::{Path, PathBuf};

use kerndns_core::proto::dnssec::Verifier;
use kerndns_core::proto::dnssec::rdata::RRSIG;

use super::*;
use crate::file::zone;
use crate::testutil::{TempDir, with_controller};

const TESTDATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../third_party/coredns/plugin/sign/testdata"
);

fn testdata() -> PathBuf {
    PathBuf::from(TESTDATA)
}

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

/// Parse a `sign` block with `root` as the root directory (the Go tests
/// run in the plugin directory).
fn parse_in(input: &str, root: &Path) -> Result<Sign, String> {
    let root = root.to_path_buf();
    with_controller("sign", input, |c| {
        c.config.root = Some(root);
        parse_sign(c).map_err(|e| e.to_string())
    })
}

fn plugin_dir() -> PathBuf {
    testdata().parent().unwrap().to_path_buf()
}

fn nsec_of(rrs: &[Record]) -> &NSEC {
    match &rrs[0].data {
        RData::DNSSEC(DNSSECRData::NSEC(x)) => x,
        d => panic!("not an NSEC: {d:?}"),
    }
}

fn rrsig(r: &Record) -> &RRSIG {
    match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => s,
        d => panic!("not an RRSIG: {d:?}"),
    }
}

// file_test.go

#[test]
fn file_parse() {
    let path = testdata().join("db.miek.nl");
    let text = std::fs::read_to_string(&path).unwrap();
    let z = parse(&text, "miek.nl.", &path).unwrap();
    let dir = TempDir::new("sign-fileparse");
    let s = Signer {
        keys: vec![],
        origin: "miek.nl.".into(),
        dbfile: path,
        directory: dir.0.clone(),
        jitter_incep: 0,
        jitter_expir: 0,
        signedfile: "db.miek.nl.test".into(),
    };
    s.write(&z).unwrap();
    let out = dir.0.join("db.miek.nl.test");
    let z = parse(&std::fs::read_to_string(&out).unwrap(), "miek.nl.", &out).unwrap();
    assert_eq!(z.apex.soa.as_ref().unwrap().name, n("miek.nl."));
    let apex = z.tree.search(&n("miek.nl.")).unwrap();
    assert!(apex.typ(RecordType::DNSKEY).is_empty(), "Expected no DNSKEYs");
}

#[test]
fn parse_syntax_error_before_soa() {
    let db = "
$TTL         1M
$ORIGIN      example.org.

@            IN  SOA    ns1.example.com. admin.example.com.  (
                               foobarbaz  ; Invalid serial
                               1200       ; Refresh
                               144        ; Retry
                               1814400    ; Expire
                               2h )       ; Minimum
";
    let e = parse(db, "example.org.", Path::new("stdin")).unwrap_err();
    // CoreDNS: "bad SOA zone parameter"; KernDNS's zone parser names the field
    assert!(e.contains("serial"), "Expected parser error, but got: {e}");
}

#[test]
fn parse_no_soa() {
    let db = "
$TTL         1M
$ORIGIN      example.org.

www          IN  A      192.168.0.14
";
    let e = parse(db, "example.org.", Path::new("stdin")).unwrap_err();
    assert!(e.contains("has no SOA record"), "{e}");
}

// nsec_test.go

#[test]
fn names_in_nsec_order() {
    let path = testdata().join("db.miek.nl_ns");
    let text = std::fs::read_to_string(&path).unwrap();
    let z = zone::parse(&text, &n("miek.nl."), &path, 0).unwrap();
    let names: Vec<String> = names(&z).iter().map(|n| n.to_ascii()).collect();
    assert_eq!(names, ["miek.nl.", "child.miek.nl.", "www.miek.nl."]);
}

// resign_test.go (the signatures are padded to valid base64: miekg/dns keeps
// RRSIG signatures as text, KernDNS's zone parser decodes them)

fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> SystemTime {
    // 2019-07-18 22:50 UTC
    let days = {
        let (y, m) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let doy = (153 * m as i32 + 2) / 5 + d as i32 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era as i64 * 146097 + doe as i64 - 719468
    };
    UNIX_EPOCH + Duration::from_secs((days * 86400 + i64::from(h) * 3600 + i64::from(mi) * 60) as u64)
}

#[test]
fn resign_inception() {
    let then = at(2019, 7, 18, 22, 50);
    // signed yesterday
    let zr = "miek.nl.\t1800\tIN\tRRSIG\tSOA 13 2 1800 20190808191936 20190717161936 59725 miek.nl. eU6gI1OkSEbytA==";
    assert!(resign(zr, then).is_ok(), "Expected RRSIG to be valid");
    // inception starts after this date
    let zr = "miek.nl.\t1800\tIN\tRRSIG\tSOA 13 2 1800 20190808191936 20190731161936 59725 miek.nl. eU6gI1OkSEbytA==";
    let e = resign(zr, then).unwrap_err();
    assert!(e.contains("is in the future"), "{e}");
}

#[test]
fn resign_expire() {
    let then = at(2019, 7, 18, 22, 50);
    // expires tomorrow
    let zr = "miek.nl.\t1800\tIN\tRRSIG\tSOA 13 2 1800 20190717191936 20190717161936 59725 miek.nl. eU6gI1OkSEbytA==";
    assert!(resign(zr, then).is_err(), "Expected RRSIG to be invalid");
    // expire too far away
    let zr = "miek.nl.\t1800\tIN\tRRSIG\tSOA 13 2 1800 20190731191936 20190717161936 59725 miek.nl. eU6gI1OkSEbytA==";
    assert!(resign(zr, then).is_ok(), "Expected RRSIG to be valid");
    // expired yesterday
    let zr = "miek.nl.\t1800\tIN\tRRSIG\tSOA 13 2 1800 20190721191936 20190717161936 59725 miek.nl. eU6gI1OkSEbytA==";
    let e = resign(zr, then).unwrap_err();
    assert_eq!(
        e,
        "expiration \"2019-07-21T19:19:36.000Z\" is less than: 168h0m0s away from 2019-07-18T22:50:00.000Z: 68h29m36s"
    );
}

#[test]
fn resign_old_inception_and_no_soa() {
    let then = at(2019, 7, 28, 22, 50);
    let zr = "miek.nl.\t1800\tIN\tRRSIG\tSOA 13 2 1800 20190818191936 20190717161936 59725 miek.nl. eU6gI1OkSEbytA==";
    let e = resign(zr, then).unwrap_err();
    assert!(
        e.starts_with("inception \"2019-07-17T16:19:36.000Z\" was more than: 144h0m0s ago"),
        "{e}"
    );
    let many: String = (0..120)
        .map(|i| format!("a{i}.miek.nl. 300 IN A 192.0.2.1\n"))
        .collect();
    assert_eq!(
        resign(&many, then).unwrap_err(),
        "no SOA RRSIG found in first 100 records"
    );
}

// setup_test.go

#[test]
fn parse_setup() {
    struct Case {
        input: &'static str,
        should_err: bool,
        origin: &'static str,
        dbfile: &'static str,
        directory: &'static str,
        signedfile: &'static str,
    }
    let tests = [
        Case {
            input: "sign testdata/db.miek.nl miek.nl {\n key file testdata/Kmiek.nl.+013+59725\n}",
            should_err: false,
            origin: "miek.nl.",
            dbfile: "testdata/db.miek.nl",
            directory: "/var/lib/coredns",
            signedfile: "db.miek.nl.signed",
        },
        Case {
            input: "sign testdata/db.miek.nl example.org {\n key file testdata/Kmiek.nl.+013+59725\n directory testdata\n}",
            should_err: false,
            origin: "example.org.",
            dbfile: "testdata/db.miek.nl",
            directory: "testdata",
            signedfile: "db.example.org.signed",
        },
        // errors
        Case {
            input: "sign db.example.org {\n key file /etc/coredns/keys/Kexample.org\n}",
            should_err: true,
            origin: "",
            dbfile: "",
            directory: "",
            signedfile: "",
        },
    ];
    let root = plugin_dir();
    for (i, tc) in tests.iter().enumerate() {
        let res = parse_in(tc.input, &root);
        if tc.should_err {
            assert!(res.is_err(), "Test {i} expected errors, but got no error");
            continue;
        }
        let sign = res.unwrap_or_else(|e| panic!("Test {i} expected no errors, but got '{e}'"));
        let s = &sign.signers[0];
        assert_eq!(s.origin, tc.origin, "Test {i}");
        assert_eq!(s.dbfile, root.join(tc.dbfile), "Test {i}");
        let dir = if tc.directory.starts_with('/') {
            PathBuf::from(tc.directory)
        } else {
            root.join(tc.directory)
        };
        assert_eq!(s.directory, dir, "Test {i}");
        assert_eq!(s.signedfile, tc.signedfile, "Test {i}");
        assert_eq!(s.keys.len(), 1);
        assert_eq!(s.keys[0].record.name, n(tc.origin), "key owner is the origin");
        assert!((-18 * 3600..=0).contains(&s.jitter_incep));
        assert!((0..=5 * 86400).contains(&s.jitter_expir));
    }
}

#[test]
fn parse_errors() {
    let root = plugin_dir();
    for (input, want) in [
        ("sign", "Wrong argument count"),
        (
            "sign testdata/db.miek.nl miek.nl {\n directory a b\n}",
            "can only be one argument after \"directory\"",
        ),
        (
            "sign testdata/db.miek.nl miek.nl {\n key directory /etc\n}",
            "directory: not implemented",
        ),
        ("sign testdata/db.miek.nl miek.nl {\n foo\n}", "unknown property 'foo'"),
        // a ZSK can't sign: sign wants CSKs/KSKs
        (
            "sign testdata/db.miek.nl miek.nl {\n key file zsk/Kmiek.nl\n}",
            "is not a CSK/KSK",
        ),
    ] {
        let dir = TempDir::new("sign-zsk");
        let res = if input.contains("zsk/") {
            dir.write(
                "Kmiek.nl.key",
                "miek.nl. IN DNSKEY 256 3 13 sfzRg5nDVxbeUc51su4MzjgwpOpUwnuu81SlRHqJuXe3SOYOeypR69tZ52XLmE56TAmPHsiB8Rgk+NTpf0o1Cw==",
            );
            dir.write(
                "Kmiek.nl.private",
                &std::fs::read_to_string(testdata().join("Kmiek.nl.+013+59725.private")).unwrap(),
            );
            parse_in(&input.replace("zsk/", &format!("{}/", dir.0.display())), &root)
        } else {
            parse_in(input, &root)
        };
        let e = res.err().unwrap_or_else(|| panic!("{input}: expected error"));
        assert!(e.contains(want), "{input}: {e}");
    }
}

/// An invalid UTF-8 dbfile token (U+FFFD after decoding) must fail.
#[test]
fn parse_rejects_invalid_dbfile_token() {
    let e = parse_in(
        "sign \"\u{FFFD}\" 8.44.in-addr.arpa. 9.44.in-addr.arpa. {}",
        &plugin_dir(),
    )
    .expect_err("expected parse to fail for invalid dbfile token");
    assert!(e.contains("invalid characters"), "{e}");
}

// signer_test.go

fn signer_for(input: &str) -> Signer {
    let sign = parse_in(input, &plugin_dir()).unwrap();
    assert_eq!(sign.signers.len(), 1, "Expected 1 signer");
    sign.signers.into_iter().next().unwrap()
}

#[test]
fn sign_zone() {
    let s = signer_for(
        "sign testdata/db.miek.nl miek.nl {\n key file testdata/Kmiek.nl.+013+59725\n directory testdata\n}",
    );
    let z = s.sign(SystemTime::now()).unwrap();
    let apex = z.tree.search(&n("miek.nl.")).unwrap();
    assert_eq!(apex.typ(RecordType::DS).len(), 0);
    assert_eq!(apex.typ(RecordType::CDS).len(), 2);
    assert_eq!(apex.typ(RecordType::CDNSKEY).len(), 1);
    assert_eq!(apex.typ(RecordType::DNSKEY).len(), 1);
}

#[test]
fn sign_apex_zone() {
    let dir = TempDir::new("sign-apex");
    dir.write(
        "db.apex-test.example.org",
        "$TTL    30M
$ORIGIN example.org.
@       IN      SOA     linode miek.miek.nl. ( 1282630060 4H 1H 7D 4H )
        IN      NS      linode
",
    );
    let input = format!(
        "sign {}/db.apex-test.example.org example.org {{\n key file testdata/Kmiek.nl.+013+59725\n directory testdata\n}}",
        dir.0.display()
    );
    let s = signer_for(&input);
    let z = s.sign(SystemTime::now()).unwrap();
    let el = z.tree.search(&n("example.org.")).unwrap();
    let nsec = el.typ(RecordType::NSEC);
    assert_eq!(nsec.len(), 1);
    let x = nsec_of(nsec);
    assert_eq!(x.next_domain_name(), &n("example.org."));
    let bitmap: Vec<RecordType> = x.type_bit_maps().collect();
    assert_eq!(bitmap.len(), 7, "{bitmap:?}");
    assert_eq!(bitmap[6], RecordType::CDNSKEY);
    assert_eq!(bitmap[4], RecordType::DNSKEY);
    let dnskey = el.typ(RecordType::DNSKEY);
    assert_eq!(dnskey[0].ttl, 1800);
    for s in el.typ(RecordType::RRSIG) {
        let sig = rrsig(s);
        if sig.input().type_covered == RecordType::DNSKEY {
            assert_eq!(sig.input().original_ttl, dnskey[0].ttl);
            assert_eq!(sig.input().signer_name, dnskey[0].name);
        }
    }
}

#[test]
fn sign_glue() {
    let s = signer_for(
        "sign testdata/db.miek.nl miek.nl {\n key file testdata/Kmiek.nl.+013+59725\n directory testdata\n}",
    );
    let z = s.sign(SystemTime::now()).unwrap();
    let e = z.tree.search(&n("ns2.bla.miek.nl.")).unwrap();
    assert!(e.typ(RecordType::RRSIG).is_empty(), "glue is not signed");
    let e = z.tree.search(&n("ns3.blaaat.miek.nl.")).unwrap();
    assert_eq!(e.typ(RecordType::RRSIG).len(), 2, "non-glue is signed (AAAA, NSEC)");
}

#[test]
fn sign_ds() {
    let s = signer_for(
        "sign testdata/db.miek.nl_ns miek.nl {\n key file testdata/Kmiek.nl.+013+59725\n directory testdata\n}",
    );
    let z = s.sign(SystemTime::now()).unwrap();
    // dnssec-signzone outputs this for db.miek.nl_ns:
    //
    // child.miek.nl.	1800	IN	NS	ns.child.miek.nl.
    // child.miek.nl.	1800	IN	DS	34385 13 2 fc7397c77afbccb6742fc....
    // child.miek.nl.	1800	IN	RRSIG	DS 13 3 1800 20191223121229 20191123121229 59725 miek.nl. ZwptLzVVs....
    // child.miek.nl.	14400	IN	NSEC	www.miek.nl. NS DS RRSIG NSEC
    // child.miek.nl.	14400	IN	RRSIG	NSEC 13 3 14400 20191223121229 20191123121229 59725 miek.nl. w+CcA8...
    let e = z.tree.search(&n("child.miek.nl.")).unwrap();
    let types: HashSet<RecordType> = e.all().map(Record::record_type).collect();
    assert_eq!(types.len(), 4, "NS DS NSEC RRSIG: {types:?}");
    assert_eq!(e.typ(RecordType::DS).len(), 1);
    assert_eq!(e.typ(RecordType::RRSIG).len(), 2);
    let nsec = e.typ(RecordType::NSEC);
    assert_eq!(nsec_of(nsec).next_domain_name(), &n("www.miek.nl."));
    let RData::SOA(soa) = &z.apex.soa.as_ref().unwrap().data else {
        panic!()
    };
    assert_eq!(nsec[0].ttl, soa.minimum);
}

/// Every RRSIG in the signed zone verifies with the key, the NSEC chain
/// is closed, and the zone written out loads into `file` with the same
/// records.
#[test]
fn signed_zone_verifies_and_round_trips() {
    let s = signer_for(
        "sign testdata/db.miek.nl miek.nl {\n key file testdata/Kmiek.nl.+013+59725\n directory testdata\n}",
    );
    let now = SystemTime::now();
    let z = s.sign(now).unwrap();
    assert_eq!(z.apex.serial(), Some(unix(now) as u32));
    let key = s.keys[0].dnskey().clone();

    let mut all: Vec<Record> = z.apex.records().unwrap();
    all.extend(z.tree.elems().flat_map(|e| e.all().cloned()));
    let mut verified = 0;
    for r in &all {
        let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = &r.data else {
            continue;
        };
        let set: Vec<&Record> = all
            .iter()
            .filter(|x| x.name == r.name && x.record_type() == sig.input().type_covered)
            .collect();
        key.verify_rrsig(&r.name, r.dns_class, sig, set.into_iter())
            .unwrap_or_else(|e| panic!("{r}: {e}"));
        let (incep, expir) = (sig.input().sig_inception.get(), sig.input().sig_expiration.get());
        let t = unix(now);
        assert!(i64::from(incep) <= t - 3 * 3600 && i64::from(incep) >= t - 21 * 3600 - 1);
        assert!(i64::from(expir) >= t + 32 * 86400 && i64::from(expir) <= t + 37 * 86400 + 1);
        verified += 1;
    }
    // SOA, NS, apex (MX AAAA DNSKEY CDS CDNSKEY NSEC), a (AAAA NSEC),
    // bla (NSEC only: a delegation), ns3.blaaat (AAAA NSEC), www (CNAME NSEC)
    assert_eq!(verified, 2 + 6 + 2 + 1 + 2 + 2);

    // the NSEC chain visits every authoritative name and wraps around
    let names = names(&z);
    for (i, name) in names.iter().enumerate() {
        let e = z.tree.search(name).unwrap();
        assert_eq!(
            nsec_of(e.typ(RecordType::NSEC)).next_domain_name(),
            &names[(i + 1) % names.len()]
        );
    }

    let text = write(&z);
    let back = zone::parse(&text, &n("miek.nl."), Path::new("signed"), -1).unwrap();
    let mut a: Vec<String> = all.iter().map(rr_string).collect();
    let mut b: Vec<String> = back.apex.records().unwrap().iter().map(rr_string).collect();
    b.extend(back.tree.elems().flat_map(|e| e.all().map(rr_string)));
    a.sort();
    b.sort();
    assert_eq!(a, b);

    // and resign() is happy with a fresh zone
    assert!(resign(&text, now).is_ok(), "{:?}", resign(&text, now));
}

/// Record types survive the trip through the signed file.
#[test]
fn presentation_round_trips() {
    let db = "$TTL 300
$ORIGIN example.org.
@ IN SOA ns1 h ( 1 7200 3600 1209600 300 )
  IN NS ns1
  IN MX 10 mail
  IN TXT \"v=spf1 -all\" \"two words\"
  IN CAA 0 issue \"letsencrypt.org\"
ns1 IN A 192.0.2.1
ns1 IN AAAA 2001:db8::1
_sip._tcp IN SRV 0 5 5060 sip
d IN DNAME example.net.
h IN HINFO \"PC\" \"Linux\"
p IN PTR x.example.org.
s IN SSHFP 1 1 123456789abcdef67890123456789abcdef67890
t IN TYPE65280 \\# 3 010203
c IN CNAME www
";
    let z = parse(db, "example.org.", Path::new("db")).unwrap();
    let text = write(&z);
    let back = parse(&text, "example.org.", Path::new("db")).unwrap();
    assert_eq!(write(&back), text, "{text}");
}

/// `ldns-verify-zone` (if installed) accepts the signed zone.
#[test]
fn ldns_verify_zone() {
    let Ok(out) = std::process::Command::new("ldns-verify-zone").arg("-v").output() else {
        eprintln!("ldns-verify-zone not installed, skipping");
        return;
    };
    let _ = out;
    let dir = TempDir::new("sign-ldns");
    let input = format!(
        "sign testdata/db.miek.nl_ns miek.nl {{\n key file testdata/Kmiek.nl.+013+59725\n directory {}\n}}",
        dir.0.display()
    );
    let s = signer_for(&input);
    sign_and_log(&s, "test");
    let signed = dir.0.join("db.miek.nl.signed");
    assert!(signed.exists());
    let out = std::process::Command::new("ldns-verify-zone")
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        std::fs::read_to_string(&signed).unwrap()
    );
    assert!(s.resign().is_ok());
}
