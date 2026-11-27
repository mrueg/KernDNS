//! Ported from `plugin/dnssec/*_test.go`, plus checks that every signature
//! verifies (hickory's DNSSEC verifier) for each supported algorithm.

use std::path::Path;

use kerndns_core::corefile::{Dispenser, parse as parse_corefile};
use kerndns_core::proto::dnssec::Verifier;
use kerndns_core::proto::dnssec::rdata::{DNSKEY, DNSSECRData, RRSIG};
use kerndns_core::proto::op::{Edns, Message, MessageType, OpCode, Query};
use kerndns_core::{BlockConfig, CaptureWriter, Hooks, ZoneAddr, result_rcode};

use super::*;
use crate::file::zonefile::new_rr;
use crate::testutil::{TempDir, with_controller};

const SERVER: &str = "dns//.";

// Keys from plugin/dnssec/dnssec_test.go.
const PUB_KEY: &str = "miek.nl. IN DNSKEY 257 3 13 0J8u0XJ9GNGFEBXuAmLu04taHG4BXPP3gwhetiOUMnGA+x09nqzgF5IY OyjWB7N3rXqQbnOSILhH1hnuyh7mmA==";
const PRIV_KEY: &str = "Private-key-format: v1.3
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: /4BZk8AFvyW5hL3cOLSVxIp1RTqHSAEloWUxj86p3gs=
Created: 20160423195532
Publish: 20160423195532
Activate: 20160423195532
";
const DS_KEY: &str = "miek.nl. IN DS 18512 13 2 D4E806322598BC97A003EF1ACDFF352EEFF7B42DBB0D41B8224714C36AEF08D9";
const PUB_KEY1: &str = "example.org. IN DNSKEY 257 3 13 tVRWNSGpHZbCi7Pr7OmbADVUO3MxJ0Lb8Lk3o/HBHqCxf5K/J50lFqRa 98lkdAIiFOVRy8LyMvjwmxZKwB5MNw==";
const PRIV_KEY1: &str = "Private-key-format: v1.3
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: i8j4OfDGT8CQt24SDwLz2hg9yx4qKOEOh1LvbAuSp1c=
Created: 20160423211746
Publish: 20160423211746
Activate: 20160423211746
";

// setup_test.go uses a 1024-bit RSASHA1 key for cluster.local. ring signs
// neither RSASHA1 nor keys under 2048 bits, so these setup tests use a
// 2048-bit RSASHA256 key (made with ldns-keygen); the original key is
// checked to be rejected below.
const CLUSTER_PUB: &str = "; This is a zone-signing key, keyid 65355, for cluster.local.
cluster.local.\tIN\tDNSKEY\t256 3 8 AwEAAbH+wGuQf1EbwPU8uTJmVOLGfPkPeiNGFRczzJoINvClwB8Nnf+qFfMdYu8ORk1qaSJmg/v4o4sCYDWd9WKdFzg/2qdMPhe0ma/Nu/C1NJTmluZLVXXbEH3bWMFdc4ZD7UfGSZDCYysaV3efvkHCdQm1brTAUJ5ATyRaAeVzLNzrf03M7X1sTHOezvkI92v+VXqze7jMVgwQe+hUV+xBUpx3JHKa8s0RzOXI5F5/vGlWyXpwY6ujXIKzJDVoUKXeGuU2trVVdrHJMhTCzPnMZ5/t7NqLiSu8fhOyDQ/JVN6JAvE7k73SHGJM9To6nkPng/iNZetKIe1Vclw44LhTKZc= ;{id = 65355 (zsk), size = 2048b}
";
const CLUSTER_PRIV: &str = "Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: sf7Aa5B/URvA9Ty5MmZU4sZ8+Q96I0YVFzPMmgg28KXAHw2d/6oV8x1i7w5GTWppImaD+/ijiwJgNZ31Yp0XOD/ap0w+F7SZr8278LU0lOaW5ktVddsQfdtYwV1zhkPtR8ZJkMJjKxpXd5++QcJ1CbVutMBQnkBPJFoB5XMs3Ot/TcztfWxMc57O+Qj3a/5VerN7uMxWDBB76FRX7EFSnHckcpryzRHM5cjkXn+8aVbJenBjq6NcgrMkNWhQpd4a5Ta2tVV2sckyFMLM+cxnn+3s2ouJK7x+E7IND8lU3okC8TuTvdIcYkz1OjqeQ+eD+I1l60oh7VVyXDjguFMplw==
PublicExponent: AQAB
PrivateExponent: N0ZlewHkh8uWoJG68WvV8JazOKUVyN56rjnnz+29If5XK02PQ1YOevElSBemvWPOQmCTnCwanZCfUAc9rOIb09wAivOiVLpA/9dkBdw/9/2j3uCGKZNeC7eSWHos5gUyKpfpQIsdQMVtZDi3XLSGo/0z4+3VG0/dQ+yvqhGaXQBAa4D6pI3RVDCEaJw2PBk9XJFzKPcKClX5A/t3nDxc3r8c1bdnqOTH97v6vPsnf4ZUTMLxa7JPOOVFgellaJzSg1h42EnGD2r7+rOc40To4LBPSMri1oC4D6K6r3GLhzcNs8Jo72+mZ1bKZnHVLxLn3EoiRSBhdJRjqAqQf1DAAQ==
Prime1: 2jN4c2jMn7vk37Lc01zKGFeAhkjI3NvKPeExjlV9yReV/QKUxepp/Esredkec3bHbzbgrDLM7yS11M3qRcJQZDAd6m7ntkpeWLPdCX5b8LjRKZj3fzIDEhvTi3kyFIJwUO5OoBNCqBnyYl4ZH4mGL+DbDkOKE6DBdVfAPwWu2lc=
Prime2: 0NRGT78vGPgbCLgTmhfdYK/krD/8ZD2OpykXkoxzHun2I/SZh3KZg8RtSMxZlK/4j/X8azZgJsk0Eoi2tIYkUN5q9YX+RocAcQ4vh589mD29KmMPdwouxe0RF+aJoQ35108zbwOcD11R5dAaTgMiP1+FR1zZVODU5Bs8WR7nIsE=
Exponent1: xDJjq+Ifm8EnGr2JMcPNM/X56sSnV2+JefpyxLi6UYaTptwbSZptkh1FClrftpKm4KlHe45yFtW7aY19iRwfjPZ278SpNI/KJZgUt+SWZuzHpc+VOxmNCUtb+50OGsLumtase+LVnLE38JsLm//cWFCmpzyzetKhIRG2GvTRNCE=
Exponent2: wQIxKiutwAowElLv6w/7kA2B8KIDCDLM0jrsioo9LGlZEcpUzBdjQ6Icz5fvg7lQpt3Xus+69p4n/qlVFGyWzBeGC/8YEN9dzSArVdIb/8WwPKjp9j/3EwAVOF3e/ngIXrPY+dYAO0MpGprIdSn4UVJbwKVUSVqz6VAy6rvhLQE=
Coefficient: wZlJV3f7vlfmYNXa6aDhP2Tv+28zU33nchxNk4RTTXavSHyfXoNYVN9WJ9767pMJJHvYFILZs636qiRl4OnoyutLtNhgu5oynuRFOw2zaJpDYMzHoyjVeaeXOkljuRt99qs+esfyCjPHagcn8hEAWicB8nAKw3CaKwhf9OSq07I=
";

// The original setup_test.go key: RSASHA1, 1024 bits.
const RSASHA1_PUB: &str = "cluster.local. IN DNSKEY 256 3 5 AwEAAcFpDv+Cb23kFJowu+VU++b2N1uEHi6Ll9H0BzLasFOdJjEEclCO q/KlD4682vOMXxJNN8ZwOyiCa7Y0TEYqSwWvhHyn3bHCwuy4I6fss4Wd 7Y9dU+6QTgJ8LimGG40Iizjc9zqoU8Q+q81vIukpYWOHioHoY7hsWBvS RSlzDJk3";
const RSASHA1_PRIV: &str = "Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: wWkO/4JvbeQUmjC75VT75vY3W4QeLouX0fQHMtqwU50mMQRyUI6r8qUPjrza84xfEk03xnA7KIJrtjRMRipLBa+EfKfdscLC7Lgjp+yzhZ3tj11T7pBOAnwuKYYbjQiLONz3OqhTxD6rzW8i6SlhY4eKgehjuGxYG9JFKXMMmTc=
PublicExponent: AQAB
PrivateExponent: K5XyZFBPrjMVFX5gCZlyPyVDamNGrfSVXSIiMSqpS96BSdCXtmHAjCj4bZFPwkzi6+vs4tJN8p4ZifEVM0a6qwPZyENBrc2qbsweOXE6l8BaPVWFX30xvVRzGXuNtXxlBXE17zoHty5r5mRyRou1bc2HUS5otdkEjE30RiocQVk=
Prime1: 7RRFUxaZkVNVH1DaT/SV5Sb8kABB389qLwU++argeDCVf+Wm9BBlTrsz2U6bKlfpaUmYZKtCCd+CVxqzMyuu0w==
Prime2: 0NiY3d7Fa08IGY9L4TaFc02A721YcDNBBf95BP31qGvwnYsLFM/1xZwaEsIjohg8g+m/GpyIlvNMbK6pywIVjQ==
Exponent1: XjXO8pype9mMmvwrNNix9DTQ6nxfsQugW30PMHGZ78kGr6NX++bEC0xS50jYWjRDGcbYGzD+9iNujSScD3qNZw==
Exponent2: wkoOhLIfhUIj7etikyUup2Ld5WAbW15DSrotstg0NrgcQ+Q7reP96BXeJ79WeREFE09cyvv/EjdLzPv81/CbbQ==
Coefficient: ah4LL0KLTO8kSKHK+X9Ud8grYi94QSNdbX11ge/eFcS/41QhDuZRTAFv4y0+IG+VWd+XzojLsQs+jzLe5GzINg==
";

// More algorithms, made with ldns-keygen (test keys only).
const P384_PUB: &str = "example.org.\tIN\tDNSKEY\t256 3 14 Vo9zE4ysbZOQkO2y1PFinYlCMFyXm1ZI+kjp+kanLoJiPnZWJ5LGYAGYwU5pWOKhmEzKlNUKb/7Rn0B9MVObwwfXcP2uAYno+7aR3xVvpBYJsW69etFYuuwZuE487y6E";
const P384_PRIV: &str = "Private-key-format: v1.2
Algorithm: 14 (ECDSAP384SHA384)
PrivateKey: swdhwSzfqTduTPk6EgMFswnDp2jn+gK3gGYknI4pvlGSZ5YpIFA2oga0iHVx7YVN
";
const ED25519_PUB: &str = "example.org.\tIN\tDNSKEY\t256 3 15 tRdt+dquIxHMBoo378Q8eC5e/G9f3ERwPDlk5jyFyKE=";
const ED25519_PRIV: &str = "Private-key-format: v1.2
Algorithm: 15 (ED25519)
PrivateKey: JArcRPMJg92m1QmxFtFPMRHJ0ZfvAwXwblUdS9/9J4E=
";
const RSASHA512_PUB: &str = "example.org.\tIN\tDNSKEY\t256 3 10 AwEAAclVCL+qrbm2lQqmQeaGwRFTC9vCNQsfCvGA5F0B/EAj9MbUv1Q1FGr7T+pmuNGixoSKNyAVIITh15VIhG5DI9CFObU/yY8uiK5zNwmb7cgsEXG3RYCLCwH9P0/tRWfJPttRET9uqnvzGiqJFNWNO/RR7HCUQEJO8ah3U0yT8GEEDiKIQVeYJOrcHUPqs9ZunBYpfrvA+Nw0zO8R/ezT/E1manFTCmw0N28HcTs7k8bjAwP48dP553BBgkGSFed4gvW5SGv1xOfg9B+jv85pwNQYRtMDpP8IeVwnXIkumODHxdjP2uH6yZ2h4Scygt3Y3OS2tPOnCKD5D4rbRou+bUM=";
const RSASHA512_PRIV: &str = "Private-key-format: v1.2
Algorithm: 10 (RSASHA512)
Modulus: yVUIv6qtubaVCqZB5obBEVML28I1Cx8K8YDkXQH8QCP0xtS/VDUUavtP6ma40aLGhIo3IBUghOHXlUiEbkMj0IU5tT/Jjy6IrnM3CZvtyCwRcbdFgIsLAf0/T+1FZ8k+21ERP26qe/MaKokU1Y079FHscJRAQk7xqHdTTJPwYQQOIohBV5gk6twdQ+qz1m6cFil+u8D43DTM7xH97NP8TWZqcVMKbDQ3bwdxOzuTxuMDA/jx0/nncEGCQZIV53iC9blIa/XE5+D0H6O/zmnA1BhG0wOk/wh5XCdciS6Y4MfF2M/a4frJnaHhJzKC3djc5La086cIoPkPittGi75tQw==
PublicExponent: AQAB
PrivateExponent: DgbkoyXrEKNN4v4OXVdKIEDe9KKlO28gPg8y2eAHiRh4N1ofMmi4UXPM75HUkpZ6qkVO7edK6rcpY/c3cs8usZp2mNAm5NjjIPRaA0tf17BqTrfsGbaWP787KABp838r5+/P+dFmA1i+m/QNBYvff3gttvI9P+FsKMaXgSBVgQy9hdpOiKXlXTglwOjB9nPqDEGllwdz5sIp4Pvin7/CtD6e92wrVwrssMTd7VWEDq3uqBmXbwegRsmvAiiLy/H9wKNvScn0pq4UfSM98P+8UtZWmVIZKfXwXi0+RysM8M6JWl84/noOejk7yMPI6NPtJrJems2wW1ILmV/RsiVXcQ==
Prime1: 98xCgG0H7EVPtzY2gcbutO20YBxEALDovsJawLjxutZzire4fuZghcoP37IXbPp+b/DNvpsFZ3cQPyCkkL45mXzp8ivUudfjVueeAmcIwaLAbFfbpI2cfsMalLkA9InnO3oBTEIYbmvopj+gAVq9MHg2TQDsaB+Gfg7LTWC+lc8=
Prime2: z/8K3Kv4Dk9YbSu6Fvf1Y/PiWI7VgJ+TVhmN4kh+p/Q9Qy9HosdMQITr+tFGKXqJR37Ne6ArmJ6XUJftEvtlKpYClfxUtkEQYxDKeRnpuaNYchquwjSyJ+SmQ+vpruNMETcxC6t8tcg48wb+ZXHK8FdyimteKglUk8KDvzJ0Qk0=
Exponent1: rbF9w+upLBKBiBj2KA27cRNV5jCp8hoPavdtCb4Zoy+DGe8h4cG2UtGKQvDgvsDvM6QFc9/R7+5jcvx8ngDY+x+2FMxodkQ/1MDR3zk9yA0++DK1gSjKU4iK70imxMKNVQF2O2/xFCWLlEzw6UIjbwA0f9Fv5KSEb4QLOZfgv70=
Exponent2: vKvk9ncn9BMVazIXA265MYmw8BPgp2QZCij0AycvfLqYN7FTkdym1n+8bzAWLNnyXOAxFMsdwLtbFsg5TNat1gttHRBe51PtwW8huug+kx4QxLBfhdq3IGjQSRxeRT35akReQO+1mE+fGRRm/y5Rn+IzDEyIhikgh0gSqgTiYKE=
Coefficient: mxgVq3b3YYrKKMQeIk5jyxAHpm5Ho14/mgg4eWPNk9lpzem2vo00vakmwg2xZrCUTxD8j0BJDTjL4AMeq3pRT/Qc4xxNaYA98C4ryHT0uSg+5A8krMsme5LkDF9VVklOh8tRAb/B3GFxPMZpkVzO70mRpuLa68ypimhgkbolKgQ=
";

fn key_from(public: &str, private: &str) -> Key {
    let record = new_rr(public).unwrap().unwrap();
    key::key_from_parts(record, private).unwrap()
}

fn new_key() -> Key {
    key_from(PUB_KEY, PRIV_KEY)
}

fn new_dnssec(zones: &[&str]) -> Dnssec {
    new_dnssec_keys(zones, vec![new_key()])
}

fn new_dnssec_keys(zones: &[&str], keys: Vec<Key>) -> Dnssec {
    Dnssec::new(
        zones.iter().map(|z| z.to_string()).collect(),
        keys,
        false,
        None,
        Arc::new(SigCache::new(DEFAULT_CAP)),
    )
}

fn rr(s: &str) -> Record {
    new_rr(s).unwrap().unwrap()
}

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn msg(
    qname: Option<(&str, RecordType)>,
    rcode: ResponseCode,
    answer: &[&str],
    ns: &[&str],
    extra: &[&str],
) -> Message {
    let mut m = Message::new(0, MessageType::Response, OpCode::Query);
    if let Some((q, t)) = qname {
        m.add_query(Query::query(n(q), t));
    }
    m.metadata.response_code = rcode;
    m.answers = answer.iter().map(|s| rr(s)).collect();
    m.authorities = ns.iter().map(|s| rr(s)).collect();
    m.additionals = extra.iter().map(|s| rr(s)).collect();
    m
}

fn sign(d: &Dnssec, m: &mut Message, zone: &str) {
    d.sign_msg(m, zone, SystemTime::now(), SERVER);
}

fn sign_at(d: &Dnssec, m: &mut Message, zone: &str, now: SystemTime) {
    d.sign_msg(m, zone, now, SERVER);
}

/// `section`: does `rrs` hold exactly `n` RRSIGs?
fn section(rrs: &[Record], n: usize) -> bool {
    rrs.iter().filter(|r| r.record_type() == RecordType::RRSIG).count() == n
}

fn nsec_of(rrs: &[Record]) -> Option<&NSEC> {
    rrs.iter().find_map(|r| match &r.data {
        RData::DNSSEC(DNSSECRData::NSEC(x)) => Some(x),
        _ => None,
    })
}

fn rrsig_of(r: &Record) -> Option<&RRSIG> {
    match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => Some(s),
        _ => None,
    }
}

fn bitmap(n: &NSEC) -> Vec<RecordType> {
    n.type_bit_maps().collect()
}

/// `correctNsecForDS`: NS, NSEC and RRSIG in the bitmap and no SOA.
fn correct_nsec_for_ds(n: &NSEC) -> bool {
    let b = bitmap(n);
    !b.contains(&RecordType::SOA)
        && [RecordType::NS, RecordType::NSEC, RecordType::RRSIG]
            .iter()
            .all(|t| b.contains(t))
}

/// Verify every RRSIG in every section of `m` against the RRset it covers
/// (in the same section) with the key whose tag it names.
fn verify_all(m: &Message, keys: &[Key]) -> usize {
    let mut verified = 0;
    for sec in [&m.answers, &m.authorities, &m.additionals] {
        for r in sec.iter() {
            let Some(sig) = rrsig_of(r) else { continue };
            let input = sig.input();
            let key = keys
                .iter()
                .find(|k| k.tag == input.key_tag)
                .unwrap_or_else(|| panic!("no key with tag {}", input.key_tag));
            let rrset: Vec<&Record> = sec
                .iter()
                .filter(|x| x.record_type() == input.type_covered && x.name == r.name)
                .collect();
            assert!(!rrset.is_empty(), "RRSIG {r} covers nothing");
            let dnskey: &DNSKEY = key.dnskey();
            dnskey
                .verify_rrsig(&r.name, r.dns_class, sig, rrset.into_iter())
                .unwrap_or_else(|e| panic!("RRSIG {r} does not verify: {e}"));
            let now = unix(SystemTime::now());
            assert!(key::validity_period(sig, now), "RRSIG {r} not valid now");
            verified += 1;
        }
    }
    verified
}

// black_lies_test.go

fn test_nxdomain_msg() -> Message {
    msg(
        Some(("ww.miek.nl.", RecordType::TXT)),
        ResponseCode::NXDomain,
        &[],
        &["miek.nl.\t1800\tIN\tSOA\tlinode.atoom.net. miek.miek.nl. 1461471181 14400 3600 604800 14400"],
        &[],
    )
}

fn test_success_msg() -> Message {
    msg(
        Some(("www.miek.nl.", RecordType::TXT)),
        ResponseCode::NoError,
        &["www.miek.nl.\t1800\tIN\tTXT\t\"response\""],
        &[],
        &[],
    )
}

fn soa_denial(q: &str, t: RecordType) -> Message {
    msg(
        Some((q, t)),
        ResponseCode::NXDomain,
        &[],
        &["miek.nl.\t1800\tIN\tSOA\tlinode.atoom.net. miek.miek.nl. 1461471181 14400 3600 604800 14400"],
        &[],
    )
}

#[test]
fn zone_signing_black_lies() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = test_nxdomain_msg();
    sign(&d, &mut m, "miek.nl.");
    assert!(section(&m.authorities, 2), "Authority section should have 2 sigs");
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    let nsec_rr = m
        .authorities
        .iter()
        .find(|r| r.record_type() == RecordType::NSEC)
        .expect("Expected NSEC, got none");
    assert_eq!(nsec_rr.name, n("ww.miek.nl."));
    let x = nsec_of(&m.authorities).unwrap();
    assert_eq!(x.next_domain_name().to_ascii(), "\\000.ww.miek.nl.");
    assert_eq!(verify_all(&m, &[new_key()]), 2);
}

#[test]
fn black_lies_no_error() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = test_success_msg();
    sign(&d, &mut m, "miek.nl.");
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert_eq!(m.answers.len(), 2, "Answer section should have 2 RRs");
    assert!(m.answers.iter().any(|r| r.record_type() == RecordType::RRSIG));
    assert!(m.answers.iter().any(|r| r.record_type() == RecordType::TXT));
    assert_eq!(verify_all(&m, &[new_key()]), 1);
}

#[test]
fn black_lies_apex_nsec() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = soa_denial("miek.nl.", RecordType::NSEC);
    sign(&d, &mut m, "miek.nl.");
    assert!(m.authorities.is_empty(), "Authority section should be empty");
    assert_eq!(m.answers.len(), 2, "Answer section should have 2 RRs");
    assert!(m.answers.iter().any(|r| r.record_type() == RecordType::RRSIG));
    let x = nsec_of(&m.answers).expect("Expected NSEC in answer section");
    let b = bitmap(x);
    for t in [RecordType::SOA, RecordType::NSEC, RecordType::RRSIG] {
        assert!(b.contains(&t), "NSEC must have SOA, RRSIG and NSEC in its bitmap");
    }
    assert_eq!(verify_all(&m, &[new_key()]), 1);
}

#[test]
fn black_lies_nsec() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = soa_denial("www.miek.nl.", RecordType::NSEC);
    sign(&d, &mut m, "miek.nl.");
    assert!(m.authorities.is_empty(), "Authority section should be empty");
    assert_eq!(m.answers.len(), 2, "Answer section should have 2 RRs");
    let x = nsec_of(&m.answers).expect("Expected NSEC in answer section");
    let b = bitmap(x);
    assert!(b.contains(&RecordType::NSEC) && b.contains(&RecordType::RRSIG));
}

#[test]
fn black_lies_apex_ds() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = soa_denial("miek.nl.", RecordType::DS);
    sign(&d, &mut m, "miek.nl.");
    assert!(section(&m.authorities, 2), "Authority section should have 2 sigs");
    let x = nsec_of(&m.authorities).expect("Expected NSEC, got none");
    assert!(
        !correct_nsec_for_ds(x),
        "NSEC DS at the apex zone should cover all apex type."
    );
}

#[test]
fn black_lies_ds() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = soa_denial("sub.miek.nl.", RecordType::DS);
    sign(&d, &mut m, "miek.nl.");
    assert!(section(&m.authorities, 2), "Authority section should have 2 sigs");
    let x = nsec_of(&m.authorities).expect("Expected NSEC, got none");
    assert!(correct_nsec_for_ds(x), "NSEC DS should cover delegation type only.");
}

// black_lies_bitmap_test.go

fn test_tlsa_msg() -> Message {
    msg(
        Some(("25._tcp.example.org.", RecordType::TLSA)),
        ResponseCode::NoError,
        &[],
        &["example.org.\t1800\tIN\tSOA\tlinode.example.org. miek.example.org. 1461471181 14400 3600 604800 14400"],
        &[],
    )
}

#[test]
fn black_lies_bitmap_no_data() {
    let d = new_dnssec(&["example.org."]);
    let mut m = test_tlsa_msg();
    sign(&d, &mut m, "example.org.");
    let x = nsec_of(&m.authorities).unwrap();
    assert!(!bitmap(x).contains(&RecordType::TLSA), "{:?}", bitmap(x));
}

#[test]
fn black_lies_bitmap_name_error() {
    let d = new_dnssec(&["example.org."]);
    let mut m = test_tlsa_msg();
    m.metadata.response_code = ResponseCode::NXDomain;
    sign(&d, &mut m, "example.org.");
    let x = nsec_of(&m.authorities).unwrap();
    assert!(!bitmap(x).contains(&RecordType::TLSA), "{:?}", bitmap(x));
}

// cache_test.go

fn test_msg() -> Message {
    msg(
        None,
        ResponseCode::NoError,
        &["miek.nl.\t1703\tIN\tMX\t1 aspmx.l.google.com."],
        &["miek.nl.\t1703\tIN\tNS\tomval.tednet.nl."],
        &[],
    )
}

#[test]
fn cache_set() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = test_msg();
    let k = hash(&m.answers); // before we add the sig
    sign(&d, &mut m, "miek.nl.");
    assert!(d.get(k, SERVER).is_some(), "Signature was not added to the cache");
}

#[test]
fn cache_not_valid_expired() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = test_msg();
    let k = hash(&m.answers);
    sign_at(
        &d,
        &mut m,
        "miek.nl.",
        SystemTime::now() - Duration::from_secs(9 * 86400),
    );
    assert!(
        d.get(k, SERVER).is_none(),
        "Signature was added to the cache even though not valid"
    );
}

#[test]
fn cache_empty_sigs_not_cached() {
    let d = new_dnssec_keys(&["miek.nl."], vec![]);
    let mut m = test_msg();
    let k = hash(&m.answers);
    sign(&d, &mut m, "miek.nl.");
    assert!(d.get(k, SERVER).is_none(), "Empty signatures should not be cached");
}

#[test]
fn cache_not_valid_yet() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = test_msg();
    let k = hash(&m.answers);
    sign_at(
        &d,
        &mut m,
        "miek.nl.",
        SystemTime::now() + Duration::from_secs(9 * 86400),
    );
    assert!(
        d.get(k, SERVER).is_none(),
        "Signature was added to the cache even though not valid yet"
    );
}

#[test]
fn cache_hit_reuses_signature_and_clean_drops_old() {
    let d = new_dnssec(&["miek.nl."]);
    let mut a = test_msg();
    sign(&d, &mut a, "miek.nl.");
    let mut b = test_msg();
    sign(&d, &mut b, "miek.nl.");
    assert_eq!(
        a.answers, b.answers,
        "a cache hit returns the same (randomized ECDSA) signature"
    );
    // a changed TTL is a different RRset
    let mut c = test_msg();
    c.answers[0].ttl = 1702;
    let k = hash(&c.answers);
    assert!(d.get(k, SERVER).is_none());

    let before = d.cache.len();
    assert!(before > 0);
    clean(&d.cache);
    assert_eq!(d.cache.len(), before, "fresh signatures stay");
    let mut old = test_msg();
    old.answers[0].ttl = 1;
    old.authorities[0].ttl = 1;
    sign_at(
        &d,
        &mut old,
        "miek.nl.",
        SystemTime::now() - Duration::from_secs(7 * 86400),
    );
    assert_eq!(d.cache.len(), before + 2);
    clean(&d.cache);
    assert_eq!(d.cache.len(), before, "signatures near expiry are dropped");
}

// dnssec_test.go

#[test]
fn zone_signing() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = test_msg();
    sign(&d, &mut m, "miek.nl.");
    assert!(section(&m.answers, 1), "Answer section should have 1 RRSIG");
    assert!(section(&m.authorities, 1), "Authority section should have 1 RRSIG");
    assert_eq!(verify_all(&m, &[new_key()]), 2);
}

#[test]
fn zone_signing_double() {
    let mut d = new_dnssec(&["miek.nl."]);
    let key1 = key_from(PUB_KEY1, PRIV_KEY1);
    let mut keys = (*d.keys).clone();
    keys.push(key1.clone());
    d.keys = Arc::new(keys);
    let mut m = test_msg();
    sign(&d, &mut m, "miek.nl.");
    assert!(section(&m.answers, 2), "Answer section should have 2 RRSIGs");
    assert!(section(&m.authorities, 2), "Authority section should have 2 RRSIGs");
    assert_eq!(verify_all(&m, &[new_key(), key1]), 4);
}

/// A key for miek.nl can be used for example.org.
#[test]
fn signing_different_zone() {
    let d = new_dnssec(&["example.org."]);
    let mut m = msg(
        None,
        ResponseCode::NoError,
        &["example.org.\t1703\tIN\tMX\t1 aspmx.l.google.com."],
        &["example.org.\t1703\tIN\tNS\tomval.tednet.nl."],
        &[],
    );
    sign(&d, &mut m, "example.org.");
    assert!(section(&m.answers, 1), "Answer section should have 1 RRSIG");
    assert!(section(&m.authorities, 1), "Authority section should have 1 RRSIG");
}

#[test]
fn signing_cname() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = msg(
        None,
        ResponseCode::NoError,
        &["www.miek.nl.\t1800\tIN\tCNAME\ta.miek.nl."],
        &[],
        &[],
    );
    sign(&d, &mut m, "miek.nl.");
    assert!(section(&m.answers, 1), "Answer section should have 1 RRSIG");
}

#[test]
fn signing_dname() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = msg(
        None,
        ResponseCode::NoError,
        &[
            "a.dname.miek.nl.\t1800\tIN\tCNAME\ta.test.miek.nl.",
            "a.test.miek.nl.\t1800\tIN\tA\t139.162.196.78",
            "dname.miek.nl.\t1800\tIN\tDNAME\ttest.miek.nl.",
        ],
        &[],
        &[],
    );
    // We sign *everything* we see, also the synthesized CNAME.
    sign(&d, &mut m, "miek.nl.");
    assert!(section(&m.answers, 3), "Answer section should have 3 RRSIGs");
    assert_eq!(verify_all(&m, &[new_key()]), 3);
}

#[test]
fn signing_empty() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = msg(
        Some(("a.miek.nl.", RecordType::A)),
        ResponseCode::NoError,
        &[],
        &["miek.nl.\t1800\tIN\tSOA\tns.miek.nl. dnsmaster.miek.nl. 2017100301 200 100 604800 3600"],
        &[],
    );
    sign(&d, &mut m, "miek.nl.");
    assert!(section(&m.authorities, 2), "Authority section should have 2 RRSIGs");
}

fn delegation(signed: bool) -> Message {
    let ds = format!("sub.{DS_KEY}");
    let mut ns = vec!["sub.miek.nl.\t1800\tIN\tNS\tns1.sub.miek.nl."];
    if signed {
        ns.push(&ds);
    }
    msg(
        Some(("sub.miek.nl.", RecordType::NS)),
        ResponseCode::NoError,
        &[],
        &ns,
        &["ns1.sub.miek.nl.\t1800\tIN\tA\t192.0.2.1"],
    )
}

#[test]
fn delegation_signed() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = delegation(true);
    sign(&d, &mut m, "miek.nl.");
    assert!(section(&m.authorities, 1), "Authority section should have 1 RRSIGs");
    assert!(section(&m.additionals, 0), "Extra section should not have RRSIGs");
    assert_eq!(verify_all(&m, &[new_key()]), 1);
}

#[test]
fn delegation_unsigned() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = delegation(false);
    sign(&d, &mut m, "miek.nl.");
    assert!(section(&m.authorities, 1), "Authority section should have 1 RRSIG");
    assert!(section(&m.additionals, 0), "Extra section should not have RRSIG");
    let x = nsec_of(&m.authorities).expect("Authority section should hold a NSEC record");
    let sig = m
        .authorities
        .iter()
        .find_map(rrsig_of)
        .expect("Authority section should hold a RRSIG record");
    assert_eq!(sig.input().type_covered, RecordType::NSEC);
    assert!(correct_nsec_for_ds(x), "NSEC as invalid TypeBitMap for a DS");
    assert_eq!(x.next_domain_name().to_ascii(), "sub\\000.miek.nl.");
    assert_eq!(verify_all(&m, &[new_key()]), 1);
}

/// When signing fails mid-way through several keys, `sign` returns an
/// error and no partial signatures.
#[test]
fn sign_returns_nil_on_error() {
    let k1 = new_key();
    let broken = k1.broken();
    let d = new_dnssec_keys(&["miek.nl."], vec![k1, broken]);
    let m = test_msg();
    let (incep, expir) = incep_expir(SystemTime::now());
    let r = d.sign(&m.answers, &n("miek.nl."), 1703, incep, expir, SERVER);
    assert!(r.is_err(), "Expected error from broken key");
}

// cname_signing_test.go

/// A CNAME whose target is outside our zones: only the CNAME is signed.
#[test]
fn signing_cname_out_of_zone() {
    let d = new_dnssec(&["miek.nl."]);
    let mut m = msg(
        None,
        ResponseCode::NoError,
        &[
            "www.miek.nl.\t1800\tIN\tCNAME\ttarget.example.com.",
            "target.example.com.\t1800\tIN\tA\t127.0.0.1",
        ],
        &[],
        &[],
    );
    sign(&d, &mut m, "miek.nl.");
    let sigs: Vec<&RRSIG> = m.answers.iter().filter_map(rrsig_of).collect();
    assert_eq!(sigs.len(), 1, "exactly 1 RRSIG (the in-zone CNAME)");
    assert_eq!(sigs[0].input().type_covered, RecordType::CNAME);
    assert_eq!(sigs[0].input().signer_name, n("miek.nl."));
}

/// A CNAME target in another of our zones: both signed, each by its zone.
#[test]
fn signing_cname_cross_zone() {
    let d = new_dnssec(&["miek.nl.", "example.org."]);
    let mut m = msg(
        None,
        ResponseCode::NoError,
        &[
            "www.miek.nl.\t1800\tIN\tCNAME\tdb.example.org.",
            "db.example.org.\t1800\tIN\tA\t127.0.0.1",
        ],
        &[],
        &[],
    );
    sign(&d, &mut m, "miek.nl.");
    let sigs: Vec<&RRSIG> = m.answers.iter().filter_map(rrsig_of).collect();
    assert_eq!(sigs.len(), 2, "CNAME + cross-zone A");
    for s in sigs {
        match s.input().type_covered {
            RecordType::CNAME => assert_eq!(s.input().signer_name, n("miek.nl.")),
            RecordType::A => assert_eq!(s.input().signer_name, n("example.org.")),
            t => panic!("unexpected RRSIG covering {t}"),
        }
    }
}

// More algorithms and split keys.

#[test]
fn every_algorithm_verifies() {
    for (public, private) in [
        (P384_PUB, P384_PRIV),
        (ED25519_PUB, ED25519_PRIV),
        (RSASHA512_PUB, RSASHA512_PRIV),
        (PUB_KEY1, PRIV_KEY1),
    ] {
        let k = key_from(public, private);
        let d = new_dnssec_keys(&["example.org."], vec![k.clone()]);
        let mut m = msg(
            Some(("a.example.org.", RecordType::A)),
            ResponseCode::NoError,
            &[
                "a.example.org.\t300\tIN\tA\t192.0.2.1",
                "a.example.org.\t300\tIN\tA\t192.0.2.2",
            ],
            &[],
            &[],
        );
        sign(&d, &mut m, "example.org.");
        assert_eq!(verify_all(&m, std::slice::from_ref(&k)), 1, "{public}");
        let mut m = msg(
            Some(("nx.example.org.", RecordType::A)),
            ResponseCode::NXDomain,
            &[],
            &["example.org.\t1800\tIN\tSOA\tns.example.org. h.example.org. 1 2 3 4 5"],
            &[],
        );
        sign(&d, &mut m, "example.org.");
        assert_eq!(verify_all(&m, &[k]), 2, "{public}");
    }
    let k = key_from(CLUSTER_PUB, CLUSTER_PRIV);
    let d = new_dnssec_keys(&["cluster.local."], vec![k.clone()]);
    let mut m = msg(
        None,
        ResponseCode::NoError,
        &["svc.cluster.local.\t5\tIN\tA\t10.0.0.1"],
        &[],
        &[],
    );
    sign(&d, &mut m, "cluster.local.");
    assert_eq!(verify_all(&m, &[k]), 1);
}

#[test]
fn rsasha1_is_rejected() {
    let record = new_rr(RSASHA1_PUB).unwrap().unwrap();
    let e = key::key_from_parts(record, RSASHA1_PRIV).unwrap_err();
    assert!(e.contains("unsupported algorithm 5"), "{e}");
}

#[test]
fn private_key_must_match() {
    let record = new_rr(PUB_KEY).unwrap().unwrap();
    assert!(key::key_from_parts(record.clone(), PRIV_KEY1).is_err());
    let e = key::key_from_parts(record, P384_PRIV).unwrap_err();
    assert_eq!(e, "bad private key");
}

#[tokio::test]
async fn split_keys_sign_dnskey_with_ksk_only() {
    let ksk = key_from(PUB_KEY1, PRIV_KEY1); // 257
    let zsk = key_from(P384_PUB, P384_PRIV); // 256
    let mut d = new_dnssec_keys(&["example.org."], vec![ksk.clone(), zsk.clone()]);
    d.splitkeys = true;
    let mut req = query("example.org.", RecordType::DNSKEY, true);
    req.msg.metadata.id = 7;
    let (rc, w) = serve(&d, &req).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    let m = &w.msgs[0];
    let sigs: Vec<&RRSIG> = m.answers.iter().filter_map(rrsig_of).collect();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].input().key_tag, ksk.tag);
    assert_eq!(verify_all(m, &[ksk.clone(), zsk.clone()]), 1);

    let mut m = test_success_msg();
    m.queries[0] = Query::query(n("www.example.org."), RecordType::TXT);
    m.answers[0].name = n("www.example.org.");
    sign(&d, &mut m, "example.org.");
    let sigs: Vec<&RRSIG> = m.answers.iter().filter_map(rrsig_of).collect();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].input().key_tag, zsk.tag);
}

// setup_test.go

#[test]
fn setup_dnssec() {
    let dir = TempDir::new("dnssec-setup");
    dir.write("Kcluster.local.key", CLUSTER_PUB);
    dir.write("Kcluster.local.private", CLUSTER_PRIV);
    dir.write(
        "ksk_Kcluster.local.key",
        &CLUSTER_PUB.replace("DNSKEY\t256", "DNSKEY\t257"),
    );
    dir.write("ksk_Kcluster.local.private", CLUSTER_PRIV);

    struct Case {
        input: &'static str,
        should_err: bool,
        zones: &'static [&'static str],
        splitkeys: bool,
        capacity: usize,
        err: &'static str,
    }
    let ok = |input, zones, splitkeys, capacity| Case {
        input,
        should_err: false,
        zones,
        splitkeys,
        capacity,
        err: "",
    };
    let fail = |input, err| Case {
        input,
        should_err: true,
        zones: &[],
        splitkeys: false,
        capacity: DEFAULT_CAP,
        err,
    };
    let tests = [
        ok("dnssec", &[], false, DEFAULT_CAP),
        ok("dnssec example.org", &["example.org."], false, DEFAULT_CAP),
        ok("dnssec 10.0.0.0/8", &["10.in-addr.arpa."], false, DEFAULT_CAP),
        ok(
            "dnssec example.org {\n cache_capacity 100\n}",
            &["example.org."],
            false,
            100,
        ),
        ok(
            "dnssec cluster.local {\n key file Kcluster.local\n}",
            &["cluster.local."],
            false,
            DEFAULT_CAP,
        ),
        ok(
            "dnssec example.org cluster.local {\n key file Kcluster.local\n}",
            &["example.org.", "cluster.local."],
            false,
            DEFAULT_CAP,
        ),
        // fails
        fail("dnssec example.org {\n key file Kcluster.local\n}", "can not sign any"),
        fail("dnssec example.org {\n key\n}", "argument count"),
        fail("dnssec example.org {\n key file\n}", "argument count"),
        fail("dnssec\ndnssec", ""),
        ok(
            "dnssec cluster.local {\n key file Kcluster.local\n key file ksk_Kcluster.local\n}",
            &["cluster.local."],
            true,
            DEFAULT_CAP,
        ),
        // more errors
        fail(
            "dnssec cluster.local {\n key file Knothere\n}",
            "Knothere.key: no such file or directory",
        ),
        fail("dnssec cluster.local {\n cache_capacity x\n}", "invalid syntax"),
        fail("dnssec cluster.local {\n foo\n}", "unknown property 'foo'"),
        fail(
            "dnssec cluster.local {\n key aws_secretsmanager secret\n}",
            "not supported",
        ),
    ];
    for (i, tc) in tests.iter().enumerate() {
        let root = dir.0.clone();
        let res = with_controller("dnssec", tc.input, |c| {
            c.config.root = Some(root);
            dnssec_parse(c).map_err(|e| e.to_string())
        });
        match res {
            Err(e) => {
                assert!(tc.should_err, "Test {i}: unexpected error {e} for {}", tc.input);
                assert!(e.contains(tc.err), "Test {i}: error {e:?} should contain {:?}", tc.err);
            }
            Ok(cfg) => {
                assert!(!tc.should_err, "Test {i}: expected error for {}", tc.input);
                if !tc.zones.is_empty() {
                    assert_eq!(cfg.zones, tc.zones, "Test {i}");
                }
                assert_eq!(cfg.splitkeys, tc.splitkeys, "Test {i}");
                assert_eq!(cfg.capacity, tc.capacity, "Test {i}");
            }
        }
    }
}

// handler_test.go

const DB_MIEK_NL: &str = "
$TTL    30M
$ORIGIN miek.nl.
@       IN      SOA     linode.atoom.net. miek.miek.nl. (
                             1282630057 ; Serial
                             4H         ; Refresh
                             1H         ; Retry
                             7D         ; Expire
                             4H )       ; Negative Cache TTL
                IN      NS      linode.atoom.net.

                IN      MX      1  aspmx.l.google.com.

                IN      A       139.162.196.78
                IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735

a               IN      A       139.162.196.78
                IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735
www             IN      CNAME   a
deleg\t\t\tIN\t\tNS\t\tns01.deleg
\t\t\t\tIN\t\tDS\t\t18512 13 2 D4E806322598BC97A003EF1ACDFF352EEFF7B42DBB0D41B8224714C36AEF08D9
unsigned\t\tIN\t\tNS\t\tns01.deleg
";

fn query(name: &str, t: RecordType, do_bit: bool) -> Request {
    let mut req = crate::testutil::query(name, t, "10.240.0.1:40212");
    if do_bit {
        let mut e = Edns::new();
        e.set_max_payload(4096);
        e.set_dnssec_ok(true);
        req.msg.edns = Some(e);
    }
    req
}

async fn serve(h: &dyn Handler, req: &Request) -> (HandlerResult, CaptureWriter) {
    let mut w = CaptureWriter::new();
    let mut ctx = Context::new(".", SERVER);
    let rc = h.serve_dns(&mut ctx, &mut w, req).await;
    (rc, w)
}

/// A chain of `dnssec` and `file` set up from `body` (inside `.:53 { }`),
/// with relative paths under `root`.
fn chain(body: &str, root: &Path) -> Next {
    let blocks = parse_corefile(&format!(".:53 {{\n{body}\n}}"), "Corefile").expect("parses");
    let mut cfg = BlockConfig::new(ZoneAddr::parse(".:53", "53").unwrap());
    cfg.root = Some(root.to_path_buf());
    let mut hooks = Hooks::default();
    let factories: [(&'static str, &dyn PluginFactory); 2] = [("dnssec", &Setup), ("file", &crate::file::Setup)];
    for (name, f) in factories {
        let toks = blocks[0].tokens_for(name);
        if toks.is_empty() {
            continue;
        }
        let mut c = Controller::new(name, Dispenser::new(toks), &mut cfg, &mut hooks, ".".into());
        f.setup(&mut c).unwrap();
    }
    cfg.chain()
}

/// `test.Case` with `SortAndCheck`: compares sections after sorting, the
/// header name, TTL and type of each record, and for some types the data
/// (for RRSIG: type covered, labels and signer; for NSEC: next domain).
struct Case {
    qname: &'static str,
    qtype: RecordType,
    do_bit: bool,
    rcode: ResponseCode,
    answer: &'static [&'static str],
    ns: &'static [&'static str],
}

fn expected(rrs: &[&str]) -> Vec<Record> {
    rrs.iter()
        .map(|s| {
            // signatures in the Go tables are not checked (and some are
            // not valid base64)
            let s = if s.contains("RRSIG") {
                let mut t: Vec<&str> = s.split_whitespace().collect();
                t.pop();
                t.push("AAAA");
                t.join(" ")
            } else {
                s.to_string()
            };
            rr(&s)
        })
        .collect()
}

fn sort_key(r: &Record) -> (String, u16, u16) {
    let covered = rrsig_of(r).map(|s| u16::from(s.input().type_covered)).unwrap_or(0);
    (r.name.to_ascii().to_lowercase(), u16::from(r.record_type()), covered)
}

fn check_section(what: &str, got: &[Record], want: &[Record]) -> Result<(), String> {
    if got.len() != want.len() {
        return Err(format!(
            "{what} contained {} results, {} expected: {got:?}",
            got.len(),
            want.len()
        ));
    }
    let mut got = got.to_vec();
    let mut want = want.to_vec();
    got.sort_by_key(sort_key);
    want.sort_by_key(sort_key);
    for (i, (a, b)) in got.iter().zip(&want).enumerate() {
        if !a.name.eq_case(&b.name) || a.ttl != b.ttl || a.record_type() != b.record_type() {
            return Err(format!("{what} RR {i}: got {a}, want {b}"));
        }
        let same = match (&a.data, &b.data) {
            (RData::DNSSEC(DNSSECRData::RRSIG(x)), RData::DNSSEC(DNSSECRData::RRSIG(y))) => {
                x.input().type_covered == y.input().type_covered
                    && x.input().num_labels == y.input().num_labels
                    && x.input().signer_name.eq_case(&y.input().signer_name)
            }
            (RData::DNSSEC(DNSSECRData::NSEC(x)), RData::DNSSEC(DNSSECRData::NSEC(y))) => {
                x.next_domain_name().eq_case(y.next_domain_name())
            }
            (RData::DNSSEC(_), _) => true, // DNSKEY, DS: header only
            (x, y) => x == y,
        };
        if !same {
            return Err(format!("{what} RR {i}: got {a}, want {b}"));
        }
    }
    Ok(())
}

impl Case {
    async fn run(&self, h: &dyn Handler, keys: &[Key]) -> Message {
        let req = query(self.qname, self.qtype, self.do_bit);
        let (rc, w) = serve(h, &req).await;
        let Some(m) = w.msg().cloned() else {
            assert_eq!(result_rcode(&rc), self.rcode, "{} {}", self.qname, self.qtype);
            return Message::new(0, MessageType::Response, OpCode::Query);
        };
        assert_eq!(m.metadata.response_code, self.rcode, "{} {}", self.qname, self.qtype);
        check_section("answer", &m.answers, &expected(self.answer))
            .unwrap_or_else(|e| panic!("{} {}: {e}", self.qname, self.qtype));
        check_section("authority", &m.authorities, &expected(self.ns))
            .unwrap_or_else(|e| panic!("{} {}: {e}", self.qname, self.qtype));
        verify_all(&m, keys);
        m
    }
}

#[tokio::test]
async fn lookup_zone() {
    let dir = TempDir::new("dnssec-lookup");
    dir.write("db.miek.nl", DB_MIEK_NL);
    dir.write("Kmiek.nl.key", PUB_KEY);
    dir.write("Kmiek.nl.private", PRIV_KEY);
    let h = chain(
        "dnssec miek.nl {\n key file Kmiek.nl\n}\nfile db.miek.nl miek.nl",
        &dir.0,
    )
    .unwrap();
    let ok = ResponseCode::NoError;
    let cases = [
        Case {
            qname: "miek.nl.",
            qtype: RecordType::DNSKEY,
            do_bit: false,
            rcode: ok,
            answer: &[
                "miek.nl.\t3600\tIN\tDNSKEY\t257 3 13 0J8u0XJ9GNGFEBXuAmLu04taHG4BXPP3gwhetiOUMnGA+x09nqzgF5IYOyjWB7N3rXqQbnOSILhH1hnuyh7mmA==",
            ],
            ns: &[],
        },
        Case {
            qname: "miek.nl.",
            qtype: RecordType::NS,
            do_bit: true,
            rcode: ok,
            answer: &[
                "miek.nl.\t1800\tIN\tNS\tlinode.atoom.net.",
                "miek.nl.\t1800\tIN\tRRSIG\tNS 13 2 1800 20220101121212 20220201121212 18512 miek.nl. RandomNotChecked",
            ],
            ns: &[],
        },
        Case {
            qname: "deleg.miek.nl.",
            qtype: RecordType::NS,
            do_bit: true,
            rcode: ok,
            answer: &[],
            ns: &[
                "deleg.miek.nl.\t1800\tIN\tDS\t18512 13 2 D4E806322598BC97A003EF1ACDFF352EEFF7B42DBB0D41B8224714C36AEF08D9",
                "deleg.miek.nl.\t1800\tIN\tNS\tns01.deleg.miek.nl.",
                "deleg.miek.nl.\t1800\tIN\tRRSIG\tDS 13 3 1800 20220101121212 20220201121212 18512 miek.nl. RandomNotChecked",
            ],
        },
        Case {
            qname: "unsigned.miek.nl.",
            qtype: RecordType::NS,
            do_bit: true,
            rcode: ok,
            answer: &[],
            ns: &[
                "unsigned.miek.nl.\t1800\tIN\tNS\tns01.deleg.miek.nl.",
                "unsigned.miek.nl.\t1800\tIN\tNSEC\tunsigned\\000.miek.nl. NS RRSIG NSEC",
                "unsigned.miek.nl.\t1800\tIN\tRRSIG\tNSEC 13 3 1800 20220101121212 20220201121212 18512 miek.nl. RandomNotChecked",
            ],
        },
        // DS should not come from dnssec plugin
        Case {
            qname: "deleg.miek.nl.",
            qtype: RecordType::DS,
            do_bit: false,
            rcode: ok,
            answer: &[
                "deleg.miek.nl.\t1800\tIN\tDS\t18512 13 2 D4E806322598BC97A003EF1ACDFF352EEFF7B42DBB0D41B8224714C36AEF08D9",
            ],
            ns: &["miek.nl.\t1800\tIN\tNS\tlinode.atoom.net."],
        },
        Case {
            qname: "unsigned.miek.nl.",
            qtype: RecordType::DS,
            do_bit: false,
            rcode: ok,
            answer: &[],
            ns: &["miek.nl.\t1800\tIN\tSOA\tlinode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"],
        },
        Case {
            qname: "miek.nl.",
            qtype: RecordType::DS,
            do_bit: true,
            rcode: ok,
            answer: &[],
            ns: &[
                "miek.nl.\t1800\tIN\tNSEC\t\\000.miek.nl. A HINFO NS SOA MX TXT AAAA LOC SRV CERT SSHFP RRSIG NSEC DNSKEY TLSA HIP OPENPGPKEY SPF",
                "miek.nl.\t1800\tIN\tRRSIG\tNSEC 13 2 1800 20220101121212 20220201121212 18512 miek.nl. RandomNotChecked",
                "miek.nl.\t1800\tIN\tRRSIG\tSOA 13 2 3600 20171220141741 20171212111741 18512 miek.nl. 8bLTReqmuQtw==",
                "miek.nl.\t1800\tIN\tSOA\tlinode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400",
            ],
        },
        Case {
            qname: "deleg.miek.nl.",
            qtype: RecordType::DS,
            do_bit: true,
            rcode: ok,
            answer: &[
                "deleg.miek.nl.\t1800\tIN\tDS\t18512 13 2 D4E806322598BC97A003EF1ACDFF352EEFF7B42DBB0D41B8224714C36AEF08D9",
                "deleg.miek.nl.\t1800\tIN\tRRSIG\tDS 13 3 1800 20220101121212 20220201121212 18512 miek.nl. RandomNotChecked",
            ],
            ns: &[
                "miek.nl.\t1800\tIN\tNS\tlinode.atoom.net.",
                "miek.nl.\t1800\tIN\tRRSIG\tNS 13 2 3600 20161217114912 20161209084912 18512 miek.nl. ad9gA8VWgF1H8ze9/0Rk2Q==",
            ],
        },
        Case {
            qname: "unsigned.miek.nl.",
            qtype: RecordType::DS,
            do_bit: true,
            rcode: ok,
            answer: &[],
            ns: &[
                "miek.nl.\t1800\tIN\tRRSIG\tSOA 13 2 3600 20171220141741 20171212111741 18512 miek.nl. 8bLTReqmuQtw==",
                "miek.nl.\t1800\tIN\tSOA\tlinode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400",
                "unsigned.miek.nl.\t1800\tIN\tNSEC\t\\000.unsigned.miek.nl. NS RRSIG NSEC",
                "unsigned.miek.nl.\t1800\tIN\tRRSIG\tNSEC 13 3 1800 20220101121212 20220201121212 18512 miek.nl. RandomNotChecked",
            ],
        },
        Case {
            qname: "miek.nl.",
            qtype: RecordType::MX,
            do_bit: false,
            rcode: ok,
            answer: &["miek.nl.\t1800\tIN\tMX\t1 aspmx.l.google.com."],
            ns: &["miek.nl.\t1800\tIN\tNS\tlinode.atoom.net."],
        },
        Case {
            qname: "miek.nl.",
            qtype: RecordType::MX,
            do_bit: true,
            rcode: ok,
            answer: &[
                "miek.nl.\t1800\tIN\tMX\t1 aspmx.l.google.com.",
                "miek.nl.\t1800\tIN\tRRSIG\tMX 13 2 3600 20160503192428 20160425162428 18512 miek.nl. 4nxuGKitXjPVA9zP1JIUvA09",
            ],
            ns: &[
                "miek.nl.\t1800\tIN\tNS\tlinode.atoom.net.",
                "miek.nl.\t1800\tIN\tRRSIG\tNS 13 2 3600 20161217114912 20161209084912 18512 miek.nl. ad9gA8VWgF1H8ze9/0Rk2Q==",
            ],
        },
        Case {
            qname: "www.miek.nl.",
            qtype: RecordType::AAAA,
            do_bit: true,
            rcode: ok,
            answer: &[
                "a.miek.nl.\t1800\tIN\tAAAA\t2a01:7e00::f03c:91ff:fef1:6735",
                "a.miek.nl.\t1800\tIN\tRRSIG\tAAAA 13 3 3600 20160503193047 20160425163047 18512 miek.nl. UAyMG+gcnoXW3",
                "www.miek.nl.\t1800\tIN\tCNAME\ta.miek.nl.",
                "www.miek.nl.\t1800\tIN\tRRSIG\tCNAME 13 3 3600 20160503193047 20160425163047 18512 miek.nl. E3qGZn",
            ],
            ns: &[
                "miek.nl.\t1800\tIN\tNS\tlinode.atoom.net.",
                "miek.nl.\t1800\tIN\tRRSIG\tNS 13 2 3600 20161217114912 20161209084912 18512 miek.nl. ad9gA8VWgF1H8ze9/0Rk2Q==",
            ],
        },
        Case {
            qname: "wwwww.miek.nl.",
            qtype: RecordType::AAAA,
            do_bit: true,
            rcode: ok,
            answer: &[],
            ns: &[
                "miek.nl.\t1800\tIN\tRRSIG\tSOA 13 2 3600 20171220135446 20171212105446 18512 miek.nl. hCRzzjYz6w==",
                "miek.nl.\t1800\tIN\tSOA\tlinode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400",
                "wwwww.miek.nl.\t1800\tIN\tNSEC\t\\000.wwwww.miek.nl. A HINFO TXT LOC SRV CERT SSHFP RRSIG NSEC TLSA HIP OPENPGPKEY SPF",
                "wwwww.miek.nl.\t1800\tIN\tRRSIG\tNSEC 13 3 3600 20171220135446 20171212105446 18512 miek.nl. cVUQWs8xw==",
            ],
        },
        Case {
            qname: "miek.nl.",
            qtype: RecordType::HINFO,
            do_bit: true,
            rcode: ok,
            answer: &[],
            ns: &[
                "miek.nl.\t1800\tIN\tNSEC\t\\000.miek.nl. A NS SOA MX TXT AAAA LOC SRV CERT SSHFP RRSIG NSEC DNSKEY TLSA HIP OPENPGPKEY SPF",
                "miek.nl.\t1800\tIN\tRRSIG\tNSEC 13 2 3600 20171220141741 20171212111741 18512 miek.nl. GuXROL7Uu+UiPcg==",
                "miek.nl.\t1800\tIN\tRRSIG\tSOA 13 2 3600 20171220141741 20171212111741 18512 miek.nl. 8bLTReqmuQtw==",
                "miek.nl.\t1800\tIN\tSOA\tlinode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400",
            ],
        },
        // CoreDNS's test puts test.ErrorHandler (SERVFAIL) after file;
        // here file is last in the chain and refuses names outside its zones
        Case {
            qname: "www.example.org.",
            qtype: RecordType::AAAA,
            do_bit: true,
            rcode: ResponseCode::Refused,
            answer: &[],
            ns: &[],
        },
    ];
    let keys = [new_key()];
    for tc in &cases {
        tc.run(h.as_ref(), &keys).await;
    }
    // the NSEC bitmaps of denials leave out the query type
    for tc in &cases {
        let m = tc.run(h.as_ref(), &keys).await;
        if let Some(x) = nsec_of(&m.authorities)
            && tc.rcode == ok
            && m.answers.is_empty()
            && !m.authorities.iter().any(|r| r.record_type() == RecordType::DS)
            && tc.qtype != RecordType::NS
            && tc.qtype != RecordType::DS
        {
            assert!(!bitmap(x).contains(&tc.qtype), "{}: bitmap contains qtype", tc.qname);
        }
    }
}

#[tokio::test]
async fn lookup_dnskey() {
    let d = new_dnssec(&["miek.nl."]);
    let cases = [
        Case {
            qname: "miek.nl.",
            qtype: RecordType::DNSKEY,
            do_bit: false,
            rcode: ResponseCode::NoError,
            answer: &[
                "miek.nl.\t3600\tIN\tDNSKEY\t257 3 13 0J8u0XJ9GNGFEBXuAmLu04taHG4BXPP3gwhetiOUMnGA+x09nqzgF5IYOyjWB7N3rXqQbnOSILhH1hnuyh7mmA==",
            ],
            ns: &[],
        },
        Case {
            qname: "miek.nl.",
            qtype: RecordType::DNSKEY,
            do_bit: true,
            rcode: ResponseCode::NoError,
            answer: &[
                "miek.nl.\t3600\tIN\tDNSKEY\t257 3 13 0J8u0XJ9GNGFEBXuAmLu04taHG4BXPP3gwhetiOUMnGA+x09nqzgF5IYOyjWB7N3rXqQbnOSILhH1hnuyh7mmA==",
                "miek.nl.\t3600\tIN\tRRSIG\tDNSKEY 13 2 3600 20160503150844 20160425120844 18512 miek.nl. Iw/kNOyM",
            ],
            ns: &[],
        },
    ];
    for tc in &cases {
        let req = query(tc.qname, tc.qtype, tc.do_bit);
        let (_, w) = serve(&d, &req).await;
        assert!(w.msgs[0].metadata.authoritative, "Authoritative Answer should be true");
        tc.run(&d, &[new_key()]).await;
    }
}

#[tokio::test]
async fn no_do_bit_passes_through() {
    let d = Dnssec {
        next: crate::testutil::reply(|r| {
            let mut m = r.reply();
            m.answers.push(Record::from_rdata(
                r.qname().clone(),
                60,
                RData::A(kerndns_core::proto::rr::rdata::A::new(192, 0, 2, 1)),
            ));
            m
        }),
        ..new_dnssec(&["miek.nl."])
    };
    let (_, w) = serve(&d, &query("a.miek.nl.", RecordType::A, false)).await;
    assert_eq!(w.msgs[0].answers.len(), 1);
    let (_, w) = serve(&d, &query("a.miek.nl.", RecordType::A, true)).await;
    assert_eq!(w.msgs[0].answers.len(), 2);
    // outside the zones: untouched
    let (_, w) = serve(&d, &query("a.example.org.", RecordType::A, true)).await;
    assert_eq!(w.msgs[0].answers.len(), 1);
}
