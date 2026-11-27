//! `siit`: synthesizes A records from AAAA records whose address embeds
//! an IPv4 address (RFC 6052) or has an explicit address mapping (RFC
//! 7757). Port of `plugin/siit`.
//!
//! ```text
//! siit {
//!     ipv6_prefix IPV6PREFIX
//!     eam IPV4 IPV6
//! }
//! ```
//!
//! The AAAA records are looked up through the server itself (`upstream`),
//! like CoreDNS. That lookup is marked as a synthesis lookup
//! ([`Context::synthesis`]), so neither `siit` nor `dns64` translate again
//! underneath it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::SystemTime;

use kerndns_core::proto::op::{Message, ResponseCode};
use kerndns_core::proto::rr::rdata::A;
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kerndns_core::typify::{ResponseType, typify};
use kerndns_core::{
    CaptureWriter, Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request,
    ResponseWriter, SetupError, async_trait, next_or_failure,
};

use crate::dns64::{Prefix, parse_cidr};
use crate::pluginmetrics as pm;

const NAME: &str = "siit";

/// The handler.
pub struct Siit {
    next: Next,
    pub prefix: Prefix,
    /// Explicit address mappings, IPv6 -> IPv4 (`eam`).
    pub eam: HashMap<Ipv6Addr, Ipv4Addr>,
}

impl Default for Siit {
    fn default() -> Self {
        Siit {
            next: None,
            prefix: Prefix::WELL_KNOWN,
            eam: HashMap::new(),
        }
    }
}

impl Siit {
    /// `requestShouldIntercept`: an A query of class IN (RFC 6147 5.1).
    fn request_should_intercept(&self, req: &Request) -> bool {
        req.qtype() == RecordType::A && req.qclass() == DNSClass::IN
    }

    /// `responseShouldSIIT`: not truncated, not NXDOMAIN, and no A record
    /// in the answer.
    fn response_should_siit(&self, m: &Message) -> bool {
        if m.metadata.truncation {
            return false;
        }
        if typify(m, SystemTime::now()) == ResponseType::NameError {
            return false;
        }
        !m.answers.iter().any(|r| r.record_type() == RecordType::A)
    }

    /// `DoSIIT`: look up the AAAA records and synthesize the answer. The
    /// flag says whether at least one A record was synthesized.
    async fn do_siit(&self, ctx: &Context, req: &Request, orig: Message) -> Result<(Message, bool), PluginError> {
        let name = Name::from_ascii(req.name()).map_err(|e| PluginError::servfail(NAME, e.to_string()))?;
        let mut lctx = ctx.clone();
        lctx.synthesis = true;
        let resp = kerndns_core::upstream::lookup(&lctx, req, &name, RecordType::AAAA)
            .await?
            .ok_or_else(|| PluginError::servfail(NAME, "siit: upstream lookup returned no response"))?;
        if resp.metadata.response_code != ResponseCode::NoError {
            return Ok((copy_error_response(req, resp), false));
        }
        Ok(self.synthesize(req, orig, resp))
    }

    /// `Synthesize`: the AAAA response with its mappable AAAA records
    /// turned into A records, as a reply to the original request. If no
    /// record could be mapped, the original response is returned.
    fn synthesize(&self, req: &Request, orig: Message, resp: Message) -> (Message, bool) {
        let mut ret = req.reply();
        ret.metadata.authoritative = resp.metadata.authoritative;
        ret.metadata.recursion_available = resp.metadata.recursion_available;
        ret.metadata.authentic_data = false;
        // persist truncated state of the AAAA response
        ret.metadata.truncation = resp.metadata.truncation;
        // 5.3.2: SIIT MUST pass the additional section unchanged
        ret.additionals = resp.additionals;
        ret.edns = resp.edns;
        ret.authorities = resp.authorities;

        // 5.1.7: the TTL is the minimum of the A RR and the SOA RR; if the
        // SOA is unknown, the minimum of the A TTL and 600
        let soa_ttl = orig
            .authorities
            .iter()
            .filter(|r| r.record_type() == RecordType::SOA)
            .map(|r| r.ttl)
            .next_back()
            .unwrap_or(600);

        let mut mapped_any = false;
        let mut answers = Vec::with_capacity(resp.answers.len());
        for rr in resp.answers {
            let RData::AAAA(aaaa) = &rr.data else {
                // 5.3.3: all other RRs MUST be returned unchanged
                answers.push(rr);
                continue;
            };
            let Some(v4) = to4(&self.eam, &self.prefix, aaaa.0) else {
                // nothing to synthesize for this record
                continue;
            };
            mapped_any = true;
            let mut a = Record::from_rdata(rr.name.clone(), rr.ttl.min(soa_ttl), RData::A(A(v4)));
            a.dns_class = rr.dns_class;
            answers.push(a);
        }
        if !mapped_any {
            return (orig, false);
        }
        ret.answers = answers;
        (ret, true)
    }
}

/// `copyErrorResponse`: a reply to the client's request carrying the
/// failed AAAA lookup's rcode, flags and sections.
fn copy_error_response(req: &Request, resp: Message) -> Message {
    let mut ret = req.reply();
    ret.metadata.response_code = resp.metadata.response_code;
    ret.metadata.authoritative = resp.metadata.authoritative;
    ret.metadata.recursion_available = resp.metadata.recursion_available;
    ret.metadata.truncation = resp.metadata.truncation;
    ret.answers = resp.answers;
    ret.authorities = resp.authorities;
    ret.additionals = resp.additionals;
    ret.edns = resp.edns;
    ret
}

impl Prefix {
    fn contains(&self, addr: &Ipv6Addr) -> bool {
        let n = u32::from(self.len);
        let mask = if n == 0 { 0 } else { u128::MAX << (128 - n) };
        u128::from(*addr) & mask == u128::from_be_bytes(self.ip) & mask
    }
}

/// `extractIPv4`: the IPv4 address embedded in `v6` under a prefix of
/// `prefix_len` bits (RFC 6052 2.2), skipping the reserved "u" octet.
fn extract_ipv4(v6: &Ipv6Addr, prefix_len: u8) -> Ipv4Addr {
    let v6 = v6.octets();
    let mut addr = [0u8; 4];
    let (mut i, mut j) = (usize::from(prefix_len) / 8, 0);
    while i < 8 {
        addr[j] = v6[i];
        i += 1;
        j += 1;
    }
    if i == 8 {
        i += 1;
    }
    while j < 4 {
        addr[j] = v6[i];
        i += 1;
        j += 1;
    }
    Ipv4Addr::from(addr)
}

/// `to4`: the IPv4 address for `addr`, from the EAM table first, then by
/// RFC 6052 translation if `addr` is in `prefix`.
fn to4(eam: &HashMap<Ipv6Addr, Ipv4Addr>, prefix: &Prefix, addr: Ipv6Addr) -> Option<Ipv4Addr> {
    if addr.to_ipv4_mapped().is_some() {
        return None;
    }
    // RFC 7757 3.3.2: search the EAM table first
    if let Some(v4) = eam.get(&addr) {
        return Some(*v4);
    }
    if prefix.contains(&addr) {
        // RFC 6052 2.2: the "u" octet MUST be zero
        if addr.octets()[8] != 0 {
            return None;
        }
        return Some(extract_ipv4(&addr, prefix.len));
    }
    None
}

#[async_trait]
impl Handler for Siit {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        // a lookup made while synthesizing (ours or dns64's) passes through
        if ctx.synthesis || !self.request_should_intercept(req) {
            return next_or_failure(NAME, &self.next, ctx, w, req).await;
        }
        // pass the request on, but intercept the response
        let mut nw = CaptureWriter::new();
        let orig = next_or_failure(NAME, &self.next, ctx, &mut nw, req).await;
        let Some(m) = nw.msgs.pop() else { return orig };

        if !self.response_should_siit(&m) {
            // like CoreDNS, a failed write is not reported
            let _ = w.write_msg(m).await;
            return orig;
        }
        let (msg, synthesized) = self.do_siit(ctx, req, m).await?;
        if synthesized {
            pm::SIIT_REQUESTS_TRANSLATED.with_label_values(&[&*ctx.server]).inc();
        }
        let rcode = msg.metadata.response_code;
        let _ = w.write_msg(msg).await;
        Ok(rcode)
    }
}

/// `parseIpv6Prefix`: an IPv6 prefix of a length RFC 6052 allows, with a
/// zero "u" octet.
fn parse_ipv6_prefix(c: &Controller<'_>, addr: &str) -> Result<Prefix, SetupError> {
    let (ip, n, total) = parse_cidr(addr).map_err(|e| SetupError::new(NAME, e))?;
    let IpAddr::V6(v6) = ip else {
        return Err(c.errf(format!("invalid netmask {total} IPv6 address: \"{ip}/{n}\"")));
    };
    let pref = Prefix {
        ip: v6.octets(),
        len: n,
    };
    if !matches!(n, 32 | 40 | 48 | 56 | 64 | 96) {
        return Err(c.errf(format!(
            "invalid prefix length \"{pref}\": must be one of /32, /40, /48, /56, /64, /96"
        )));
    }
    if pref.ip[8] != 0 {
        return Err(c.errf(format!(
            "invalid prefix \"{pref}\": reserved octet (byte 8) must be zero"
        )));
    }
    Ok(pref)
}

/// `net.ParseIP` as `%q` prints it, `"<nil>"` when it doesn't parse.
fn quoted_ip(ip: Option<IpAddr>) -> String {
    match ip {
        Some(ip) => format!("\"{ip}\""),
        None => "\"<nil>\"".into(),
    }
}

/// `parseEam`: `IPV4 IPV6`.
fn parse_eam(c: &mut Controller<'_>) -> Result<(Ipv4Addr, Ipv6Addr), SetupError> {
    let args = c.remaining_args();
    if args.len() != 2 {
        return Err(c.arg_err());
    }
    let v4 = match args[0].parse::<IpAddr>().ok() {
        None => return Err(c.errf(format!("invalid IP address: {}", quoted_ip(None)))),
        Some(IpAddr::V4(v4)) => v4,
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return Err(c.errf(format!("invalid IPv4 address: \"{v6}\""))),
        },
    };
    let v6 = match args[1].parse::<IpAddr>().ok() {
        None => return Err(c.errf(format!("invalid IP address: {}", quoted_ip(None)))),
        Some(IpAddr::V4(v4)) => return Err(c.errf(format!("invalid IPv6 address: \"{v4}\""))),
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => return Err(c.errf(format!("invalid IPv6 address: \"{v4}\""))),
            None => v6,
        },
    };
    Ok((v4, v6))
}

/// `siitParse`.
fn parse(c: &mut Controller<'_>) -> Result<Siit, SetupError> {
    let mut s = Siit::default();
    while c.next() {
        if !c.remaining_args().is_empty() {
            return Err(c.arg_err());
        }
        while c.next_block() {
            match c.val() {
                "ipv6_prefix" => {
                    if !c.next_arg() {
                        return Err(c.arg_err());
                    }
                    let v = c.val().to_string();
                    s.prefix = parse_ipv6_prefix(c, &v)?;
                }
                "eam" => {
                    let (v4, v6) = parse_eam(c)?;
                    s.eam.insert(v6, v4);
                }
                other => {
                    let msg = format!("unknown property '{other}'");
                    return Err(c.errf(msg));
                }
            }
        }
    }
    Ok(s)
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let s = parse(c)?;
        c.add_plugin(move |next| {
            Arc::new(Siit {
                next,
                prefix: s.prefix,
                eam: s.eam.clone(),
            })
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns64::Dns64;
    use crate::file::zonefile::new_rr;
    use crate::testutil::*;
    use kerndns_core::proto::op::{MessageType, OpCode, Query};
    use kerndns_core::{Protocol, Upstream};
    use std::sync::Mutex;

    fn rr(s: &str) -> Record {
        new_rr(s).unwrap().unwrap()
    }

    fn prefix(s: &str) -> Prefix {
        let (ip, len, _) = parse_cidr(s).unwrap();
        let IpAddr::V6(v6) = ip else { panic!("not IPv6") };
        Prefix { ip: v6.octets(), len }
    }

    fn parse_siit(input: &str) -> Result<Siit, String> {
        with_controller(NAME, input, |c| parse(c).map_err(|e| e.to_string()))
    }

    // setup_test.go: TestSetupSiit
    #[test]
    fn setup_siit() {
        // (input, should_err, prefix, eam)
        type Case<'a> = (&'a str, bool, &'a str, &'a [(&'a str, &'a str)]);
        let tests: &[Case] = &[
            ("siit", false, "64:ff9b::/96", &[]),
            ("siit {\n ipv6_prefix 64:dead::/96\n}", false, "64:dead::/96", &[]),
            ("siit {\n ipv6_prefix 10.0.0.0/8\n}", true, "", &[]),
            ("siit {\n ipv6_prefix foobar\n}", true, "", &[]),
            (
                "siit {\n eam 10.0.0.1 64:dead::1\n}",
                false,
                "64:ff9b::/96",
                &[("64:dead::1", "10.0.0.1")],
            ),
            (
                "siit {\n eam 10.0.0.1 64:dead::1\n eam 10.0.0.2 64:dead::2\n}",
                false,
                "64:ff9b::/96",
                &[("64:dead::1", "10.0.0.1"), ("64:dead::2", "10.0.0.2")],
            ),
            ("siit {\n eam 64:dead::1 10.0.0.1\n}", true, "", &[]),
            ("siit {\n eam foobar 64:dead::1\n}", true, "", &[]),
            ("siit {\n eam 10.0.0.1 foobar\n}", true, "", &[]),
            ("siit {\n ipv6_prefix 64:ff9b::/72\n}", true, "", &[]),
            ("siit {\n ipv6_prefix 64:ff9b::/32\n}", false, "64:ff9b::/32", &[]),
            ("siit {\n ipv6_prefix 64:ff9b::/40\n}", false, "64:ff9b::/40", &[]),
            ("siit {\n ipv6_prefix 64:ff9b::/48\n}", false, "64:ff9b::/48", &[]),
            ("siit {\n ipv6_prefix 64:ff9b::/56\n}", false, "64:ff9b::/56", &[]),
            ("siit {\n ipv6_prefix 64:ff9b::/64\n}", false, "64:ff9b::/64", &[]),
            ("siit {\n ipv6_prefix 2001:db8:122:344:ff00::/96\n}", true, "", &[]),
            ("siit {\n ipv6_prefix 2001:db8::/96\n}", false, "2001:db8::/96", &[]),
            ("siit {\n eam 10.0.0.1\n}", true, "", &[]),
            ("siit {\n eam 10.0.0.1 64:dead::1 extra\n}", true, "", &[]),
        ];
        for (i, (input, should_err, want_prefix, want_eam)) in tests.iter().enumerate() {
            match parse_siit(input) {
                Ok(s) => {
                    assert!(!should_err, "test {}: expected an error for {input}", i + 1);
                    assert_eq!(s.prefix.to_string(), *want_prefix, "test {}", i + 1);
                    let mut got: Vec<(String, String)> =
                        s.eam.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
                    got.sort();
                    let want: Vec<(String, String)> =
                        want_eam.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
                    assert_eq!(got, want, "test {}", i + 1);
                }
                Err(e) => assert!(should_err, "test {}: {input}: {e}", i + 1),
            }
        }
    }

    #[test]
    fn setup_errors() {
        let cases = [
            (
                "siit {\n ipv6_prefix 10.0.0.0/8\n}",
                "plugin/siit: Corefile:3 - Error during parsing: invalid netmask 32 IPv6 address: \"10.0.0.0/8\"",
            ),
            (
                "siit {\n ipv6_prefix foobar\n}",
                "plugin/siit: invalid CIDR address: foobar",
            ),
            (
                "siit {\n ipv6_prefix 64:ff9b::/72\n}",
                "plugin/siit: Corefile:3 - Error during parsing: invalid prefix length \"64:ff9b::/72\": must be one of /32, /40, /48, /56, /64, /96",
            ),
            (
                "siit {\n ipv6_prefix 2001:db8:122:344:ff00::/96\n}",
                "plugin/siit: Corefile:3 - Error during parsing: invalid prefix \"2001:db8:122:344:ff00::/96\": reserved octet (byte 8) must be zero",
            ),
            (
                "siit {\n eam foobar 64:dead::1\n}",
                "plugin/siit: Corefile:3 - Error during parsing: invalid IP address: \"<nil>\"",
            ),
            (
                "siit {\n eam 64:dead::1 10.0.0.1\n}",
                "plugin/siit: Corefile:3 - Error during parsing: invalid IPv4 address: \"64:dead::1\"",
            ),
            (
                "siit {\n eam 10.0.0.1 10.0.0.2\n}",
                "plugin/siit: Corefile:3 - Error during parsing: invalid IPv6 address: \"10.0.0.2\"",
            ),
            (
                "siit x",
                "plugin/siit: Corefile:2 - Error during parsing: Wrong argument count or unexpected line ending after 'x'",
            ),
            (
                "siit {\n foo\n}",
                "plugin/siit: Corefile:3 - Error during parsing: unknown property 'foo'",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(setup_err(&Setup, input), want, "{input}");
        }
        assert!(setup_ok(&Setup, "siit"));
    }

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    // siit_test.go: TestToUnmappedAAAA, TestToEamPrecedence, TestToAlgorithmicFallback
    #[test]
    fn to4_lookup_order() {
        let p = prefix("64:ff9b::/96");
        assert_eq!(to4(&HashMap::new(), &p, v6("2001:db8::1")), None);
        let eam = HashMap::from([(v6("64:ff9b::192.0.2.1"), Ipv4Addr::new(203, 0, 113, 9))]);
        assert_eq!(
            to4(&eam, &p, v6("64:ff9b::192.0.2.1")),
            Some(Ipv4Addr::new(203, 0, 113, 9))
        );
        assert_eq!(
            to4(&HashMap::new(), &p, v6("64:ff9b::192.0.2.42")),
            Some(Ipv4Addr::new(192, 0, 2, 42))
        );
        // IPv4-mapped AAAA records are never translated
        assert_eq!(to4(&HashMap::new(), &p, v6("::ffff:192.0.2.1")), None);
    }

    // siit_test.go: TestExtractIPv4RFC6052Vectors
    #[test]
    fn extract_rfc6052_vectors() {
        let cases = [
            ("2001:db8::/32", "2001:db8:c000:221::"),
            ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
            ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::"),
            ("2001:db8:122:344::/96", "2001:db8:122:344::192.0.2.33"),
        ];
        for (p, addr) in cases {
            assert_eq!(
                extract_ipv4(&v6(addr), prefix(p).len),
                Ipv4Addr::new(192, 0, 2, 33),
                "{p}"
            );
        }
    }

    // siit_test.go: TestToRejectsNonzeroUOctet, TestToAcceptsZeroUOctet
    #[test]
    fn u_octet() {
        let p = prefix("2001:db8:122:344::/64");
        assert_eq!(to4(&HashMap::new(), &p, v6("2001:db8:122:344:ffc0:2:2100:0")), None);
        assert_eq!(
            to4(&HashMap::new(), &p, v6("2001:db8:122:344:c0:2:2100::")),
            Some(Ipv4Addr::new(192, 0, 2, 33))
        );
    }

    fn msg(id: u16, rcode: ResponseCode, qtype: RecordType, answers: &[&str], ns: &[&str]) -> Message {
        let mut m = Message::new(id, MessageType::Response, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.metadata.response_code = rcode;
        m.add_query(Query::query(Name::from_ascii("example.com.").unwrap(), qtype));
        m.answers = answers.iter().map(|s| rr(s)).collect();
        m.authorities = ns.iter().map(|s| rr(s)).collect();
        m
    }

    /// `fakeUpstream`: answers the AAAA lookup with a fixed message and
    /// records the lookups and whether they were marked as synthesis.
    #[derive(Default)]
    struct FakeUpstream {
        resp: Option<Message>,
        lookups: Mutex<Vec<(String, RecordType, bool)>>,
    }

    #[async_trait]
    impl Upstream for FakeUpstream {
        async fn lookup(
            &self,
            ctx: &Context,
            _: &Request,
            name: &Name,
            qtype: RecordType,
        ) -> Result<Option<Message>, PluginError> {
            self.lookups
                .lock()
                .unwrap()
                .push((name.to_ascii(), qtype, ctx.synthesis));
            Ok(self.resp.clone())
        }
    }

    /// `fakeHandler`: writes a fixed reply and returns its rcode.
    struct FakeHandler(Message);

    #[async_trait]
    impl Handler for FakeHandler {
        fn name(&self) -> &'static str {
            "fake"
        }

        async fn serve_dns(&self, _: &mut Context, w: &mut dyn ResponseWriter, _: &Request) -> HandlerResult {
            w.write_msg(self.0.clone()).await.unwrap();
            Ok(self.0.metadata.response_code)
        }
    }

    fn handler(init: Message) -> Siit {
        Siit {
            next: Some(Arc::new(FakeHandler(init))),
            eam: HashMap::from([
                (v6("64:dead::1"), Ipv4Addr::new(10, 0, 0, 1)),
                (v6("64:dead::2"), Ipv4Addr::new(10, 0, 0, 2)),
            ]),
            ..Default::default()
        }
    }

    fn request(name: &str, id: u16) -> Request {
        let mut r = query(name, RecordType::A, "[::1]:40212");
        r.msg.metadata.id = id;
        r
    }

    async fn run(s: &Siit, up: Option<Message>, req: &Request, server: &str) -> (HandlerResult, CaptureWriter) {
        let mut ctx = Context::new(".", server);
        ctx.upstream = Some(Arc::new(FakeUpstream {
            resp: up,
            ..Default::default()
        }));
        let mut w = CaptureWriter::new();
        let rc = s.serve_dns(&mut ctx, &mut w, req).await;
        (rc, w)
    }

    fn summary(m: &Message) -> (u16, ResponseCode, bool, Vec<String>, Vec<String>, RecordType) {
        (
            m.metadata.id,
            m.metadata.response_code,
            m.metadata.truncation,
            m.answers.iter().map(|r| r.to_string()).collect(),
            m.authorities.iter().map(|r| r.to_string()).collect(),
            m.queries[0].query_type(),
        )
    }

    // siit_test.go: TestSIIT
    #[tokio::test]
    async fn siit() {
        use RecordType::{A as TA, AAAA as TAAAA};
        use ResponseCode::{NXDomain, NoError, Refused};
        let soa70 = "example.com. 70 IN SOA foo. bar. 1 1 1 1 1";
        let soa = "example.com. 3600 IN SOA foo. bar. 1 7200 900 1209600 86400";
        let s = |v: &[&str]| v.iter().map(|x| rr(x).to_string()).collect::<Vec<_>>();
        let aaaa2 = [
            "example.com. 60 IN AAAA 64:ff9b::192.0.2.42",
            "example.com. 5000 IN AAAA 64:ff9b::192.0.2.43",
        ];
        let tc = |mut m: Message| {
            m.metadata.truncation = true;
            m
        };
        // (name, initial response, AAAA response, expected)
        let cases = [
            (
                "standard flow",
                msg(42, NoError, TA, &[], &[soa70]),
                Some(msg(43, NoError, TAAAA, &aaaa2, &[])),
                (
                    42,
                    NoError,
                    false,
                    s(&["example.com. 60 IN A 192.0.2.42", "example.com. 70 IN A 192.0.2.43"]),
                    vec![],
                    TA,
                ),
            ),
            (
                "aaaa empty",
                msg(42, NoError, TA, &[], &[soa]),
                Some(msg(43, NoError, TAAAA, &[], &[soa])),
                (42, NoError, false, vec![], s(&[soa]), TA),
            ),
            (
                "aaaa not synthesized",
                msg(42, NoError, TA, &[], &[soa]),
                Some(msg(43, NoError, TAAAA, &["example.com. 60 IN AAAA 2001:db8::1"], &[])),
                (42, NoError, false, vec![], s(&[soa]), TA),
            ),
            (
                "aaaa partly synthesized",
                msg(42, NoError, TA, &[], &[soa]),
                Some(msg(
                    43,
                    NoError,
                    TAAAA,
                    &[
                        "example.com. 60 IN AAAA 2001:db8::1",
                        "example.com. 60 IN AAAA 64:ff9b::192.0.2.42",
                    ],
                    &[],
                )),
                (42, NoError, false, s(&["example.com. 60 IN A 192.0.2.42"]), vec![], TA),
            ),
            (
                "non-nxdomain error",
                msg(42, Refused, TA, &[], &[]),
                Some(msg(43, NoError, TAAAA, &aaaa2, &[])),
                (
                    42,
                    NoError,
                    false,
                    s(&["example.com. 60 IN A 192.0.2.42", "example.com. 600 IN A 192.0.2.43"]),
                    vec![],
                    TA,
                ),
            ),
            (
                "nxdomain",
                msg(42, NXDomain, TA, &[], &[soa]),
                None,
                (42, NXDomain, false, vec![], s(&[soa]), TA),
            ),
            (
                "A record",
                msg(42, NoError, TA, &["example.com. 60 IN A 127.0.0.1"], &[]),
                None,
                (42, NoError, false, s(&["example.com. 60 IN A 127.0.0.1"]), vec![], TA),
            ),
            (
                "truncated AAAA response",
                msg(42, NoError, TA, &[], &[soa70]),
                Some(tc(msg(43, NoError, TAAAA, &aaaa2, &[]))),
                (
                    42,
                    NoError,
                    true,
                    s(&["example.com. 60 IN A 192.0.2.42", "example.com. 70 IN A 192.0.2.43"]),
                    vec![],
                    TA,
                ),
            ),
            (
                "eam AAAA response",
                msg(42, NoError, TA, &[], &[soa70]),
                Some(tc(msg(
                    43,
                    NoError,
                    TAAAA,
                    &[
                        "example.com. 60 IN AAAA 64:dead::1",
                        "example.com. 5000 IN AAAA 64:dead::2",
                    ],
                    &[],
                ))),
                (
                    42,
                    NoError,
                    true,
                    s(&["example.com. 60 IN A 10.0.0.1", "example.com. 70 IN A 10.0.0.2"]),
                    vec![],
                    TA,
                ),
            ),
        ];
        for (name, init, aaaa, want) in cases {
            let (rc, w) = run(&handler(init), aaaa, &request("example.com.", 42), "dns://:53").await;
            let m = w.msg().unwrap_or_else(|| panic!("{name}: nothing written"));
            // ServeDNS returns the real result code
            assert_eq!(rc.unwrap(), m.metadata.response_code, "{name}");
            assert_eq!(summary(m), want, "{name}");
        }
    }

    // siit_test.go: TestDoSIITNegativeResponse, TestDoSIITNXDOMAIN,
    // TestServeDNSUpstreamSERVFAIL, TestServeDNSUpstreamNXDOMAIN
    #[tokio::test]
    async fn failed_aaaa_lookup() {
        let soa = "example.org. 3600 IN SOA foo. bar. 1 7200 900 1209600 86400";
        let mut fail = Message::new(9, MessageType::Response, OpCode::Query);
        fail.add_query(Query::query(
            Name::from_ascii("example.org.").unwrap(),
            RecordType::AAAA,
        ));
        fail.metadata.response_code = ResponseCode::ServFail;
        fail.metadata.recursion_available = true;
        let mut nx = fail.clone();
        nx.metadata.response_code = ResponseCode::NXDomain;
        nx.metadata.recursion_available = false;
        nx.metadata.authoritative = true;
        nx.authorities = vec![rr(soa)];

        let mut init = Message::new(42, MessageType::Response, OpCode::Query);
        init.add_query(Query::query(Name::from_ascii("example.org.").unwrap(), RecordType::A));
        for (aaaa, id) in [(fail, 42), (nx, 7)] {
            let want_rc = aaaa.metadata.response_code;
            let (rc, w) = run(
                &handler(init.clone()),
                Some(aaaa.clone()),
                &request("example.org.", id),
                "dns://:53",
            )
            .await;
            assert_eq!(rc.unwrap(), want_rc);
            let m = w.msg().expect("a response is written");
            assert_eq!(m.metadata.id, id);
            assert_eq!(m.metadata.response_code, want_rc);
            assert_eq!(m.queries[0].query_type(), RecordType::A);
            assert_eq!(m.queries[0].name().to_ascii(), "example.org.");
            assert_eq!(m.metadata.recursion_available, aaaa.metadata.recursion_available);
            assert_eq!(m.metadata.authoritative, aaaa.metadata.authoritative);
            assert_eq!(m.authorities, aaaa.authorities);
        }
    }

    // siit_test.go: TestDoSIITNilResponse, TestServeDNSUpstreamNilResponse
    #[tokio::test]
    async fn nil_upstream_response() {
        let init = msg(99, ResponseCode::NoError, RecordType::A, &[], &[]);
        let (rc, w) = run(&handler(init), None, &request("example.com.", 99), "dns://:53").await;
        let e = rc.expect_err("an upstream without a response is an error");
        assert_eq!(e.rcode, ResponseCode::ServFail);
        assert!(!w.written());
    }

    // siit_test.go: TestSynthesizePreservesAuthoritativeAndRecursive
    #[test]
    fn synthesize_preserves_flags() {
        for (aa, ra) in [(true, false), (false, true), (true, true), (false, false)] {
            let s = Siit::default();
            let req = request("example.org.", 55);
            let orig = req.reply();
            let mut resp = msg(
                1,
                ResponseCode::NoError,
                RecordType::AAAA,
                &["example.org. 60 IN AAAA 64:ff9b::192.0.2.1"],
                &[],
            );
            resp.metadata.authoritative = aa;
            resp.metadata.recursion_available = ra;
            resp.metadata.authentic_data = true;
            let (out, synthesized) = s.synthesize(&req, orig, resp);
            assert!(synthesized);
            assert_eq!(out.metadata.authoritative, aa);
            assert_eq!(out.metadata.recursion_available, ra);
            assert!(!out.metadata.authentic_data, "AD must not survive synthesis");
            assert_eq!(out.metadata.id, 55);
            assert_eq!(out.queries[0].query_type(), RecordType::A);
        }
    }

    // siit_test.go: TestServeDNSTruncatedInitialResponseNotSynthesized
    #[tokio::test]
    async fn truncated_initial_response() {
        let mut init = msg(42, ResponseCode::NoError, RecordType::A, &[], &[]);
        init.metadata.truncation = true;
        let up = Arc::new(FakeUpstream::default());
        let mut ctx = Context::new(".", "dns://:53");
        ctx.upstream = Some(up.clone());
        let mut w = CaptureWriter::new();
        let rc = handler(init)
            .serve_dns(&mut ctx, &mut w, &request("example.com.", 42))
            .await;
        assert_eq!(rc.unwrap(), ResponseCode::NoError);
        let m = w.msg().unwrap();
        assert!(m.metadata.truncation);
        assert!(m.answers.is_empty());
        assert!(up.lookups.lock().unwrap().is_empty(), "no AAAA lookup");
    }

    // siit_test.go: TestServeDNSMetricCounting
    #[tokio::test]
    async fn metric_counting() {
        let server = "dns://:5349";
        let get = || pm::SIIT_REQUESTS_TRANSLATED.with_label_values(&[server]).get();
        let aaaa = |rcode, answers: &[&str]| msg(1, rcode, RecordType::AAAA, answers, &[]);
        let cases = [
            (
                aaaa(ResponseCode::NoError, &["example.com. 60 IN AAAA 64:ff9b::192.0.2.1"]),
                1.0,
            ),
            (aaaa(ResponseCode::ServFail, &[]), 0.0),
            (
                aaaa(ResponseCode::NoError, &["example.com. 60 IN AAAA 2001:db8::1"]),
                0.0,
            ),
        ];
        for (resp, want) in cases {
            let before = get();
            let init = msg(1, ResponseCode::NoError, RecordType::A, &[], &[]);
            let _ = run(&handler(init), Some(resp), &request("example.com.", 1), server).await;
            assert_eq!(get() - before, want);
        }
    }

    #[tokio::test]
    async fn lookup_is_marked_and_marked_requests_pass() {
        let init = msg(1, ResponseCode::NoError, RecordType::A, &[], &[]);
        let up = Arc::new(FakeUpstream {
            resp: Some(msg(1, ResponseCode::NoError, RecordType::AAAA, &[], &[])),
            ..Default::default()
        });
        let mut ctx = Context::new(".", "dns://:53");
        ctx.upstream = Some(up.clone());
        let mut w = CaptureWriter::new();
        let h = handler(init);
        h.serve_dns(&mut ctx, &mut w, &request("example.com.", 1))
            .await
            .unwrap();
        assert_eq!(
            *up.lookups.lock().unwrap(),
            [("example.com.".to_string(), RecordType::AAAA, true)]
        );
        assert!(!ctx.synthesis, "the client's context is not marked");

        // a request that is itself a synthesis lookup is not intercepted
        ctx.synthesis = true;
        let mut w = CaptureWriter::new();
        h.serve_dns(&mut ctx, &mut w, &request("example.com.", 1))
            .await
            .unwrap();
        assert_eq!(up.lookups.lock().unwrap().len(), 1);
    }

    /// Re-enters `top` for every lookup, like the server does, with a
    /// fresh context that inherits the synthesis flag.
    struct Reentrant {
        top: Mutex<Option<Arc<dyn Handler>>>,
        calls: Mutex<usize>,
    }

    #[async_trait]
    impl Upstream for Reentrant {
        async fn lookup(
            &self,
            ctx: &Context,
            req: &Request,
            name: &Name,
            qtype: RecordType,
        ) -> Result<Option<Message>, PluginError> {
            {
                let mut n = self.calls.lock().unwrap();
                *n += 1;
                assert!(*n <= 4, "recursion exceeded bound: siit/dns64 re-entering each other");
            }
            let top = self.top.lock().unwrap().clone().unwrap();
            let mut r = req.clone();
            r.msg.queries = vec![Query::query(name.clone(), qtype)];
            let mut nctx = Context::new(".", "dns://:53");
            nctx.upstream = ctx.upstream.clone();
            nctx.synthesis = ctx.synthesis;
            let mut w = CaptureWriter::new();
            top.serve_dns(&mut nctx, &mut w, &r).await?;
            Ok(w.msgs.pop())
        }
    }

    // siit_dns64_test.go: TestSIITDNS64NoRecursion
    #[tokio::test]
    async fn siit_dns64_no_recursion() {
        for (remote, allow_ipv4) in [("[::1]:53", false), ("10.240.0.1:53", true)] {
            let empty = reply(|r: &Request| r.reply());
            let s: Arc<dyn Handler> = Arc::new(Siit {
                next: empty,
                ..Default::default()
            });
            let d = Arc::new(Dns64::with_next(Some(s), allow_ipv4));
            let up = Arc::new(Reentrant {
                top: Mutex::new(Some(d.clone())),
                calls: Mutex::new(0),
            });
            let mut req = query("example.org.", RecordType::A, remote);
            req.protocol = Protocol::Udp;
            let mut ctx = Context::new(".", "dns://:53");
            ctx.upstream = Some(up.clone());
            let mut w = CaptureWriter::new();
            let rc = d.serve_dns(&mut ctx, &mut w, &req).await.unwrap();
            assert_eq!(rc, ResponseCode::NoError);
            // siit's AAAA lookup + dns64's nested A lookup
            assert_eq!(*up.calls.lock().unwrap(), 2, "{remote}");
            *up.top.lock().unwrap() = None;
        }
    }
}
