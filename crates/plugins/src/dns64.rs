//! `dns64`: synthesizes AAAA records from A records (RFC 6147). Port of
//! `plugin/dns64`.
//!
//! ```text
//! dns64 [PREFIX] {
//!     prefix PREFIX
//!     translate_all
//!     allow_ipv4
//! }
//! ```
//!
//! The A records are looked up through the server itself (`upstream`), like
//! CoreDNS.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::SystemTime;

use kerndns_core::proto::op::{Message, ResponseCode};
use kerndns_core::proto::rr::rdata::AAAA;
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kerndns_core::typify::{ResponseType, typify};
use kerndns_core::{
    CaptureWriter, Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request,
    ResponseWriter, SetupError, async_trait, next_or_failure,
};

use crate::pluginmetrics as pm;

const NAME: &str = "dns64";

/// An IPv6 prefix, like the `*net.IPNet` CoreDNS keeps: the address is
/// masked to the prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub ip: [u8; 16],
    pub len: u8,
}

impl Prefix {
    /// The well-known prefix `64:ff9b::/96`.
    pub const WELL_KNOWN: Prefix = Prefix {
        ip: [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        len: 96,
    };
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.ip), self.len)
    }
}

/// `net.ParseCIDR`: the masked network and the address length in bits, with
/// Go's error message.
fn parse_cidr(s: &str) -> Result<(IpAddr, u8, u8), String> {
    let err = || format!("invalid CIDR address: {s}");
    let (addr, mask) = s.split_once('/').ok_or_else(err)?;
    let ip: IpAddr = addr.parse().map_err(|_| err())?;
    if mask.is_empty() || !mask.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err());
    }
    let total: u8 = if ip.is_ipv4() { 32 } else { 128 };
    let n: u32 = mask.parse().map_err(|_| err())?;
    if n > u32::from(total) {
        return Err(err());
    }
    let n = n as u8;
    let masked = match ip {
        IpAddr::V4(v4) => {
            let m = if n == 0 { 0 } else { u32::MAX << (32 - n) };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & m))
        }
        IpAddr::V6(v6) => {
            let m = if n == 0 { 0 } else { u128::MAX << (128 - n) };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & m))
        }
    };
    Ok((masked, n, total))
}

/// The handler.
pub struct Dns64 {
    next: Next,
    pub prefix: Prefix,
    /// Translate even if the answer has AAAA records (not RFC 6147 5.1.1).
    pub translate_all: bool,
    pub allow_ipv4: bool,
}

impl Default for Dns64 {
    fn default() -> Self {
        Dns64 {
            next: None,
            prefix: Prefix::WELL_KNOWN,
            translate_all: false,
            allow_ipv4: false,
        }
    }
}

impl Dns64 {
    /// `requestShouldIntercept`: an AAAA query of class IN, over IPv6
    /// unless `allow_ipv4` is set.
    fn request_should_intercept(&self, req: &Request) -> bool {
        if !self.allow_ipv4 && req.family() == 1 {
            return false;
        }
        req.qtype() == RecordType::AAAA && req.qclass() == DNSClass::IN
    }

    /// `responseShouldDNS64`: not NXDOMAIN, and no AAAA record in the
    /// answer (unless `translate_all`).
    fn response_should_dns64(&self, m: &Message) -> bool {
        if typify(m, SystemTime::now()) == ResponseType::NameError {
            return false;
        }
        if self.translate_all {
            return true;
        }
        !m.answers.iter().any(|r| r.record_type() == RecordType::AAAA)
    }

    /// `DoDNS64`: look up the A records and synthesize the answer.
    async fn do_dns64(&self, ctx: &Context, req: &Request, orig: &Message) -> Result<Message, PluginError> {
        let name = Name::from_ascii(req.name()).map_err(|e| PluginError::servfail(NAME, e.to_string()))?;
        let resp = kerndns_core::upstream::lookup(ctx, req, &name, RecordType::A)
            .await?
            .ok_or_else(|| PluginError::servfail(NAME, "dns64: upstream returned no response"))?;
        Ok(self.synthesize(req, orig, resp))
    }

    /// `Synthesize`: the A response with its A records turned into AAAA
    /// records, as a reply to the original request.
    fn synthesize(&self, req: &Request, orig: &Message, resp: Message) -> Message {
        let mut ret = req.reply();
        ret.metadata.response_code = resp.metadata.response_code;
        // persist truncated state of the A response
        ret.metadata.truncation = resp.metadata.truncation;
        // 5.3.2: DNS64 MUST pass the additional section unchanged
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

        ret.answers = resp
            .answers
            .into_iter()
            .map(|rr| match &rr.data {
                // 5.3.3: all other RRs MUST be returned unchanged
                RData::A(a) => {
                    let mut aaaa = Record::from_rdata(
                        rr.name.clone(),
                        rr.ttl.min(soa_ttl),
                        RData::AAAA(AAAA(to6(&self.prefix, a.0))),
                    );
                    aaaa.dns_class = rr.dns_class;
                    aaaa
                }
                _ => rr,
            })
            .collect();
        ret
    }
}

/// `to6`: the IPv6 address for `addr` under `prefix` (RFC 6052 2.2). Bits
/// 64..71 (the "u" octet) stay zero.
fn to6(prefix: &Prefix, addr: Ipv4Addr) -> Ipv6Addr {
    let addr = addr.octets();
    let n = usize::from(prefix.len) / 8;
    let mut v6 = [0u8; 16];
    let (mut i, mut j) = (0, 0);
    while i < n {
        v6[i] = prefix.ip[i];
        i += 1;
    }
    while i < 8 {
        v6[i] = addr[j];
        i += 1;
        j += 1;
    }
    if i == 8 {
        i += 1;
    }
    while j < 4 {
        v6[i] = addr[j];
        i += 1;
        j += 1;
    }
    Ipv6Addr::from(v6)
}

#[async_trait]
impl Handler for Dns64 {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        if !self.request_should_intercept(req) {
            return next_or_failure(NAME, &self.next, ctx, w, req).await;
        }
        // pass the request on, but intercept the response
        let mut nw = CaptureWriter::new();
        let orig = next_or_failure(NAME, &self.next, ctx, &mut nw, req).await;
        let Some(m) = nw.msgs.pop() else { return orig };

        if !self.response_should_dns64(&m) {
            // like CoreDNS, a failed write is not reported
            let _ = w.write_msg(m).await;
            return orig;
        }
        let msg = self.do_dns64(ctx, req, &m).await?;
        pm::DNS64_REQUESTS_TRANSLATED.with_label_values(&[&*ctx.server]).inc();
        let _ = w.write_msg(msg).await;
        Ok(ResponseCode::NoError)
    }
}

/// `parsePrefix`: an IPv6 prefix of a length RFC 6052 allows.
fn parse_prefix(c: &Controller<'_>, addr: &str) -> Result<Prefix, SetupError> {
    let (ip, n, total) = parse_cidr(addr).map_err(|e| SetupError::new(NAME, e))?;
    let pref = match ip {
        IpAddr::V6(v6) => Prefix {
            ip: v6.octets(),
            len: n,
        },
        IpAddr::V4(_) => return Err(c.errf(format!("invalid netmask {total} IPv6 address: \"{ip}/{n}\""))),
    };
    if !matches!(n, 32 | 40 | 48 | 56 | 64 | 96) {
        return Err(c.errf(format!("invalid prefix length \"{pref}\"")));
    }
    Ok(pref)
}

/// `dns64Parse`.
fn parse(c: &mut Controller<'_>) -> Result<Dns64, SetupError> {
    let mut d = Dns64::default();
    while c.next() {
        let args = c.remaining_args();
        if args.len() == 1 {
            d.prefix = parse_prefix(c, &args[0])?;
            continue;
        }
        if !args.is_empty() {
            return Err(c.arg_err());
        }
        while c.next_block() {
            match c.val() {
                "prefix" => {
                    if !c.next_arg() {
                        return Err(c.arg_err());
                    }
                    let v = c.val().to_string();
                    d.prefix = parse_prefix(c, &v)?;
                }
                "translate_all" => d.translate_all = true,
                "allow_ipv4" => d.allow_ipv4 = true,
                other => {
                    let msg = format!("unknown property '{other}'");
                    return Err(c.errf(msg));
                }
            }
        }
    }
    Ok(d)
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let d = parse(c)?;
        c.add_plugin(move |next| {
            Arc::new(Dns64 {
                next,
                prefix: d.prefix,
                translate_all: d.translate_all,
                allow_ipv4: d.allow_ipv4,
            })
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::zonefile::new_rr;
    use crate::testutil::*;
    use kerndns_core::corefile::{Dispenser, parse as parse_corefile};
    use kerndns_core::proto::op::{MessageType, OpCode, Query};
    use kerndns_core::{BlockConfig, Hooks, Upstream, ZoneAddr};
    use std::sync::Mutex;

    fn rr(s: &str) -> Record {
        new_rr(s).unwrap().unwrap()
    }

    fn parse_dns64(input: &str) -> Result<Dns64, String> {
        let blocks = parse_corefile(&format!(".:53 {{\n{input}\n}}"), "Corefile").expect("parses");
        let mut cfg = BlockConfig::new(ZoneAddr::parse(".:53", "53").unwrap());
        let mut hooks = Hooks::default();
        let mut c = Controller::new(
            NAME,
            Dispenser::new(blocks[0].tokens_for(NAME)),
            &mut cfg,
            &mut hooks,
            ".".into(),
        );
        parse(&mut c).map_err(|e| e.to_string())
    }

    fn prefix(s: &str) -> Prefix {
        let (ip, len, _) = parse_cidr(s).unwrap();
        let IpAddr::V6(v6) = ip else { panic!("not IPv6") };
        Prefix { ip: v6.octets(), len }
    }

    // setup_test.go: TestSetupDns64PrefixLengths
    #[test]
    fn setup_prefix_lengths() {
        for length in [32, 40, 48, 56, 64, 72, 80, 88, 96] {
            let p = format!("2001:db8::/{length}");
            for input in [format!("dns64 {p}"), format!("dns64 {{\n prefix {p}\n}}")] {
                let invalid = matches!(length, 72 | 80 | 88);
                assert_eq!(parse_dns64(&input).is_err(), invalid, "{input}");
            }
        }
    }

    // setup_test.go: TestSetupDns64
    #[test]
    fn setup_dns64() {
        // (input, should_err, prefix, allow_ipv4)
        let tests = [
            ("dns64", false, "64:ff9b::/96", false),
            ("dns64 64:dead::/96", false, "64:dead::/96", false),
            ("dns64 {\n translate_all\n}", false, "64:ff9b::/96", false),
            ("dns64 {\n prefix 64:ff9b::/96\n}", false, "64:ff9b::/96", false),
            ("dns64 {\n prefix 64:ff9b::/32\n}", false, "64:ff9b::/32", false),
            ("dns64 {\n prefix 64:ff9b::/52\n}", true, "", false),
            ("dns64 {\n prefix 64:ff9b::/104\n}", true, "", false),
            ("dns64 {\n prefix 8.8.8.8/24\n}", true, "", false),
            (
                "dns64 {\n prefix 2002:ac12:b083::/96\n}",
                false,
                "2002:ac12:b083::/96",
                false,
            ),
            (
                "dns64 {\n prefix 2002:c0a8:a88a::/48\n}",
                false,
                "2002:c0a8:a88a::/48",
                false,
            ),
            ("dns64 foobar {\n prefix 64:ff9b::/96\n}", true, "", false),
            ("dns64 foobar", true, "", false),
            ("dns64 {\n foobar\n}", true, "", false),
            ("dns64 {\n allow_ipv4\n}", false, "64:ff9b::/96", true),
        ];
        for (i, (input, should_err, want_prefix, allow_ipv4)) in tests.into_iter().enumerate() {
            match parse_dns64(input) {
                Ok(d) => {
                    assert!(!should_err, "test {i}: expected an error for {input}");
                    assert_eq!(d.prefix.to_string(), want_prefix, "test {i}");
                    assert_eq!(d.allow_ipv4, allow_ipv4, "test {i}");
                }
                Err(e) => assert!(should_err, "test {i}: {input}: {e}"),
            }
        }
    }

    #[test]
    fn setup_errors() {
        let cases = [
            (
                "dns64 {\n prefix 8.8.8.8/24\n}",
                "plugin/dns64: Corefile:3 - Error during parsing: invalid netmask 32 IPv6 address: \"8.8.8.0/24\"",
            ),
            (
                "dns64 {\n prefix 64:ff9b::/52\n}",
                "plugin/dns64: Corefile:3 - Error during parsing: invalid prefix length \"64:ff9b::/52\"",
            ),
            ("dns64 foobar", "plugin/dns64: invalid CIDR address: foobar"),
            (
                "dns64 foobar bar",
                "plugin/dns64: Corefile:2 - Error during parsing: Wrong argument count or unexpected line ending after 'bar'",
            ),
            (
                "dns64 {\n foobar\n}",
                "plugin/dns64: Corefile:3 - Error during parsing: unknown property 'foobar'",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(parse_dns64(input).err().as_deref(), Some(want), "{input}");
        }
        assert!(setup_ok(&Setup, "dns64 64:dead::/96"));
    }

    // dns64_test.go: TestRequestShouldIntercept
    #[test]
    fn request_should_intercept() {
        // (allow_ipv4, remote, qtype, want)
        let tests = [
            (true, "[::1]:40212", RecordType::AAAA, true),
            (true, "127.0.0.1:40212", RecordType::AAAA, true),
            (false, "127.0.0.1:40212", RecordType::AAAA, false),
            (false, "[::1]:40212", RecordType::A, false),
        ];
        for (allow_ipv4, remote, qtype, want) in tests {
            let h = Dns64 {
                allow_ipv4,
                ..Default::default()
            };
            assert_eq!(
                h.request_should_intercept(&query("example.com.", qtype, remote)),
                want,
                "{remote} {qtype}"
            );
        }
    }

    // dns64_test.go: TestTo6
    #[test]
    fn to6_cases() {
        let v4 = Ipv4Addr::new(64, 64, 64, 64);
        let cases = [
            ("64:ff9b::/96", "64:ff9b::4040:4040"),
            ("64:ff9b::/64", "64:ff9b::40:4040:4000:0"),
            ("64:ff9b::/56", "64:ff9b:0:40:40:4040::"),
            ("64::/32", "64:0:4040:4040::"),
        ];
        for (p, want) in cases {
            assert_eq!(to6(&prefix(p), v4).to_string(), want, "{p}");
        }
    }

    fn msg(rcode: ResponseCode, answers: &[&str], ns: &[&str]) -> Message {
        let mut m = Message::new(42, MessageType::Response, OpCode::Query);
        m.metadata.response_code = rcode;
        m.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::AAAA,
        ));
        m.answers = answers.iter().map(|s| rr(s)).collect();
        m.authorities = ns.iter().map(|s| rr(s)).collect();
        m
    }

    // dns64_test.go: TestResponseShould
    #[test]
    fn response_should() {
        let soa = "example.com. 3600 IN SOA foo. bar. 1 1 1 1 1";
        let aaaa = "example.com. 3600 IN AAAA ::1";
        // (response, translate_all, expected)
        let tests = [
            (msg(ResponseCode::NoError, &[aaaa], &[]), false, false),
            (msg(ResponseCode::NoError, &[], &[soa]), false, true),
            (msg(ResponseCode::NotImp, &[], &[soa]), false, true),
            (msg(ResponseCode::NXDomain, &[], &[soa]), false, false),
            (msg(ResponseCode::NoError, &[aaaa], &[]), true, true),
        ];
        for (i, (m, translate_all, want)) in tests.into_iter().enumerate() {
            let d = Dns64 {
                translate_all,
                ..Default::default()
            };
            assert_eq!(d.response_should_dns64(&m), want, "case {i}");
        }
    }

    /// `fakeUpstream`: answers the A lookup with a fixed message and
    /// records the lookups it got.
    struct FakeUpstream {
        resp: Option<Message>,
        lookups: Mutex<Vec<(String, RecordType)>>,
    }

    #[async_trait]
    impl Upstream for FakeUpstream {
        async fn lookup(
            &self,
            _: &Context,
            _: &Request,
            name: &Name,
            qtype: RecordType,
        ) -> Result<Option<Message>, PluginError> {
            self.lookups.lock().unwrap().push((name.to_ascii(), qtype));
            Ok(self.resp.clone())
        }
    }

    fn a_resp(rcode: ResponseCode, truncated: bool, answers: &[&str], ns: &[&str]) -> Message {
        let mut m = msg(rcode, answers, ns);
        m.metadata.id = 43;
        m.metadata.truncation = truncated;
        m.queries[0].set_query_type(RecordType::A);
        m
    }

    fn written(m: &Message) -> (ResponseCode, bool, Vec<String>, Vec<String>) {
        (
            m.metadata.response_code,
            m.metadata.truncation,
            m.answers.iter().map(|r| r.to_string()).collect(),
            m.authorities.iter().map(|r| r.to_string()).collect(),
        )
    }

    async fn run(d: &Dns64, up: Arc<FakeUpstream>) -> (HandlerResult, CaptureWriter) {
        let req = query("example.com.", RecordType::AAAA, "[::1]:40212");
        let mut ctx = Context::new(".", "dns://:53");
        ctx.upstream = Some(up);
        let mut w = CaptureWriter::new();
        let rc = d.serve_dns(&mut ctx, &mut w, &req).await;
        (rc, w)
    }

    /// `fakeHandler`: writes a fixed reply and returns its rcode.
    struct FakeHandler(Message);

    #[async_trait]
    impl Handler for FakeHandler {
        fn name(&self) -> &'static str {
            "fake"
        }

        async fn serve_dns(&self, _: &mut Context, w: &mut dyn ResponseWriter, r: &Request) -> HandlerResult {
            let mut m = self.0.clone();
            m.metadata.id = r.id();
            m.metadata.recursion_desired = true;
            w.write_msg(m).await.unwrap();
            Ok(self.0.metadata.response_code)
        }
    }

    fn handler(init: Message) -> Dns64 {
        Dns64 {
            next: Some(Arc::new(FakeHandler(init))),
            ..Default::default()
        }
    }

    // dns64_test.go: TestDNS64
    #[tokio::test]
    async fn dns64() {
        let soa70 = "example.com. 70 IN SOA foo. bar. 1 1 1 1 1";
        let soa = "example.com. 3600 IN SOA foo. bar. 1 7200 900 1209600 86400";
        let a = ["example.com. 60 IN A 192.0.2.42", "example.com. 5000 IN A 192.0.2.43"];
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        struct Case {
            name: &'static str,
            init: Message,
            a: Option<Message>,
            want: (ResponseCode, bool, Vec<String>, Vec<String>),
        }
        let cases = [
            Case {
                name: "standard flow",
                init: msg(ResponseCode::NoError, &[], &[soa70]),
                a: Some(a_resp(ResponseCode::NoError, false, &a, &[])),
                want: (
                    ResponseCode::NoError,
                    false,
                    // the second TTL is the SOA's, which is lower
                    s(&[
                        "example.com. 60 IN AAAA 64:ff9b::c000:22a",
                        "example.com. 70 IN AAAA 64:ff9b::c000:22b",
                    ]),
                    vec![],
                ),
            },
            Case {
                name: "a empty",
                init: msg(ResponseCode::NoError, &[], &[soa]),
                a: Some(a_resp(ResponseCode::NoError, false, &[], &[soa])),
                want: (ResponseCode::NoError, false, vec![], s(&[soa])),
            },
            Case {
                name: "non-nxdomain error",
                init: msg(ResponseCode::Refused, &[], &[]),
                a: Some(a_resp(ResponseCode::NoError, false, &a, &[])),
                want: (
                    ResponseCode::NoError,
                    false,
                    s(&[
                        "example.com. 60 IN AAAA 64:ff9b::c000:22a",
                        "example.com. 600 IN AAAA 64:ff9b::c000:22b",
                    ]),
                    vec![],
                ),
            },
            Case {
                name: "nxdomain",
                init: msg(ResponseCode::NXDomain, &[], &[soa]),
                a: None,
                want: (ResponseCode::NXDomain, false, vec![], s(&[soa])),
            },
            Case {
                name: "AAAA record",
                init: msg(
                    ResponseCode::NoError,
                    &["example.com. 60 IN AAAA ::1", "example.com. 5000 IN AAAA ::2"],
                    &[],
                ),
                a: None,
                want: (
                    ResponseCode::NoError,
                    false,
                    s(&["example.com. 60 IN AAAA ::1", "example.com. 5000 IN AAAA ::2"]),
                    vec![],
                ),
            },
            Case {
                name: "truncated A response",
                init: msg(ResponseCode::NoError, &[], &[soa70]),
                a: Some(a_resp(ResponseCode::NoError, true, &a, &[])),
                want: (
                    ResponseCode::NoError,
                    true,
                    s(&[
                        "example.com. 60 IN AAAA 64:ff9b::c000:22a",
                        "example.com. 70 IN AAAA 64:ff9b::c000:22b",
                    ]),
                    vec![],
                ),
            },
        ];
        for c in cases {
            let expect_lookup = c.a.is_some();
            let up = Arc::new(FakeUpstream {
                resp: c.a,
                lookups: Mutex::default(),
            });
            let (rc, w) = run(&handler(c.init), up.clone()).await;
            let m = w.msg().unwrap_or_else(|| panic!("{}: nothing written", c.name));
            // ServeDNS returns the real result code
            assert_eq!(rc.unwrap(), m.metadata.response_code, "{}", c.name);
            assert_eq!(written(m), c.want, "{}", c.name);
            assert_eq!(m.metadata.id, 1, "{}", c.name);
            assert_eq!(m.metadata.message_type, MessageType::Response, "{}", c.name);
            assert!(m.metadata.recursion_desired, "{}", c.name);
            assert_eq!(m.queries[0].query_type(), RecordType::AAAA, "{}", c.name);
            let lookups = up.lookups.lock().unwrap().clone();
            if expect_lookup {
                assert_eq!(lookups, [("example.com.".to_string(), RecordType::A)], "{}", c.name);
            } else {
                assert!(lookups.is_empty(), "{}: unexpected A lookup", c.name);
            }
        }
    }

    // dns64_test.go: TestDNS64NilUpstreamResponse
    #[tokio::test]
    async fn nil_upstream_response() {
        let up = Arc::new(FakeUpstream {
            resp: None,
            lookups: Mutex::default(),
        });
        let (rc, w) = run(&handler(msg(ResponseCode::NoError, &[], &[])), up).await;
        let e = rc.expect_err("an upstream without a response is an error");
        assert_eq!(e.rcode, ResponseCode::ServFail);
        assert!(!w.written());
    }

    // dns64_test.go: TestDNS64FallbackError
    #[tokio::test]
    async fn fallback_error() {
        let soa = "example.com. 60 IN SOA ns.example.com. hostmaster.example.com. 1 1 1 1 1";
        for rcode in [
            ResponseCode::NoError,
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::FormErr,
            ResponseCode::NXDomain,
            ResponseCode::NotImp,
        ] {
            let up = Arc::new(FakeUpstream {
                resp: Some(a_resp(rcode, false, &[], &[soa])),
                lookups: Mutex::default(),
            });
            let (rc, w) = run(&handler(msg(ResponseCode::NoError, &[], &[])), up).await;
            assert_eq!(rc.unwrap(), ResponseCode::NoError, "{rcode}");
            let m = w.msg().unwrap();
            assert_eq!(m.metadata.response_code, rcode);
            assert_eq!(m.metadata.id, 1);
            assert_eq!(m.queries[0].name().to_ascii(), "example.com.");
            assert_eq!(m.queries[0].query_type(), RecordType::AAAA);
            assert_eq!(written(m).3, [rr(soa).to_string()]);
        }
    }

    #[tokio::test]
    async fn translated_metric() {
        let server = "dns://:5364";
        let get = || pm::DNS64_REQUESTS_TRANSLATED.with_label_values(&[server]).get();
        let before = get();
        let up = Arc::new(FakeUpstream {
            resp: Some(a_resp(
                ResponseCode::NoError,
                false,
                &["example.com. 60 IN A 192.0.2.1"],
                &[],
            )),
            lookups: Mutex::default(),
        });
        let d = handler(msg(ResponseCode::NoError, &[], &[]));
        let req = query("example.com.", RecordType::AAAA, "[::1]:40212");
        let mut ctx = Context::new(".", server);
        ctx.upstream = Some(up);
        let mut w = CaptureWriter::new();
        d.serve_dns(&mut ctx, &mut w, &req).await.unwrap();
        assert_eq!(get(), before + 1.0);

        // not translated: an AAAA answer exists
        let d = handler(msg(ResponseCode::NoError, &["example.com. 60 IN AAAA ::1"], &[]));
        let mut w = CaptureWriter::new();
        d.serve_dns(&mut ctx, &mut w, &req).await.unwrap();
        assert_eq!(get(), before + 1.0);
    }

    #[tokio::test]
    async fn ipv4_client_passes_through() {
        let up = Arc::new(FakeUpstream {
            resp: None,
            lookups: Mutex::default(),
        });
        let d = handler(msg(ResponseCode::NoError, &[], &[]));
        let req = query("example.com.", RecordType::AAAA, "10.0.0.1:53");
        let mut ctx = Context::new(".", "dns://:53");
        ctx.upstream = Some(up.clone());
        let mut w = CaptureWriter::new();
        assert_eq!(
            d.serve_dns(&mut ctx, &mut w, &req).await.unwrap(),
            ResponseCode::NoError
        );
        assert!(w.written());
        assert!(up.lookups.lock().unwrap().is_empty());
    }
}
