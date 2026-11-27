//! `erratic`: answers A and AAAA queries with fixed records (and AXFR with a
//! small zone), dropping, delaying or truncating every Nth query. A plugin
//! for testing client behavior. Port of `plugin/erratic`.
//!
//! ```text
//! erratic {
//!     drop [AMOUNT]
//!     truncate [AMOUNT]
//!     delay [AMOUNT [DURATION]]
//! }
//! ```
//!
//! It is also an [`AutoPather`]: `autopath @erratic` gets the fixed search
//! path `a.example.org.`, `b.example.org.`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::IntErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kerndns_core::duration::parse_duration;
use kerndns_core::proto::op::{Message, ResponseCode};
use kerndns_core::proto::rr::rdata::{A, AAAA, NS, SOA};
use kerndns_core::proto::rr::{Name, RData, Record, RecordType};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
};

use crate::autopath::{AutoPather, AutoPathers};

const NAME: &str = "erratic";

/// The handler. It never calls the next plugin.
#[derive(Default)]
pub struct Erratic {
    /// Number of queries seen; shared with the readiness check.
    q: Arc<AtomicU64>,
    drop: u64,
    delay: u64,
    truncate: u64,
    duration: Duration,
    /// Undocumented: answer A queries with 30 records (to test compression).
    large: bool,
}

impl Erratic {
    /// Like `Ready`: true while the number of queries seen is in [3, 5), so
    /// that readiness flips, to aid testing.
    fn ready(q: &AtomicU64) -> bool {
        (3..5).contains(&q.load(Ordering::SeqCst))
    }

    async fn maybe_delay(&self, delay: bool) {
        if delay {
            tokio::time::sleep(self.duration).await;
        }
    }
}

#[async_trait]
impl Handler for Erratic {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn serve_dns(&self, _ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let nr = self.q.fetch_add(1, Ordering::SeqCst);
        let drop = self.drop > 0 && nr.is_multiple_of(self.drop);
        let delay = self.delay > 0 && nr.is_multiple_of(self.delay);
        // CoreDNS tests `queryNr&e.truncate == 0` (a bitwise and, not a
        // modulo); kept as is so the same queries are truncated.
        let trunc = self.truncate > 0 && nr & self.truncate == 0;

        let mut m = req.reply();
        m.metadata.authoritative = true;
        m.metadata.truncation = trunc;

        let qname = req.qname().clone();
        match req.qtype() {
            RecordType::A => {
                let rr = Record::from_rdata(qname, 0, RData::A(A(Ipv4Addr::new(192, 0, 2, 53))));
                let n = if self.large { 30 } else { 1 };
                m.answers = vec![rr; n];
            }
            RecordType::AAAA => {
                let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);
                m.answers = vec![Record::from_rdata(qname, 0, RData::AAAA(AAAA(ip)))];
            }
            RecordType::AXFR => {
                if drop {
                    return Ok(ResponseCode::NoError);
                }
                self.maybe_delay(delay).await;
                // like CoreDNS, a failed write is not reported
                let _ = w.write_msg(xfr(req, trunc)).await;
                return Ok(ResponseCode::NoError);
            }
            _ => {
                if drop {
                    return Ok(ResponseCode::NoError);
                }
                self.maybe_delay(delay).await;
                // the server writes the SERVFAIL
                return Ok(ResponseCode::ServFail);
            }
        }

        if drop {
            // nothing written: the server sends no reply
            return Ok(ResponseCode::NoError);
        }
        self.maybe_delay(delay).await;
        let _ = w.write_msg(m).await;
        Ok(ResponseCode::NoError)
    }
}

impl AutoPather for Erratic {
    /// `AutoPath`: a fixed search path, for testing.
    fn auto_path(&self, _: &Request) -> Vec<String> {
        vec!["a.example.org.".into(), "b.example.org.".into(), String::new()]
    }
}

/// `allRecords`: a small zone at `zone`. The first record is the SOA.
fn all_records(zone: &Name) -> Vec<Record> {
    let sub = |l: &str| zone.prepend_label(l).expect("short name");
    let fixed = |s: &str| Name::from_ascii(s).expect("valid name");
    vec![
        Record::from_rdata(
            zone.clone(),
            0,
            RData::SOA(SOA::new(
                fixed("sns.dns.icann.org."),
                fixed("noc.dns.icann.org."),
                2018050825,
                7200,
                3600,
                1209600,
                3600,
            )),
        ),
        Record::from_rdata(zone.clone(), 0, RData::NS(NS(sub("b")))),
        Record::from_rdata(zone.clone(), 0, RData::NS(NS(sub("a")))),
        Record::from_rdata(
            sub("a"),
            0,
            RData::AAAA(AAAA("2001:bd8::53".parse().expect("valid address"))),
        ),
        Record::from_rdata(
            sub("b"),
            0,
            RData::AAAA(AAAA("2001:500::54".parse().expect("valid address"))),
        ),
    ]
}

/// `xfr`: the whole transfer in one message, like the single envelope
/// CoreDNS sends. When truncating, the closing SOA is left out so the
/// transfer is incomplete.
fn xfr(req: &Request, truncate: bool) -> Message {
    let mut rrs = all_records(req.qname());
    if !truncate {
        rrs.push(rrs[0].clone());
    }
    let mut m = req.reply();
    m.metadata.authoritative = true;
    m.answers = rrs;
    m
}

/// `strconv.ParseInt(s, 10, 32)`, with Go's error message.
fn parse_int(s: &str) -> Result<i32, String> {
    s.parse::<i32>().map_err(|e| {
        let why = match e.kind() {
            IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => "value out of range",
            _ => "invalid syntax",
        };
        format!("strconv.ParseInt: parsing {s:?}: {why}")
    })
}

/// A non-negative amount.
fn parse_amount(s: &str) -> Result<u64, String> {
    let amount = parse_int(s)?;
    u64::try_from(amount).map_err(|_| format!("illegal amount value given {s:?}"))
}

/// `parseErratic`.
fn parse(c: &mut Controller<'_>) -> Result<Erratic, SetupError> {
    let err = |m: String| SetupError::new(NAME, m);
    let mut e = Erratic {
        drop: 2,
        ..Default::default()
    };
    let mut drop = false; // true if we've seen the drop keyword

    while c.next() {
        while c.next_block() {
            match c.val() {
                "drop" => {
                    let args = c.remaining_args();
                    if args.len() > 1 {
                        return Err(c.arg_err());
                    }
                    let Some(a) = args.first() else { continue };
                    e.drop = parse_amount(a).map_err(err)?;
                    drop = true;
                }
                "delay" => {
                    let args = c.remaining_args();
                    if args.len() > 2 {
                        return Err(c.arg_err());
                    }
                    // defaults
                    e.delay = 2;
                    e.duration = Duration::from_millis(100);
                    let Some(a) = args.first() else { continue };
                    e.delay = parse_amount(a).map_err(err)?;
                    if let Some(d) = args.get(1) {
                        e.duration = parse_duration(d).map_err(err)?;
                    }
                }
                "truncate" => {
                    let args = c.remaining_args();
                    if args.len() > 1 {
                        return Err(c.arg_err());
                    }
                    // defaults
                    e.truncate = 2;
                    let Some(a) = args.first() else { continue };
                    e.truncate = parse_amount(a).map_err(err)?;
                }
                "large" => e.large = true,
                other => {
                    let msg = format!("unknown property '{other}'");
                    return Err(c.errf(msg));
                }
            }
        }
    }
    // delay or truncate is set without a drop keyword: no default drops
    if (e.delay > 0 || e.truncate > 0) && !drop {
        e.drop = 0;
    }
    Ok(e)
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let e = Arc::new(parse(c)?);
        let q = e.q.clone();
        kerndns_core::readiness::register(NAME, move || Erratic::ready(&q));
        AutoPathers::of(c.config).register(NAME, e.clone());
        c.add_plugin(move |_next| e.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::corefile::{Dispenser, parse as parse_corefile};
    use kerndns_core::{BlockConfig, Hooks, ZoneAddr};

    fn parse_erratic(input: &str) -> Result<Erratic, String> {
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

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "erratic {\n drop\n}"));
        assert!(setup_ok(&Setup, "erratic"));
        assert_eq!(
            setup_err(&Setup, "erratic {\n drop -1\n}"),
            "plugin/erratic: illegal amount value given \"-1\""
        );
    }

    #[test]
    fn parse_erratic_cases() {
        // (input, drop, delay, truncate)
        let oks = [
            ("erratic", 2, 0, 0),
            ("erratic {\n drop 2\n delay 3 1ms\n\n}", 2, 3, 0),
            ("erratic {\n truncate 2\n delay 3 1ms\n\n}", 0, 3, 2),
            ("erratic {\n drop 3\n delay\n}", 3, 2, 0),
            ("erratic {\n drop 3\n truncate\n}", 3, 0, 2),
        ];
        for (input, drop, delay, truncate) in oks {
            let e = parse_erratic(input).unwrap_or_else(|err| panic!("{input}: {err}"));
            assert_eq!((e.drop, e.delay, e.truncate), (drop, delay, truncate), "{input}");
        }
        let e = parse_erratic("erratic {\n delay 3 1ms\n large\n}").unwrap();
        assert_eq!(e.duration, Duration::from_millis(1));
        assert!(e.large);
        assert_eq!(
            parse_erratic("erratic {\n delay\n}").unwrap().duration,
            Duration::from_millis(100)
        );

        let fails = [
            (
                "erratic {\n drop -1\n}",
                "plugin/erratic: illegal amount value given \"-1\"",
            ),
            (
                "erratic {\n delay -1\n}",
                "plugin/erratic: illegal amount value given \"-1\"",
            ),
            (
                "erratic {\n delay 1 2 4\n}",
                "plugin/erratic: Corefile:3 - Error during parsing: Wrong argument count or unexpected line ending after '4'",
            ),
            (
                "erratic {\n delay 15.a\n}",
                "plugin/erratic: strconv.ParseInt: parsing \"15.a\": invalid syntax",
            ),
            (
                "erratic {\n drop 3\n delay 3 bla\n}",
                "plugin/erratic: time: invalid duration \"bla\"",
            ),
            (
                "erratic {\n truncate 15.a\n}",
                "plugin/erratic: strconv.ParseInt: parsing \"15.a\": invalid syntax",
            ),
            (
                "erratic {\n drop 3000000000\n}",
                "plugin/erratic: strconv.ParseInt: parsing \"3000000000\": value out of range",
            ),
            (
                "erratic {\n something-else\n}",
                "plugin/erratic: Corefile:3 - Error during parsing: unknown property 'something-else'",
            ),
        ];
        for (input, want) in fails {
            assert_eq!(parse_erratic(input).err().as_deref(), Some(want), "{input}");
        }
    }

    #[tokio::test]
    async fn drops() {
        let e = Erratic {
            drop: 2,
            ..Default::default()
        };
        // (qtype, rcode, dropped)
        let cases = [
            (RecordType::A, ResponseCode::NoError, true),
            (RecordType::A, ResponseCode::NoError, false),
            (RecordType::AAAA, ResponseCode::NoError, true),
            (RecordType::HINFO, ResponseCode::ServFail, false),
        ];
        for (i, (qtype, rcode, dropped)) in cases.into_iter().enumerate() {
            let (rc, w) = serve(&e, &query("example.org.", qtype, "10.0.0.1:53")).await;
            assert_eq!(rc.unwrap(), rcode, "case {i}");
            if dropped {
                assert!(!w.written(), "case {i}");
            }
        }
    }

    #[tokio::test]
    async fn truncates() {
        let e = Erratic {
            truncate: 2,
            ..Default::default()
        };
        // with CoreDNS's bitwise test, queries 0, 1, 4, 5, ... are truncated
        for want in [true, true, false, false, true] {
            let (rc, w) = serve(&e, &query("example.org.", RecordType::A, "10.0.0.1:53")).await;
            assert_eq!(rc.unwrap(), ResponseCode::NoError);
            let m = w.msg().unwrap();
            assert_eq!(m.metadata.truncation, want);
            assert_eq!(m.answers.len(), 1);
        }
    }

    #[tokio::test]
    async fn delays() {
        let e = Erratic {
            delay: 2,
            duration: Duration::from_millis(50),
            ..Default::default()
        };
        let req = query("example.org.", RecordType::A, "10.0.0.1:53");
        for want_delay in [true, false] {
            let start = std::time::Instant::now();
            let (_, w) = serve(&e, &req).await;
            assert!(w.written());
            assert_eq!(start.elapsed() >= Duration::from_millis(50), want_delay);
        }
    }

    #[tokio::test]
    async fn axfr() {
        let e = Erratic::default();
        let (rc, w) = serve(&e, &query("example.org.", RecordType::AXFR, "10.0.0.1:53")).await;
        assert_eq!(rc.unwrap(), ResponseCode::NoError);
        let m = w.msg().unwrap();
        let got: Vec<String> = m.answers.iter().map(|r| r.to_string()).collect();
        assert_eq!(
            got,
            [
                "example.org. 0 IN SOA sns.dns.icann.org. noc.dns.icann.org. 2018050825 7200 3600 1209600 3600",
                "example.org. 0 IN NS b.example.org.",
                "example.org. 0 IN NS a.example.org.",
                "a.example.org. 0 IN AAAA 2001:bd8::53",
                "b.example.org. 0 IN AAAA 2001:500::54",
                "example.org. 0 IN SOA sns.dns.icann.org. noc.dns.icann.org. 2018050825 7200 3600 1209600 3600",
            ]
        );

        // truncated: no closing SOA
        let e = Erratic {
            truncate: 1,
            ..Default::default()
        };
        let (_, w) = serve(&e, &query("example.org.", RecordType::AXFR, "10.0.0.1:53")).await;
        let m = w.msg().unwrap();
        assert_eq!(m.answers.len(), 5);
        assert_eq!(m.answers[0].record_type(), RecordType::SOA);
    }

    #[tokio::test]
    async fn answers() {
        let e = Erratic::default();
        let (_, w) = serve(&e, &query("Example.org.", RecordType::A, "10.0.0.1:53")).await;
        let m = w.msg().unwrap();
        assert!(m.metadata.authoritative);
        assert_eq!(m.answers[0].to_string(), "Example.org. 0 IN A 192.0.2.53");
        let (_, w) = serve(&e, &query("example.org.", RecordType::AAAA, "10.0.0.1:53")).await;
        assert_eq!(
            w.msg().unwrap().answers[0].to_string(),
            "example.org. 0 IN AAAA 2001:db8::53"
        );

        let e = Erratic {
            large: true,
            ..Default::default()
        };
        let (_, w) = serve(&e, &query("example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(w.msg().unwrap().answers.len(), 30);
    }

    #[tokio::test]
    async fn ready() {
        let e = Erratic::default();
        let req = query("example.org.", RecordType::A, "10.0.0.1:53");
        let mut got = Vec::new();
        for _ in 0..6 {
            got.push(Erratic::ready(&e.q));
            let _ = serve(&e, &req).await;
        }
        assert_eq!(got, [false, false, false, true, true, false]);
    }
}
