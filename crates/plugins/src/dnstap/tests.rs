//! Ported from `plugin/dnstap/{setup,handler}_test.go` (`io_test.go`,
//! `listener_test.go` and `msg/msg_test.go` are in the submodules) and
//! `plugin/forward/forward_test.go`'s `TestSetTapPlugin`.

use std::time::Duration;

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::rdata::A;
use kerndns_core::proto::rr::{Name, RData, Record, RecordType};

use super::msg::{Decoded, FAMILY_INET, PROTO_UDP, decode_dnstap};
use super::*;
use crate::testutil::*;

struct Want {
    endpoint: &'static str,
    full: bool,
    proto: Proto,
    identity: Option<&'static str>,
    version: Option<&'static str>,
    extra: &'static str,
    buf: usize,
    queue: usize,
    listener: bool,
    cert: Option<&'static str>,
    key: Option<&'static str>,
    ca: Option<&'static str>,
    skip_verify: bool,
}

const fn want(endpoint: &'static str, full: bool, proto: Proto) -> Want {
    Want {
        endpoint,
        full,
        proto,
        identity: None,
        version: None,
        extra: "",
        buf: 1,
        queue: 1,
        listener: false,
        cert: None,
        key: None,
        ca: None,
        skip_verify: false,
    }
}

const fn named(mut w: Want, identity: &'static str, version: &'static str, extra: &'static str) -> Want {
    w.identity = Some(identity);
    w.version = Some(version);
    w.extra = extra;
    w
}

const fn listen(mut w: Want) -> Want {
    w.listener = true;
    w
}

fn parse(input: &str) -> Result<Vec<Tap>, String> {
    with_controller("dnstap", input, parse_config).map_err(|e| e.to_string())
}

fn check(i: usize, tap: &Tap, w: &Want) {
    let host = hostname();
    let version = default_version();
    if w.listener {
        let l = tap
            .listener
            .as_ref()
            .unwrap_or_else(|| panic!("{i}: expected a listener"));
        let s = &l.settings;
        assert_eq!(s.endpoint, w.endpoint, "{i}");
        assert_eq!(s.proto, w.proto, "{i}");
        assert_eq!(s.cert_file.as_deref(), w.cert, "{i}");
        assert_eq!(s.key_file.as_deref(), w.key, "{i}");
        assert_eq!(s.ca_file.as_deref(), w.ca, "{i}");
        assert_eq!(s.skip_verify, w.skip_verify, "{i}");
    } else {
        let d = tap.io.as_ref().unwrap_or_else(|| panic!("{i}: expected io"));
        assert_eq!(d.settings.endpoint, w.endpoint, "{i}");
        assert_eq!(d.settings.proto, w.proto, "{i}");
        assert_eq!(tap.multiple_tcp_write_buf, w.buf, "{i}");
        assert_eq!(tap.multiple_queue, w.queue, "{i}");
        assert_eq!(d.settings.tcp_write_buf_size, w.buf << 20, "{i}");
    }
    assert_eq!(tap.include_raw, w.full, "{i}");
    assert_eq!(tap.identity, w.identity.unwrap_or(&host).as_bytes(), "{i}");
    assert_eq!(tap.version, w.version.unwrap_or(&version).as_bytes(), "{i}");
    assert_eq!(tap.extra_format, w.extra, "{i}");
}

// TestConfig
#[test]
fn config() {
    use Proto::*;
    let ok: Vec<(&str, Vec<Want>)> = vec![
        ("dnstap dnstap.sock full", vec![want("dnstap.sock", true, Unix)]),
        ("dnstap unix://dnstap.sock", vec![want("dnstap.sock", false, Unix)]),
        ("dnstap tcp://127.0.0.1:6000", vec![want("127.0.0.1:6000", false, Tcp)]),
        ("dnstap tcp://[::1]:6000", vec![want("[::1]:6000", false, Tcp)]),
        (
            "dnstap tcp://example.com:6000",
            vec![want("example.com:6000", false, Tcp)],
        ),
        (
            "dnstap dnstap.sock full {\nidentity NAME\nversion VER\n}\n",
            vec![named(want("dnstap.sock", true, Unix), "NAME", "VER", "")],
        ),
        (
            "dnstap dnstap.sock full {\nidentity NAME\nversion VER\nextra EXTRA\n}\n",
            vec![named(want("dnstap.sock", true, Unix), "NAME", "VER", "EXTRA")],
        ),
        (
            "dnstap dnstap.sock {\nidentity NAME\nversion VER\nextra EXTRA\n}\n",
            vec![named(want("dnstap.sock", false, Unix), "NAME", "VER", "EXTRA")],
        ),
        (
            "dnstap dnstap.sock full {\n identity NAME\n version VER\n extra EXTRA\n}\n\
             dnstap tcp://127.0.0.1:6000 {\n identity NAME2\n version VER2\n extra EXTRA2\n}",
            vec![
                named(want("dnstap.sock", true, Unix), "NAME", "VER", "EXTRA"),
                named(want("127.0.0.1:6000", false, Tcp), "NAME2", "VER2", "EXTRA2"),
            ],
        ),
        ("dnstap tls://127.0.0.1:6000", vec![want("127.0.0.1:6000", false, Tls)]),
        (
            "dnstap dnstap.sock full 1024 2048",
            vec![Want {
                buf: 1024,
                queue: 2048,
                ..want("dnstap.sock", true, Unix)
            }],
        ),
        // listeners
        (
            "dnstap listen tcp://127.0.0.1:6000",
            vec![listen(want("127.0.0.1:6000", false, Tcp))],
        ),
        (
            "dnstap listen tcp://127.0.0.1:6000 full",
            vec![listen(want("127.0.0.1:6000", true, Tcp))],
        ),
        (
            "dnstap listen unix:///tmp/dnstap.sock",
            vec![listen(want("/tmp/dnstap.sock", false, Unix))],
        ),
        (
            "dnstap listen /tmp/dnstap.sock full",
            vec![listen(want("/tmp/dnstap.sock", true, Unix))],
        ),
        (
            "dnstap listen tls://127.0.0.1:6000 full {\ntls /path/to/cert.pem /path/to/key.pem\n}\n",
            vec![Want {
                cert: Some("/path/to/cert.pem"),
                key: Some("/path/to/key.pem"),
                ..listen(want("127.0.0.1:6000", true, Tls))
            }],
        ),
        (
            "dnstap listen tls://127.0.0.1:6000 {\ntls /path/to/cert.pem /path/to/key.pem /path/to/ca.pem\n}\n",
            vec![Want {
                cert: Some("/path/to/cert.pem"),
                key: Some("/path/to/key.pem"),
                ca: Some("/path/to/ca.pem"),
                ..listen(want("127.0.0.1:6000", false, Tls))
            }],
        ),
        (
            "dnstap listen tls://127.0.0.1:6000 {\ntls /path/to/cert.pem /path/to/key.pem\nskipverify\n}\n",
            vec![Want {
                cert: Some("/path/to/cert.pem"),
                key: Some("/path/to/key.pem"),
                skip_verify: true,
                ..listen(want("127.0.0.1:6000", false, Tls))
            }],
        ),
        (
            "dnstap tcp://remote.example.com:6000 full\ndnstap listen tcp://127.0.0.1:6001",
            vec![
                want("remote.example.com:6000", true, Tcp),
                listen(want("127.0.0.1:6001", false, Tcp)),
            ],
        ),
    ];
    for (i, (input, wants)) in ok.iter().enumerate() {
        let taps = parse(input).unwrap_or_else(|e| panic!("{i} {input}: {e}"));
        assert_eq!(taps.len(), wants.len(), "{i}");
        for (t, w) in taps.iter().zip(wants) {
            check(i, t, w);
        }
    }

    let bad = [
        "dnstap",
        "dnstap {\nidentity NAME\nversion VER\nextra EXTRA\n}\n",
        "dnstap dnstap.sock {\nidentity\n}\n",
        "dnstap dnstap.sock {\nversion\n}\n",
        "dnstap dnstap.sock {\nextra\n}\n",
        "dnstap dnstap.sock {\nidentitiy NAME\n}\n",
        "dnstap dnstap.sock full 1025 1",
        "dnstap dnstap.sock full 1 4097",
        "dnstap dnstap.sock full 0 10",
        "dnstap dnstap.sock full 10 0",
        "dnstap dnstap.sock full x 10",
        "dnstap dnstap.sock full 10 y",
        "dnstap listen",
        "dnstap listen tcp://127.0.0.1:6000 {\ntls /path/to/cert.pem\n}\n",
        "dnstap tcp://127.0.0.1:6000 {\ntls /a /b\n}\n",
    ];
    for input in bad {
        assert!(parse(input).is_err(), "{input}: expected an error");
    }
    let e = parse("dnstap dnstap.sock {\nidentitiy NAME\n}\n").unwrap_err();
    assert!(e.contains("unknown property 'identitiy'"), "{e}");
    let e = parse("dnstap dnstap.sock full 1025 1").unwrap_err();
    assert!(
        e.contains("dnstap: MultipleTcpWriteBuf must be between 1 and 1024 (MiB units): 1025"),
        "{e}"
    );
    let e = parse("dnstap listen").unwrap_err();
    assert!(e.contains("dnstap listen requires an endpoint argument"), "{e}");
}

// TestMultiDnstap: one handler per directive, in order, and the block's
// taps list for other plugins
#[test]
fn multi_dnstap() {
    let (res, mut cfg) = run_setup(&Setup, "dnstap dnstap1.sock\ndnstap dnstap2.sock\ndnstap dnstap3.sock");
    res.unwrap();
    assert_eq!(cfg.plugins.len(), 3);
    let taps = Taps::of(&mut cfg);
    let eps: Vec<_> = taps
        .get()
        .unwrap()
        .iter()
        .map(|t| t.io.as_ref().unwrap().settings.endpoint.clone())
        .collect();
    assert_eq!(eps, ["dnstap1.sock", "dnstap2.sock", "dnstap3.sock"]);
}

fn capturing(include_raw: bool, extra: &str, metadata: bool) -> Arc<Tap> {
    Arc::new(Tap {
        include_raw,
        identity: Vec::new(),
        version: Vec::new(),
        extra_format: extra.to_string(),
        multiple_tcp_write_buf: 1,
        multiple_queue: 1,
        metadata,
        io: None,
        listener: None,
        capture: Some(Mutex::new(Vec::new())),
    })
}

fn captured(t: &Tap) -> Vec<Decoded> {
    t.capture
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .iter()
        .map(|b| decode_dnstap(b).unwrap())
        .collect()
}

fn answer(r: &Request) -> kerndns_core::proto::op::Message {
    let mut m = r.reply();
    m.answers.push(Record::from_rdata(
        Name::from_ascii("example.org.").unwrap(),
        3600,
        RData::A(A::new(10, 0, 0, 1)),
    ));
    m
}

// TestDnstap
#[tokio::test]
async fn dnstap() {
    let extra = "extra_field_{/metadata/test}_{type}_{name}_{class}_{proto}_{size}_{remote}_{port}_{local}";
    for (format, want_extra) in [
        ("", None),
        (
            extra,
            Some("extra_field_MetadataValue_A_example.org._IN_udp_29_10.240.0.1_40212_127.0.0.1"),
        ),
    ] {
        let tap = capturing(false, format, true);
        let h = Dnstap {
            tap: tap.clone(),
            next: reply(answer),
        };
        let mut req = query("example.org.", RecordType::A, "10.240.0.1:40212");
        req.msg.metadata.recursion_desired = false;
        let mut w = kerndns_core::CaptureWriter::new();
        let mut ctx = Context::new(".", "dns://:53");
        ctx.metadata.insert("metadata/test".into(), "MetadataValue".into());
        h.serve_dns(&mut ctx, &mut w, &req).await.unwrap();
        let got = captured(&tap);
        assert_eq!(got.len(), 2);
        for (d, typ) in got.iter().zip([5, 6]) {
            assert_eq!(d.typ, Some(1));
            assert_eq!(d.int(1), Some(typ));
            assert_eq!(d.int(2), Some(u64::from(FAMILY_INET)));
            assert_eq!(d.int(3), Some(u64::from(PROTO_UDP)));
            assert_eq!(d.bytes(4), Some(&[10, 240, 0, 1][..]));
            assert_eq!(d.int(6), Some(40212));
            assert_eq!(d.extra.as_deref(), want_extra.map(str::as_bytes));
            // not `full`
            assert!(d.bytes(10).is_none() && d.bytes(14).is_none());
        }
        assert!(got[1].int(12).is_some(), "response time");
    }
}

// TestTapMessage: TapMessage doesn't expand `extra`
#[test]
fn tap_message() {
    let extra = "extra_field_no_replacement_{/metadata/test}_{type}";
    let tap = capturing(false, extra, true);
    let mut m = Message::new(MessageType::ClientQuery);
    m.set_query_address("10.240.0.1:40212".parse().unwrap(), "udp");
    tap.tap_message(&m);
    let got = captured(&tap);
    assert_eq!(got[0].extra.as_deref(), Some(extra.as_bytes()));
}

// TestNilIoAndListener
#[test]
fn nil_io_and_listener() {
    let t = Tap {
        capture: None,
        ..Arc::into_inner(capturing(false, "", false)).unwrap()
    };
    t.tap_message(&Message::new(MessageType::ClientQuery));
}

// TestDnstapDeferredError
#[tokio::test]
async fn deferred_error() {
    struct Fail;
    #[async_trait]
    impl Handler for Fail {
        fn name(&self) -> &'static str {
            "fail"
        }
        async fn serve_dns(&self, _: &mut Context, _: &mut dyn ResponseWriter, _: &Request) -> HandlerResult {
            Ok(ResponseCode::ServFail)
        }
    }
    let tap = capturing(true, "", false);
    let h = Dnstap {
        tap: tap.clone(),
        next: Some(Arc::new(Fail)),
    };
    let req = query("example.org.", RecordType::A, "10.240.0.1:40212");
    let (rc, w) = serve(&h, &req).await;
    assert_eq!(rc.unwrap(), ResponseCode::ServFail);
    assert!(!w.written());
    let got = captured(&tap);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].int(1), Some(5));
    assert_eq!(got[1].int(1), Some(6));
    let m = DnsMessage::from_vec(got[1].bytes(14).unwrap()).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    // full: the query is included too
    let q = DnsMessage::from_vec(got[0].bytes(10).unwrap()).unwrap();
    assert_eq!(q.queries, req.msg.queries);
}

#[test]
fn replacer() {
    let req = query("example.org.", RecordType::AAAA, "[2001:db8::1]:53");
    let mut ctx = Context::new(".", "dns://:53");
    ctx.metadata.insert("forward/upstream".into(), "127.0.0.1:53".into());
    assert_eq!(
        replace(
            "{/forward/upstream} {remote} {rcode} {/nope} {nolabel} } { {type}",
            Some(&ctx),
            &req
        ),
        "127.0.0.1:53 [2001:db8::1] - - {nolabel} } { AAAA"
    );
    // without the metadata plugin, metadata is "-"
    assert_eq!(replace("{/forward/upstream}", None, &req), "-");
    assert_eq!(replace("{>id} {>opcode} {>do} {>bufsize}", None, &req), "1 0 false 512");
}

// TestSetTapPlugin (forward): forward sees every dnstap of the block
#[tokio::test]
async fn forward_taps() {
    use tokio::net::UdpSocket;
    // an upstream that answers one query
    let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        let (n, from) = up.recv_from(&mut buf).await.unwrap();
        let q = DnsMessage::from_vec(&buf[..n]).unwrap();
        let mut a = q.clone();
        a.metadata.message_type = kerndns_core::proto::op::MessageType::Response;
        up.send_to(&a.to_vec().unwrap(), from).await.unwrap();
    });
    let blocks = kerndns_core::corefile::parse(
        &format!(".:53 {{\ndnstap /tmp/dnstap.sock full\ndnstap tcp://example.com:6000\nforward . {up_addr}\n}}"),
        "Corefile",
    )
    .unwrap();
    let mut cfg = BlockConfig::new(kerndns_core::ZoneAddr::parse(".:53", "53").unwrap());
    let mut hooks = kerndns_core::Hooks::default();
    for f in [&Setup as &dyn PluginFactory, &crate::forward::Setup] {
        let mut c = Controller::new(
            f.name(),
            kerndns_core::corefile::Dispenser::new(blocks[0].tokens_for(f.name())),
            &mut cfg,
            &mut hooks,
            ".".into(),
        );
        f.setup(&mut c).unwrap();
    }
    let taps = Taps::of(&mut cfg).get().unwrap().to_vec();
    assert_eq!(taps.len(), 2);
    assert!(taps[0].include_raw && !taps[1].include_raw);
    // what forward logs, through a capturing tap
    let core_taps = Taps::default();
    let tap = capturing(true, "{/forward/upstream}", true);
    let _ = core_taps.0.set(vec![tap.clone()]);
    let mut fcfg = BlockConfig::new(kerndns_core::ZoneAddr::parse(".:53", "53").unwrap());
    fcfg.extensions.insert(core_taps);
    let blocks = kerndns_core::corefile::parse(&format!(".:53 {{\nforward . {up_addr}\n}}"), "Corefile").unwrap();
    {
        let mut c = Controller::new(
            "forward",
            kerndns_core::corefile::Dispenser::new(blocks[0].tokens_for("forward")),
            &mut fcfg,
            &mut hooks,
            ".".into(),
        );
        crate::forward::Setup.setup(&mut c).unwrap();
    }
    let fwd = fcfg.chain().unwrap();
    let req = query("example.org.", RecordType::A, "10.240.0.1:40212");
    let (rc, w) = tokio::time::timeout(Duration::from_secs(5), serve(fwd.as_ref(), &req))
        .await
        .unwrap();
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    assert!(w.written());
    let got = captured(&tap);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].int(1), Some(7)); // FORWARDER_QUERY
    assert_eq!(got[1].int(1), Some(8)); // FORWARDER_RESPONSE
    for d in &got {
        assert_eq!(d.bytes(5), Some(&[127, 0, 0, 1][..]), "upstream address");
        assert_eq!(d.int(7), Some(u64::from(up_addr.port())));
        assert_eq!(d.bytes(4), Some(&[127, 0, 0, 1][..]), "our address");
        assert_eq!(d.extra.as_deref(), Some(up_addr.to_string().as_bytes()));
    }
    assert!(got[0].bytes(10).is_some() && got[1].bytes(14).is_some());
}
