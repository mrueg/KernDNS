//! End-to-end tests of plugins that talk to other servers: `grpc` against
//! KernDNS's own `grpc://` listener, and `dnstap` (with `forward`'s hook)
//! against a Frame Streams sink on a unix socket.

use std::net::SocketAddr;
use std::time::Duration;

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_plugins::dnstap::framestream::read_stream;
use kerndns_plugins::dnstap::msg::decode_dnstap;
use kerndns_server::{Instance, Options};
use tokio::net::UdpSocket;

const TLS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../bench/shared/tls");

async fn start(corefile: &str) -> Instance {
    Instance::start(corefile, "Corefile", &kerndns_plugins::registry(), &Options::default())
        .await
        .unwrap_or_else(|e| panic!("start: {e}\n{corefile}"))
}

fn udp_addr(inst: &Instance) -> SocketAddr {
    let a = inst.listeners()[0].udp.unwrap();
    SocketAddr::from(([127, 0, 0, 1], a.port()))
}

async fn exchange(server: SocketAddr, name: &str) -> Message {
    let mut m = Message::new(4242, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(&m.to_vec().unwrap(), server).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(6), s.recv(&mut buf))
        .await
        .expect("answer")
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

#[tokio::test]
async fn grpc_to_kerndns_grpc_listener() {
    let backend = start("grpc://example.org:0 {\n whoami\n}").await;
    let port = backend.listeners()[0].port();
    let front = start(&format!(
        ".:0 {{\n grpc example.org 127.0.0.1:{port} {{\n  except skip.example.org\n }}\n}}"
    ))
    .await;
    let addr = udp_addr(&front);
    let m = exchange(addr, "whoami.example.org.").await;
    assert_eq!(m.metadata.id, 4242);
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    // whoami saw a gRPC (TCP) client
    assert!(
        m.additionals.iter().any(|r| r.name.to_ascii().starts_with("_tcp.")),
        "{m:?}"
    );
    // outside FROM, or excepted, with no next plugin: SERVFAIL
    let m = exchange(addr, "example.net.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    let m = exchange(addr, "a.skip.example.org.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    // the backend's REFUSED for a zone it doesn't serve comes back as is
    let front2 = start(&format!(".:0 {{\n grpc . 127.0.0.1:{port}\n}}")).await;
    let m = exchange(udp_addr(&front2), "example.net.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn grpc_tls_and_fallthrough() {
    let backend = start(&format!(
        "grpc://.:0 {{\n tls {TLS_DIR}/cert.pem {TLS_DIR}/key.pem\n template IN A nx.example.org {{\n  rcode NXDOMAIN\n }}\n whoami\n}}"
    ))
    .await;
    let port = backend.listeners()[0].port();
    let front = start(&format!(
        ".:0 {{\n grpc . 127.0.0.1:{port} {{\n  tls {TLS_DIR}/ca.pem\n  tls_servername kerndns.test\n  fallthrough\n }}\n whoami\n}}"
    ))
    .await;
    let addr = udp_addr(&front);
    let proto_seen = |m: &Message| {
        m.additionals
            .iter()
            .find(|r| r.record_type() == RecordType::SRV)
            .map(|r| r.name.to_ascii()[..5].to_string())
    };
    // the backend's whoami answers, for a gRPC (TCP) client
    let m = exchange(addr, "whoami.example.org.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert_eq!(proto_seen(&m).as_deref(), Some("_tcp."), "{m:?}");
    // NXDOMAIN from the backend falls through to the local whoami (UDP)
    let m = exchange(addr, "nx.example.org.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert_eq!(proto_seen(&m).as_deref(), Some("_udp."), "{m:?}");

    // the wrong server name fails the handshake: SERVFAIL
    let bad = start(&format!(
        ".:0 {{\n grpc . 127.0.0.1:{port} {{\n  tls {TLS_DIR}/ca.pem\n  tls_servername wrong.example\n }}\n}}"
    ))
    .await;
    let m = exchange(udp_addr(&bad), "whoami.example.org.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn dnstap_client_and_forwarder_messages() {
    let dir = std::env::temp_dir().join(format!("kerndns-dnstap-e2e-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let sock = dir.join("tap.sock");
    let _ = std::fs::remove_file(&sock);
    let sink = tokio::net::UnixListener::bind(&sock).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((s, _)) = sink.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = read_stream(s, move |f| {
                    let _ = tx.send(f);
                })
                .await;
            });
        }
    });

    let upstream = start("example.org:0 {\n whoami\n}").await;
    let up = udp_addr(&upstream);
    let front = start(&format!(
        ".:0 {{\n metadata\n dnstap {} full {{\n  identity test-id\n  version test-ver\n  extra \"{{/forward/upstream}} {{type}}\"\n }}\n forward . {up}\n}}",
        sock.display()
    ))
    .await;
    let m = exchange(udp_addr(&front), "whoami.example.org.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);

    // CLIENT_QUERY, FORWARDER_QUERY, FORWARDER_RESPONSE, CLIENT_RESPONSE
    let mut got = Vec::new();
    while got.len() < 4 {
        let f = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("dnstap frames")
            .unwrap();
        got.push(decode_dnstap(&f).unwrap());
    }
    let types: Vec<_> = got.iter().map(|d| d.int(1).unwrap()).collect();
    assert_eq!(types, [5, 7, 8, 6]);
    for d in &got {
        assert_eq!(d.identity.as_deref(), Some(&b"test-id"[..]));
        assert_eq!(d.version.as_deref(), Some(&b"test-ver"[..]));
        assert_eq!(d.int(3), Some(1), "UDP");
    }
    // the query is logged before forward picks an upstream
    assert_eq!(got[0].extra.as_deref(), Some(&b"- A"[..]));
    let up_extra = format!("{up} A");
    for d in &got[1..] {
        assert_eq!(d.extra.as_deref(), Some(up_extra.as_bytes()));
    }
    assert_eq!(got[1].int(7), Some(u64::from(up.port())));
    let q = Message::from_vec(got[0].bytes(10).unwrap()).unwrap();
    assert_eq!(q.metadata.id, 4242);
    let r = Message::from_vec(got[3].bytes(14).unwrap()).unwrap();
    assert_eq!(r.metadata.id, 4242);
    assert_eq!(r.additionals.len(), 2);
    drop(front);
    let _ = std::fs::remove_dir_all(&dir);
}

async fn exchange_tcp(server: SocketAddr, name: &str, qtype: RecordType) -> Message {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut m = Message::new(4243, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
    let wire = m.to_vec().unwrap();
    let mut s = tokio::net::TcpStream::connect(server).await.unwrap();
    let mut out = (wire.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&wire);
    s.write_all(&out).await.unwrap();
    let mut len = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(6), s.read_exact(&mut len))
        .await
        .expect("answer")
        .unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).await.unwrap();
    Message::from_vec(&buf).unwrap()
}

/// The transport whoami saw: `_tcp.` or `_udp.`.
fn whoami_proto(m: &Message) -> Option<String> {
    m.additionals
        .iter()
        .find(|r| r.record_type() == RecordType::SRV)
        .map(|r| r.name.to_ascii()[..5].to_string())
}

/// `forward` to KernDNS's own DoH and DoQ listeners (like CoreDNS's
/// TestProxyHTTPS and TestForwardDoQIntegration): answers come back with
/// the client's ID, over both DoH methods and with a per-upstream DoQ
/// server name.
#[tokio::test]
async fn forward_doh_and_doq_upstreams() {
    let backend = start(&format!(
        "https://example.org:0 {{\n tls {TLS_DIR}/cert.pem {TLS_DIR}/key.pem\n whoami\n}}\nquic://example.org:0 {{\n tls {TLS_DIR}/cert.pem {TLS_DIR}/key.pem\n whoami\n}}"
    ))
    .await;
    let doh = backend.listeners()[0].port();
    let doq = backend.listeners()[1].port();
    for (to, extra) in [
        (format!("https://127.0.0.1:{doh}"), ""),
        (format!("https://127.0.0.1:{doh}"), "doh_method GET"),
        (format!("quic://127.0.0.1:{doq}"), ""),
        (format!("quic://127.0.0.1%kerndns.test:{doq}"), ""),
    ] {
        let servername = if to.contains('%') {
            ""
        } else {
            "tls_servername kerndns.test"
        };
        let front = start(&format!(
            ".:0 {{\n forward . {to} {{\n  tls {TLS_DIR}/ca.pem\n  {servername}\n  {extra}\n }}\n}}"
        ))
        .await;
        let addr = udp_addr(&front);
        for _ in 0..3 {
            let m = exchange(addr, "whoami.example.org.").await;
            assert_eq!(m.metadata.id, 4242, "{to}");
            assert_eq!(m.metadata.response_code, ResponseCode::NoError, "{to}: {m:?}");
            let want = if to.starts_with("https") { "_tcp." } else { "_udp." };
            assert_eq!(whoami_proto(&m).as_deref(), Some(want), "{to}: {m:?}");
        }
        // DoQ can't carry zone transfers: NOTIMP, without dialing
        if to.starts_with("quic") {
            let tcp = SocketAddr::from(([127, 0, 0, 1], front.listeners()[0].tcp.unwrap().port()));
            let m = exchange_tcp(tcp, "example.org.", RecordType::AXFR).await;
            assert_eq!(m.metadata.response_code, ResponseCode::NotImp, "{m:?}");
        }
    }

    // the wrong server name fails the handshake: SERVFAIL
    for to in [format!("https://127.0.0.1:{doh}"), format!("quic://127.0.0.1:{doq}")] {
        let bad = start(&format!(
            ".:0 {{\n forward . {to} {{\n  tls {TLS_DIR}/ca.pem\n  tls_servername wrong.example\n }}\n}}"
        ))
        .await;
        let m = exchange(udp_addr(&bad), "whoami.example.org.").await;
        assert_eq!(m.metadata.response_code, ResponseCode::ServFail, "{to}");
    }
}

/// An upstream that goes away: queries fail over to the next one, and once
/// the health checks mark it down it costs no time any more.
#[tokio::test]
async fn forward_doh_doq_failover() {
    let tls = format!("tls {TLS_DIR}/cert.pem {TLS_DIR}/key.pem");
    let blocks = format!("https://example.org:0 {{\n {tls}\n whoami\n}}\nquic://example.org:0 {{\n {tls}\n whoami\n}}");
    let good = start(&blocks).await;
    let mut gone = start(&blocks).await;
    let mut fronts = Vec::new();
    for (i, scheme) in ["https", "quic"].iter().enumerate() {
        let (dead, live) = (gone.listeners()[i].port(), good.listeners()[i].port());
        let front = start(&format!(
            ".:0 {{\n forward . {scheme}://127.0.0.1:{dead} {scheme}://127.0.0.1:{live} {{\n  tls {TLS_DIR}/ca.pem\n  tls_servername kerndns.test\n  policy sequential\n  health_check 100ms\n }}\n}}"
        ))
        .await;
        let m = exchange(udp_addr(&front), "whoami.example.org.").await;
        assert_eq!(m.metadata.response_code, ResponseCode::NoError, "{scheme}");
        fronts.push((scheme, front));
    }
    gone.stop().await;
    drop(gone);
    for (scheme, front) in &fronts {
        let addr = udp_addr(front);
        // DoH: the refused connection fails over to the second upstream at
        // once. DoQ: a handshake with the dead upstream takes up to its 5s
        // timeout (as in CoreDNS), which can use up the query's budget.
        let m = exchange(addr, "whoami.example.org.").await;
        if **scheme == "https" {
            assert_eq!(m.metadata.response_code, ResponseCode::NoError, "{scheme}: {m:?}");
        }
        // the health checks mark the dead upstream down: no time lost on it
        let start = std::time::Instant::now();
        loop {
            let t = std::time::Instant::now();
            let m = exchange(addr, "whoami.example.org.").await;
            if m.metadata.response_code == ResponseCode::NoError && t.elapsed() < Duration::from_millis(300) {
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(20), "{scheme}: not marked down");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}
