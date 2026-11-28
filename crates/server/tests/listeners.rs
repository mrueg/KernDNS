//! End-to-end tests of the DoQ, DoH3, gRPC and DoH listeners: start an
//! [`Instance`] from a Corefile and query it with real clients.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use kerndns_core::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_server::{Instance, Options, load};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

const TLS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/coredns/plugin/tls");

fn tls_line() -> String {
    format!("tls {TLS_DIR}/test_cert.pem {TLS_DIR}/test_key.pem {TLS_DIR}/test_ca.pem")
}

async fn start(corefile: &str) -> Instance {
    Instance::start(corefile, "Corefile", &kerndns_plugins::registry(), &Options::default())
        .await
        .unwrap_or_else(|e| panic!("start: {e}"))
}

fn query_msg(id: u16, name: &str) -> Message {
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    m
}

fn query(id: u16) -> Vec<u8> {
    query_msg(id, "whoami.example.org.").to_vec().unwrap()
}

/// whoami's answer: an A or AAAA record for the client plus `_udp`/`_tcp` SRV.
fn check_whoami(wire: &[u8], id: u16, proto: &str) {
    let m = Message::from_vec(wire).unwrap();
    assert_eq!(m.metadata.id, id);
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert_eq!(m.additionals.len(), 2, "{m:?}");
    let srv = m
        .additionals
        .iter()
        .find(|r| r.record_type() == RecordType::SRV)
        .unwrap();
    assert!(srv.name.to_ascii().starts_with(&format!("_{proto}.")), "{srv:?}");
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_tls(alpn: &[&[u8]]) -> rustls::ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut c = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    c
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

async fn quic_connect(port: u16, alpn: &[u8]) -> quinn::Connection {
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(&[alpn])).unwrap();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    ep.connect(localhost(port), "localhost").unwrap().await.unwrap()
}

/// One DoQ exchange on a new stream: the prefixed message, FIN, then the
/// prefixed answer.
async fn doq_exchange(conn: &quinn::Connection, msg: &[u8]) -> Result<Vec<u8>, String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let mut out = (msg.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    send.write_all(&out).await.map_err(|e| e.to_string())?;
    send.finish().unwrap();
    let all = recv.read_to_end(65537).await.map_err(|e| e.to_string())?;
    let n = u16::from_be_bytes([all[0], all[1]]) as usize;
    assert_eq!(all.len(), n + 2);
    Ok(all[2..].to_vec())
}

fn port_of(inst: &Instance, i: usize) -> u16 {
    inst.listeners()[i].port()
}

#[tokio::test]
async fn doq() {
    let inst = start(&format!("quic://.:0 {{\n {}\n whoami\n}}", tls_line())).await;
    let l = &inst.listeners()[0];
    assert!(l.tcp.is_none() && l.udp.is_some());
    let conn = quic_connect(port_of(&inst, 0), b"doq").await;
    // several queries on one connection, one stream each; DoQ counts as udp
    for _ in 0..3 {
        let a = doq_exchange(&conn, &query(0)).await.unwrap();
        check_whoami(&a, 0, "udp");
    }
    conn.close(0u32.into(), b"");
}

#[tokio::test]
async fn doq_protocol_errors() {
    let inst = start(&format!("quic://.:0 {{\n {}\n whoami\n}}", tls_line())).await;
    let port = port_of(&inst, 0);
    // the connection is closed with DOQ_PROTOCOL_ERROR
    let protocol_error = |conn: &quinn::Connection| match conn.close_reason() {
        Some(quinn::ConnectionError::ApplicationClosed(c)) => c.error_code == quinn::VarInt::from_u32(2),
        _ => false,
    };
    // a message without the length prefix (TestQUICProtocolError)
    let conn = quic_connect(port, b"doq").await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&query(1234)).await.unwrap();
    send.finish().unwrap();
    recv.read_to_end(1024).await.unwrap_err();
    assert!(protocol_error(&conn), "{:?}", conn.close_reason());
    // a non-zero message ID
    let conn = quic_connect(port, b"doq").await;
    doq_exchange(&conn, &query(7)).await.unwrap_err();
    assert!(protocol_error(&conn), "{:?}", conn.close_reason());
    // edns-tcp-keepalive
    let mut m = query_msg(0, "whoami.example.org.");
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(kerndns_core::proto::rr::rdata::opt::EdnsOption::Unknown(11, vec![]));
    m.edns = Some(edns);
    let conn = quic_connect(port, b"doq").await;
    doq_exchange(&conn, &m.to_vec().unwrap()).await.unwrap_err();
    assert!(protocol_error(&conn), "{:?}", conn.close_reason());
    // a wrong ALPN is refused in the handshake
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(&[b"h3"])).unwrap();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    assert!(ep.connect(localhost(port), "localhost").unwrap().await.is_err());
}

#[tokio::test]
async fn doq_limits() {
    let inst = start(&format!(
        "quic://.:0 {{\n {}\n quic {{\n  max_connections 1\n  max_streams 2\n }}\n whoami\n}}",
        tls_line()
    ))
    .await;
    let port = port_of(&inst, 0);
    let first = quic_connect(port, b"doq").await;
    doq_exchange(&first, &query(0)).await.unwrap();
    // the second connection is closed right away with code 0
    let second = quic_connect(port, b"doq").await;
    let e = second.closed().await.to_string();
    assert!(e.contains("too many connections (code 0)"), "{e}");
    // the stream limit is announced to the client: a third concurrent
    // stream can't be opened while two are open
    let (_s1, _r1) = first.open_bi().await.unwrap();
    let (mut s2, _r2) = first.open_bi().await.unwrap();
    // streams are only announced once data flows
    s2.write_all(&[0]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), first.open_bi())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn doq_read_timeout_resets_stream() {
    let inst = start(&format!(
        "quic://.:0 {{\n {}\n timeouts {{\n  read 1s\n }}\n whoami\n}}",
        tls_line()
    ))
    .await;
    let conn = quic_connect(port_of(&inst, 0), b"doq").await;
    // a stream whose query never comes is reset with DOQ_INTERNAL_ERROR...
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&[0]).await.unwrap();
    let e = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(e, quinn::ReadToEndError::Read(quinn::ReadError::Reset(c)) if c == quinn::VarInt::from_u32(1)),
        "{e:?}"
    );
    // ...and the connection lives on
    check_whoami(&doq_exchange(&conn, &query(0)).await.unwrap(), 0, "udp");
}

#[tokio::test]
async fn doq_reload_keeps_listener() {
    let mut inst = start(&format!("quic://.:0 {{\n {}\n whoami\n}}", tls_line())).await;
    let port = port_of(&inst, 0);
    let conn = quic_connect(port, b"doq").await;
    doq_exchange(&conn, &query(0)).await.unwrap();
    // reload with the same address: the socket and open connections stay
    let corefile = format!("quic://.:0 {{\n {}\n whoami\n quic\n}}", tls_line());
    let plan = load(&corefile, "Corefile", &kerndns_plugins::registry(), &Options::default()).unwrap();
    inst.reload(plan).await.unwrap();
    assert_eq!(port_of(&inst, 0), port);
    doq_exchange(&conn, &query(0)).await.unwrap();
    let conn = quic_connect(port, b"doq").await;
    check_whoami(&doq_exchange(&conn, &query(0)).await.unwrap(), 0, "udp");
}

#[tokio::test]
async fn quic_requires_tls() {
    let e = Instance::start(
        "quic://.:0 {\n whoami\n}",
        "Corefile",
        &kerndns_plugins::registry(),
        &Options::default(),
    )
    .await
    .err()
    .unwrap()
    .to_string();
    assert!(e.contains("no TLS configuration"), "{e}");
    let e = Instance::start(
        "https3://.:0 {\n whoami\n}",
        "Corefile",
        &kerndns_plugins::registry(),
        &Options::default(),
    )
    .await
    .err()
    .unwrap()
    .to_string();
    assert!(e.contains("DoH3 requires TLS"), "{e}");
}

/// Send one HTTP/3 request; returns the status, the content type and the body.
async fn h3_request(port: u16, req: http::Request<()>, body: Option<Vec<u8>>) -> (u16, String, Vec<u8>) {
    let conn = quic_connect(port, b"h3").await;
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let mut stream = send.send_request(req).await.unwrap();
    if let Some(b) = body {
        stream.send_data(Bytes::from(b)).await.unwrap();
    }
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    let ct = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let mut out = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let c = chunk.chunk().to_vec();
            chunk.advance(c.len());
            out.extend(c);
        }
    }
    drive.abort();
    (resp.status().as_u16(), ct, out)
}

#[tokio::test]
async fn doh3() {
    // (h3's client opens three unidirectional streams, so it can't talk to
    // a listener with `max_streams 2`, which limits those too, as in CoreDNS)
    let inst = start(&format!(
        "https3://.:0 {{\n {}\n https3 {{\n  max_streams 3\n }}\n whoami\n}}",
        tls_line()
    ))
    .await;
    let port = port_of(&inst, 0);
    let uri = format!("https://localhost:{port}/dns-query");
    let post = http::Request::post(&uri)
        .header("content-type", "application/dns-message")
        .body(())
        .unwrap();
    let (status, ct, body) = h3_request(port, post, Some(query(42))).await;
    assert_eq!((status, ct.as_str()), (200, "application/dns-message"));
    check_whoami(&body, 42, "udp");

    let b64 = data_encoding::BASE64URL_NOPAD.encode(&query(43));
    let get = http::Request::get(format!("{uri}?dns={b64}")).body(()).unwrap();
    let (status, _, body) = h3_request(port, get, None).await;
    assert_eq!(status, 200);
    check_whoami(&body, 43, "udp");

    let other = http::Request::get(format!("https://localhost:{port}/other"))
        .body(())
        .unwrap();
    assert_eq!(h3_request(port, other, None).await.0, 404);
    let bad = http::Request::post(&uri).body(()).unwrap();
    let (status, _, body) = h3_request(port, bad, Some(vec![1, 2, 3])).await;
    assert_eq!((status, body.as_slice()), (400, &b"invalid request\n"[..]));
}

/// A gRPC call to `path` over HTTP/2 (cleartext or TLS): the HTTP status,
/// the grpc-status and the response message, if any.
async fn grpc_call(
    port: u16,
    tls: bool,
    path: &str,
    payload: &[u8],
) -> (u16, Option<String>, Option<String>, Option<Vec<u8>>) {
    let tcp = tokio::net::TcpStream::connect(localhost(port)).await.unwrap();
    let mut frame = vec![0u8];
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    let req = hyper::Request::post(format!("http://localhost:{port}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from(frame)))
        .unwrap();
    let resp = if tls {
        let c = tokio_rustls::TlsConnector::from(Arc::new(client_tls(&[b"h2"])));
        let s = c
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(s))
            .await
            .unwrap();
        tokio::spawn(conn);
        send.send_request(req).await.unwrap()
    } else {
        let (mut send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(conn);
        send.send_request(req).await.unwrap()
    };
    let status = resp.status().as_u16();
    let header = |h: &http::HeaderMap, k: &str| h.get(k).map(|v| v.to_str().unwrap().to_string());
    let (head_status, head_msg) = (
        header(resp.headers(), "grpc-status"),
        header(resp.headers(), "grpc-message"),
    );
    let collected = resp.into_body().collect().await.unwrap();
    let trailers = collected.trailers().cloned().unwrap_or_default();
    let body = collected.to_bytes();
    let grpc_status = head_status.or_else(|| header(&trailers, "grpc-status"));
    let grpc_msg = head_msg.or_else(|| header(&trailers, "grpc-message"));
    let msg = (body.len() >= 5).then(|| kerndns_server::grpc::decode_packet(&body[5..]).unwrap());
    (status, grpc_status, grpc_msg, msg)
}

#[tokio::test]
async fn grpc_cleartext() {
    let inst = start("grpc://.:0 {\n grpc_server {\n  max_streams 2\n }\n whoami\n}").await;
    let l = &inst.listeners()[0];
    assert!(l.udp.is_none() && l.tcp.is_some());
    let port = port_of(&inst, 0);
    let pb = kerndns_server::grpc::encode_packet(&query(99));
    let (status, gs, _, msg) = grpc_call(port, false, "/coredns.dns.DnsService/Query", &pb).await;
    assert_eq!((status, gs.as_deref()), (200, Some("0")));
    check_whoami(&msg.unwrap(), 99, "tcp");

    // a gRPC error for a message that isn't a query
    let mut resp = query_msg(1, "whoami.example.org.");
    resp.metadata.message_type = MessageType::Response;
    let pb = kerndns_server::grpc::encode_packet(&resp.to_vec().unwrap());
    let (_, gs, gm, msg) = grpc_call(port, false, "/coredns.dns.DnsService/Query", &pb).await;
    assert_eq!(
        (gs.as_deref(), gm.as_deref(), msg),
        (Some("2"), Some("dns request rejected"), None)
    );

    let (_, gs, gm, _) = grpc_call(port, false, "/coredns.dns.DnsService/Nope", &[]).await;
    assert_eq!(gs.as_deref(), Some("12"));
    assert_eq!(
        gm.as_deref(),
        Some("unknown method Nope for service coredns.dns.DnsService")
    );
}

#[tokio::test]
async fn grpc_tls() {
    let inst = start(&format!("grpc://.:0 {{\n {}\n whoami\n}}", tls_line())).await;
    let port = port_of(&inst, 0);
    let pb = kerndns_server::grpc::encode_packet(&query(5));
    let (status, gs, _, msg) = grpc_call(port, true, "/coredns.dns.DnsService/Query", &pb).await;
    assert_eq!((status, gs.as_deref()), (200, Some("0")));
    check_whoami(&msg.unwrap(), 5, "tcp");
}

#[tokio::test]
async fn grpc_connection_limit() {
    let inst = start("grpc://.:0 {\n grpc_server {\n  max_connections 1\n }\n whoami\n}").await;
    let port = port_of(&inst, 0);
    let held = tokio::net::TcpStream::connect(localhost(port)).await.unwrap();
    // let the server accept it
    tokio::time::sleep(Duration::from_millis(100)).await;
    // a second connection is not served while the first is open
    let pb = kerndns_server::grpc::encode_packet(&query(1));
    let blocked = tokio::spawn(async move { grpc_call(port, false, "/coredns.dns.DnsService/Query", &pb).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!blocked.is_finished());
    drop(held);
    let (_, gs, _, _) = tokio::time::timeout(Duration::from_secs(5), blocked)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gs.as_deref(), Some("0"));
}

/// The SETTINGS_MAX_CONCURRENT_STREAMS a DoH listener announces.
async fn doh_max_streams(port: u16) -> Option<u32> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tcp = tokio::net::TcpStream::connect(localhost(port)).await.unwrap();
    let c = tokio_rustls::TlsConnector::from(Arc::new(client_tls(&[b"h2"])));
    let mut s = c
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
        .await
        .unwrap();
    loop {
        let mut hdr = [0u8; 9];
        s.read_exact(&mut hdr).await.unwrap();
        let len = (hdr[0] as usize) << 16 | (hdr[1] as usize) << 8 | hdr[2] as usize;
        let mut payload = vec![0u8; len];
        s.read_exact(&mut payload).await.unwrap();
        if hdr[3] != 4 || hdr[4] & 1 != 0 {
            continue;
        }
        return payload
            .chunks(6)
            .find(|c| u16::from_be_bytes([c[0], c[1]]) == 3)
            .map(|c| u32::from_be_bytes([c[2], c[3], c[4], c[5]]));
    }
}

#[tokio::test]
async fn doh_limits() {
    // max_streams is propagated to the https key even when it isn't first
    let inst = start(&format!(
        ".:0 https://.:0 {{\n bind 127.0.0.1\n {}\n https {{\n  max_streams 7\n }}\n whoami\n}}",
        tls_line()
    ))
    .await;
    let https = inst.listeners().iter().find(|l| l.label.starts_with("https")).unwrap();
    assert!(https.udp.is_none());
    assert_eq!(doh_max_streams(https.port()).await, Some(7));
    // the default is Go's 250
    let inst = start(&format!("https://.:0 {{\n {}\n whoami\n}}", tls_line())).await;
    assert_eq!(doh_max_streams(port_of(&inst, 0)).await, Some(250));
}

#[test]
fn conflicting_doh_max_streams() {
    let tls = tls_line();
    let corefile = format!(
        "https://a.:8443 {{\n {tls}\n https {{\n  max_streams 7\n }}\n whoami\n}}\n\
         https://b.:8443 {{\n {tls}\n https {{\n  max_streams 8\n }}\n whoami\n}}"
    );
    let e = load(&corefile, "Corefile", &kerndns_plugins::registry(), &Options::default())
        .err()
        .unwrap()
        .to_string();
    assert_eq!(
        e,
        "conflicting max_streams values for shared HTTPS listener https://:8443: 7 and 8"
    );
}

/// A UDP proxy on a local port that puts a PROXY v2 header for `client`
/// (with `tlvs`) in front of every datagram to `server` and relays the
/// answers back, like a QUIC load balancer.
async fn ppv2_relay(server: SocketAddr, client: SocketAddr, tlvs: &[u8]) -> u16 {
    let SocketAddr::V4(c) = client else { panic!("IPv4 only") };
    let mut header = b"\r\n\r\n\0\r\nQUIT\n\x21\x12".to_vec();
    header.extend_from_slice(&(12 + tlvs.len() as u16).to_be_bytes());
    header.extend_from_slice(&c.ip().octets());
    header.extend_from_slice(&[127, 0, 0, 1]);
    header.extend_from_slice(&c.port().to_be_bytes());
    header.extend_from_slice(&server.port().to_be_bytes());
    header.extend_from_slice(tlvs);
    let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = front.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut a, mut b) = (vec![0u8; 65536], vec![0u8; 65536]);
        let mut from = None;
        loop {
            tokio::select! {
                r = front.recv_from(&mut a) => {
                    let (n, src) = r.unwrap();
                    from = Some(src);
                    let mut pkt = header.clone();
                    pkt.extend_from_slice(&a[..n]);
                    let _ = back.send_to(&pkt, server).await;
                }
                r = back.recv_from(&mut b) => {
                    let (n, _) = r.unwrap();
                    if let Some(c) = from {
                        let _ = front.send_to(&b[..n], c).await;
                    }
                }
            }
        }
    });
    port
}

/// whoami's address and port.
fn whoami_addr(wire: &[u8]) -> (String, u16) {
    let m = Message::from_vec(wire).unwrap();
    let mut addr = String::new();
    let mut port = 0;
    for r in &m.additionals {
        match &r.data {
            kerndns_core::proto::rr::RData::A(a) => addr = a.to_string(),
            kerndns_core::proto::rr::RData::SRV(s) => port = s.port,
            _ => {}
        }
    }
    (addr, port)
}

/// What whoami (address and port) or the TXT template (the TLVs) says.
fn seen(wire: &[u8]) -> String {
    let m = Message::from_vec(wire).unwrap();
    if let Some(txt) = m.answers.first() {
        return txt.data.to_string();
    }
    let (addr, port) = whoami_addr(wire);
    format!("{addr}:{port}")
}

fn txt_query() -> Vec<u8> {
    let mut m = Message::new(0, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii("x.example.").unwrap(), RecordType::TXT));
    m.to_vec().unwrap()
}

async fn doh3_get(port: u16, q: &[u8]) -> Vec<u8> {
    let b64 = data_encoding::BASE64URL_NOPAD.encode(q);
    let get = http::Request::get(format!("https://localhost:{port}/dns-query?dns={b64}"))
        .body(())
        .unwrap();
    let (status, _, body) = h3_request(port, get, None).await;
    assert_eq!(status, 200);
    body
}

/// DoQ and DoH3 behind a proxy that sends PROXY v2 headers: what a
/// proxied client is told (twice on one DoQ connection), then a direct
/// one (its port left out), then the TLVs of a proxied client.
async fn quic_proxyproto(doq: u16, doh3: u16) -> Vec<String> {
    let client: SocketAddr = "203.0.113.7:4242".parse().unwrap();
    let tlvs = [0xe0, 0, 2, 0xab, 0xcd];
    let mut out = Vec::new();

    let relay = ppv2_relay(localhost(doq), client, &tlvs).await;
    let conn = quic_connect(relay, b"doq").await;
    out.push(seen(&doq_exchange(&conn, &query(0)).await.unwrap()));
    out.push(seen(&doq_exchange(&conn, &query(0)).await.unwrap()));
    let direct = quic_connect(doq, b"doq").await;
    out.push(whoami_addr(&doq_exchange(&direct, &query(0)).await.unwrap()).0);
    out.push(seen(&doq_exchange(&conn, &txt_query()).await.unwrap()));

    let relay = ppv2_relay(localhost(doh3), client, &tlvs).await;
    out.push(seen(&doh3_get(relay, &query(0)).await));
    out.push(whoami_addr(&doh3_get(doh3, &query(0)).await).0);
    out.push(seen(&doh3_get(relay, &txt_query()).await));
    out
}

/// One block per listener: CoreDNS sets plugins up for the first key of a
/// block only, and doesn't pass `proxyproto` on to the others.
fn quic_proxyproto_corefile(doq: u16, doh3: u16) -> String {
    let block = |key: String| {
        format!(
            "{key} {{\n bind 127.0.0.1\n {}\n metadata\n proxyproto {{\n  allow 127.0.0.1/32\n  tlv_metadata\n }}\n template IN TXT {{\n  answer \"{{{{ .Name }}}} 60 IN TXT \\\"{{{{ .Meta \\\"proxyproto/tlv\\\" }}}}\\\"\"\n }}\n whoami\n}}\n",
            tls_line()
        )
    };
    block(format!("quic://.:{doq}")) + &block(format!("https3://.:{doh3}"))
}

/// What CoreDNS answers in [`quic_proxyproto`].
fn quic_proxyproto_want() -> Vec<String> {
    [
        "203.0.113.7:4242",
        "203.0.113.7:4242",
        "127.0.0.1",
        "e00002abcd",
        "203.0.113.7:4242",
        "127.0.0.1",
        "e00002abcd",
    ]
    .map(String::from)
    .to_vec()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn quic_proxyproto_client() {
    let (doq, doh3) = (free_udp_port(), free_udp_port());
    let _inst = start(&quic_proxyproto_corefile(doq, doh3)).await;
    assert_eq!(quic_proxyproto(doq, doh3).await, quic_proxyproto_want());
}

/// [`quic_proxyproto_client`] against CoreDNS (`target/coredns-ref`, from
/// `cargo xtask difftest`, or `$COREDNS_REF`).
#[tokio::test]
#[ignore = "needs a CoreDNS binary"]
async fn quic_proxyproto_against_coredns() {
    let bin = std::env::var("COREDNS_REF")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/coredns-ref").to_string());
    let (doq, doh3) = (free_udp_port(), free_udp_port());
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("quic-proxyproto-{doq}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Corefile"), quic_proxyproto_corefile(doq, doh3)).unwrap();
    let mut child = std::process::Command::new(bin)
        .arg("-conf")
        .arg(dir.join("Corefile"))
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let got = tokio::time::timeout(Duration::from_secs(20), quic_proxyproto(doq, doh3)).await;
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(got.expect("CoreDNS answered"), quic_proxyproto_want());
}
