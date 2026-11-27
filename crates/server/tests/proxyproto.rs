//! End-to-end tests of PROXY protocol (`proxyproto`) on the plain DNS
//! listener: the address `whoami` reports is the header's source.

use std::net::SocketAddr;
use std::time::Duration;

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_server::{Instance, Options};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

async fn start(corefile: &str) -> Instance {
    Instance::start(corefile, "Corefile", &kerndns_plugins::registry(), &Options::default())
        .await
        .unwrap_or_else(|e| panic!("start: {e}"))
}

fn query(id: u16) -> Vec<u8> {
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(
        Name::from_ascii("whoami.example.org.").unwrap(),
        RecordType::A,
    ));
    m.to_vec().unwrap()
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// A PROXY v2 header for `src` over UDP (`0x12`) or TCP (`0x11`).
fn ppv2(transport: u8, src: [u8; 4], port: u16) -> Vec<u8> {
    let mut b = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    b.extend_from_slice(&[0x21, transport, 0, 12]);
    b.extend_from_slice(&src);
    b.extend_from_slice(&[127, 0, 0, 1]);
    b.extend_from_slice(&port.to_be_bytes());
    b.extend_from_slice(&53u16.to_be_bytes());
    b
}

/// The id and the address whoami reports.
fn whoami(wire: &[u8]) -> (u16, String) {
    let m = Message::from_vec(wire).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    let a = m
        .additionals
        .iter()
        .find(|r| r.record_type() == RecordType::A)
        .map(|r| r.data.to_string())
        .unwrap_or_default();
    (m.metadata.id, a)
}

async fn recv(sock: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 1500];
    let n = tokio::time::timeout(wait, sock.recv(&mut buf)).await.ok()?.unwrap();
    Some(buf[..n].to_vec())
}

async fn tcp_exchange(port: u16, prefix: &[u8], q: &[u8]) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect(localhost(port)).await.unwrap();
    let mut out = prefix.to_vec();
    out.extend_from_slice(&(q.len() as u16).to_be_bytes());
    out.extend_from_slice(q);
    s.write_all(&out).await.unwrap();
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await.ok()?;
    let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut resp).await.ok()?;
    Some(resp)
}

#[tokio::test]
async fn udp_and_tcp() {
    let inst = start(".:0 {\n proxyproto {\n  allow 127.0.0.0/8\n }\n whoami\n}").await;
    let l = inst.listeners()[0].clone();
    let udp = l.udp.unwrap().port();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut pkt = ppv2(0x12, [192, 0, 2, 33], 4242);
    pkt.extend_from_slice(&query(7));
    sock.send_to(&pkt, localhost(udp)).await.unwrap();
    let r = recv(&sock, Duration::from_secs(5)).await.expect("an answer");
    assert_eq!(whoami(&r), (7, "192.0.2.33".into()));

    // no header: the peer's address
    sock.send_to(&query(8), localhost(udp)).await.unwrap();
    let r = recv(&sock, Duration::from_secs(5)).await.expect("an answer");
    assert_eq!(whoami(&r), (8, "127.0.0.1".into()));

    // TCP with a v1 and a v2 header
    let tcp = l.tcp.unwrap().port();
    let r = tcp_exchange(tcp, b"PROXY TCP4 198.51.100.7 127.0.0.1 5555 53\r\n", &query(9))
        .await
        .unwrap();
    assert_eq!(whoami(&r), (9, "198.51.100.7".into()));
    let r = tcp_exchange(tcp, &ppv2(0x11, [203, 0, 113, 1], 1), &query(10))
        .await
        .unwrap();
    assert_eq!(whoami(&r), (10, "203.0.113.1".into()));
    // an invalid header closes the connection
    assert!(tcp_exchange(tcp, b"PROXY TCP4 x\r\n", &query(11)).await.is_none());
}

#[tokio::test]
async fn reject_drops_datagrams_with_a_header() {
    let inst = start(".:0 {\n proxyproto {\n  allow 192.0.2.0/24\n  default reject\n }\n whoami\n}").await;
    let port = inst.listeners()[0].udp.unwrap().port();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut pkt = ppv2(0x12, [192, 0, 2, 33], 4242);
    pkt.extend_from_slice(&query(7));
    sock.send_to(&pkt, localhost(port)).await.unwrap();
    assert!(recv(&sock, Duration::from_millis(300)).await.is_none());
    sock.send_to(&query(8), localhost(port)).await.unwrap();
    let r = recv(&sock, Duration::from_secs(5)).await.expect("an answer");
    assert_eq!(whoami(&r), (8, "127.0.0.1".into()));
}

#[tokio::test]
async fn tlv_metadata() {
    // the TLVs reach the metadata label (template prints it)
    let inst = start(
        ".:0 {\n metadata\n proxyproto {\n  tlv_metadata\n }\n template IN TXT {\n  answer \"{{ .Name }} 60 IN TXT \\\"{{ .Meta \\\"proxyproto/tlv\\\" }}\\\"\"\n }\n}",
    )
    .await;
    let port = inst.listeners()[0].udp.unwrap().port();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut pkt = ppv2(0x12, [192, 0, 2, 33], 4242);
    pkt[15] = 12 + 5;
    pkt.extend_from_slice(&[0xe0, 0, 2, 0xab, 0xcd]);
    let mut m = Message::new(1, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii("x.example.").unwrap(), RecordType::TXT));
    pkt.extend_from_slice(&m.to_vec().unwrap());
    sock.send_to(&pkt, localhost(port)).await.unwrap();
    let r = recv(&sock, Duration::from_secs(5)).await.expect("an answer");
    let m = Message::from_vec(&r).unwrap();
    assert_eq!(m.answers.len(), 1, "{m:?}");
    assert_eq!(m.answers[0].data.to_string(), "e00002abcd");
}
