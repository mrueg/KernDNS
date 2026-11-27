//! End-to-end test of `shed` on the plain DNS listener: queries over UDP
//! (through the socket's single writer) and TCP (passed through) are
//! answered.

use std::net::SocketAddr;
use std::time::Duration;

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query};
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

fn whoami(wire: &[u8]) -> (u16, ()) {
    (Message::from_vec(wire).unwrap().metadata.id, ())
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
async fn shed_answers_udp_and_tcp() {
    let inst = start(".:0 {\n shed\n whoami\n}").await;
    let l = inst.listeners()[0].clone();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for id in 0..50 {
        sock.send_to(&query(id), localhost(l.udp.unwrap().port()))
            .await
            .unwrap();
        let r = recv(&sock, Duration::from_secs(5)).await.expect("an answer");
        assert_eq!(whoami(&r).0, id);
    }
    let r = tcp_exchange(l.tcp.unwrap().port(), &[], &query(99)).await.unwrap();
    assert_eq!(whoami(&r).0, 99);
}
