//! The UDP listener.
//!
//! hickory-server's UDP loop receives and sends every packet on one task,
//! which caps throughput. Here each listener has several `SO_REUSEPORT`
//! sockets (the kernel spreads clients across them), one receive loop per
//! socket, and every request runs in its own task that answers directly
//! with `send_to`. Each request is parsed once and each response encoded
//! once (re-encoded only if it has to be truncated).

use std::net::SocketAddr;
use std::sync::Arc;

use kerndns_core::proto::op::{Header, Message, MessageType, ResponseCode};
use kerndns_core::proto::serialize::binary::{BinDecodable, BinDecoder};
use kerndns_core::{Protocol, Request};
use socket2::{Domain, Protocol as SockProto, Socket, Type};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

use crate::dispatch::{Dispatcher, encode};

/// Bind `n` UDP sockets to `addr` with `SO_REUSEPORT`. With port 0 the
/// first socket picks the port and the others join it.
///
/// `SO_REUSEPORT` would also let a second server process join the group
/// and silently take half the queries. So the address is first bound
/// without it: if anyone holds the port this fails with "address in use",
/// like any other server; if not, the probe is released and the group bound.
pub fn bind_reuseport(addr: SocketAddr, n: usize) -> std::io::Result<Vec<UdpSocket>> {
    let mut addr = addr;
    {
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let probe = Socket::new(domain, Type::DGRAM, Some(SockProto::UDP))?;
        if addr.is_ipv6() {
            let _ = probe.set_only_v6(false);
        }
        probe.bind(&addr.into())?;
        if addr.port() == 0 {
            // keep the port the kernel picked for the group
            addr.set_port(probe.local_addr()?.as_socket().expect("inet socket").port());
        }
    }
    let mut socks = Vec::with_capacity(n);
    for _ in 0..n.max(1) {
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let s = Socket::new(domain, Type::DGRAM, Some(SockProto::UDP))?;
        if addr.is_ipv6() {
            // dual stack, like Go's ":53"
            let _ = s.set_only_v6(false);
        }
        s.set_reuse_port(true)?;
        s.set_nonblocking(true)?;
        s.bind(&addr.into())?;
        let local = s.local_addr()?.as_socket().expect("inet socket");
        addr.set_port(local.port());
        socks.push(UdpSocket::from_std(s.into())?);
    }
    Ok(socks)
}

/// Serve `socks` until the returned tasks are aborted.
pub fn serve(socks: Vec<UdpSocket>, dispatcher: Dispatcher, local: SocketAddr) -> JoinSet<()> {
    let mut set = JoinSet::new();
    for sock in socks {
        let sock = Arc::new(sock);
        let d = dispatcher.clone();
        set.spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let packet = buf[..n].to_vec();
                let (sock, d) = (sock.clone(), d.clone());
                tokio::spawn(async move {
                    for wire in handle(&d, &packet, src, local, Protocol::Udp).await {
                        let _ = sock.send_to(&wire, src).await;
                    }
                });
            }
        });
    }
    set
}

/// Answer one packet; returns the wire responses to send.
pub async fn handle(
    d: &Dispatcher,
    packet: &[u8],
    src: SocketAddr,
    local: SocketAddr,
    protocol: Protocol,
) -> Vec<Vec<u8>> {
    let msg = match Message::from_vec(packet) {
        Ok(m) => m,
        Err(_) => return formerr(packet).into_iter().collect(),
    };
    // never answer responses (reflection)
    if msg.metadata.message_type == MessageType::Response {
        return Vec::new();
    }
    let mut req = Request::new(msg, local, src, protocol);
    req.wire = Some(Arc::from(packet));
    let answer = d.answer(&req).await;
    let size = crate::dispatch::effective_request(&req, answer.bufsize).size() as usize;
    encode(answer, size)
}

/// A FORMERR for a packet whose header parses but whose body doesn't.
pub fn formerr(packet: &[u8]) -> Option<Vec<u8>> {
    let header = Header::read(&mut BinDecoder::new(packet)).ok()?;
    if header.metadata.message_type == MessageType::Response {
        return None;
    }
    let mut m = Message::new(header.metadata.id, MessageType::Response, header.metadata.op_code);
    m.metadata.response_code = ResponseCode::FormErr;
    m.to_vec().ok()
}
