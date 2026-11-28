//! The UDP listener.
//!
//! hickory-server's UDP loop receives and sends every packet on one task,
//! which caps throughput. Here each listener has several `SO_REUSEPORT`
//! sockets (the kernel spreads clients across them), one receive loop per
//! socket. Requests are answered directly with `send_to`. While no other
//! packet is waiting, a request runs on its receive loop; one that has to
//! wait (an upstream, a timer), or arrives with more behind it, gets a task
//! of its own so the other workers can share the load. Each request is
//! parsed once and each response encoded once (re-encoded only if it has to
//! be truncated).

use std::future::Future;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use kerndns_core::proto::op::{Header, Message, MessageType, ResponseCode};
use kerndns_core::proto::serialize::binary::{BinDecodable, BinDecoder};
use kerndns_core::udpwrite::UdpDecorator;
use kerndns_core::{ConnInfo, Protocol, Request};
use socket2::{Domain, Protocol as SockProto, Socket, Type};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

use crate::dispatch::{Dispatcher, encode};
use crate::proxyproto::UdpProxy;

/// Bind `n` UDP sockets to `addr` with `SO_REUSEPORT`. With port 0 the
/// first socket picks the port and the others join it.
///
/// Like CoreDNS (`pkg/reuseport`), another server that also sets
/// `SO_REUSEPORT` can bind the same port and share the queries. CoreDNS's
/// integration tests rely on this (`TestView` starts a second server on a
/// port that is still in use).
pub fn bind_reuseport(addr: SocketAddr, n: usize) -> std::io::Result<Vec<UdpSocket>> {
    let mut addr = addr;
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

/// Serve `socks` until the returned tasks are aborted. With a
/// `decorator` (`shed`), each socket's responses go through the writer it
/// installs instead of straight to the socket.
pub fn serve(
    socks: Vec<UdpSocket>,
    dispatcher: Dispatcher,
    local: SocketAddr,
    decorator: Option<Arc<dyn UdpDecorator>>,
    proxy: Option<Arc<UdpProxy>>,
) -> JoinSet<()> {
    let mut set = JoinSet::new();
    for sock in socks {
        let sock = Arc::new(sock);
        let d = dispatcher.clone();
        let proxy = proxy.clone();
        let writer = decorator.as_ref().map(|dec| {
            let (w, task) = dec.decorate(d.label(), sock.clone());
            set.spawn(task);
            w
        });
        set.spawn(async move {
            let mut buf = vec![0u8; 65535];
            // a packet already read while checking for a backlog
            let mut queued = None;
            loop {
                let (n, src) = match queued.take() {
                    Some(x) => x,
                    None => match sock.recv_from(&mut buf).await {
                        Ok(x) => x,
                        Err(_) => continue,
                    },
                };
                // PROXY protocol: the client is the header's source
                let (packet, client, tlvs) = match &proxy {
                    None => (buf[..n].to_vec(), src, None),
                    Some(p) => match p.read(&buf[..n], src) {
                        Ok(Some(dg)) => (buf[dg.offset..n].to_vec(), dg.client, dg.tlvs),
                        Ok(None) => continue,
                        Err(e) => {
                            kerndns_core::warning!(
                                "dropping invalid Proxy Protocol packet from {}: {e}",
                                crate::proxyproto::canonical(src)
                            );
                            continue;
                        }
                    },
                };
                let (sock2, d, writer) = (sock.clone(), d.clone(), writer.clone());
                let fut = Box::pin(async move {
                    let conn = ConnInfo {
                        udp_writer: writer.clone(),
                        proxy_tlvs: tlvs,
                    };
                    let wires = handle(&d, &packet, client, local, Protocol::Udp, conn).await;
                    for wire in wires {
                        match &writer {
                            Some(w) => w.write(wire, src),
                            None => {
                                let _ = sock2.send_to(&wire, src).await;
                            }
                        }
                    }
                });
                // More packets waiting: give this one a task of its own so
                // idle workers can take it. Otherwise answer it right here.
                match sock.try_recv_from(&mut buf) {
                    Ok(next) => {
                        queued = Some(next);
                        tokio::spawn(fut);
                    }
                    Err(_) => run_or_spawn(fut).await,
                }
            }
        });
    }
    set
}

/// Run one request's future on the receive loop and spawn it as a task of
/// its own only if it has to wait (an upstream, a timer, a lock).
///
/// Most chains answer without waiting (whoami, cache hits, file, hosts):
/// they then cost no task (allocation, scheduling, moving the request's
/// future into it) and no hand-off to another worker thread. A panic is
/// contained like in a spawned task: the request is dropped and the
/// receive loop goes on.
async fn run_or_spawn(mut fut: Pin<Box<dyn Future<Output = ()> + Send>>) {
    let polled = std::future::poll_fn(|cx| Poll::Ready(catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(cx))))).await;
    if let Ok(Poll::Pending) = polled {
        tokio::spawn(fut);
    }
}

/// Answer one packet; returns the wire responses to send.
pub async fn handle(
    d: &Dispatcher,
    packet: &[u8],
    src: SocketAddr,
    local: SocketAddr,
    protocol: Protocol,
    conn: ConnInfo,
) -> Vec<Vec<u8>> {
    let msg = match Message::from_vec(packet) {
        Ok(m) => m,
        Err(_) => return formerr(packet).into_iter().collect(),
    };
    // never answer responses (reflection)
    if msg.metadata.message_type == MessageType::Response {
        return Vec::new();
    }
    answer(d, msg, packet, src, local, protocol, conn).await
}

/// Serve a parsed request `msg` (received as `packet`); returns the wire
/// responses, truncated to what the client accepts and signed.
pub async fn answer(
    d: &Dispatcher,
    msg: Message,
    packet: &[u8],
    src: SocketAddr,
    local: SocketAddr,
    protocol: Protocol,
    conn: ConnInfo,
) -> Vec<Vec<u8>> {
    let mut req = Request::new(msg, local, src, protocol);
    req.wire = Some(Arc::from(packet));
    req.conn = conn;
    let answer = d.answer(&req).await;
    let size = crate::dispatch::effective_request(&req, answer.edns.as_deref(), answer.bufsize).size() as usize;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn run_or_spawn_runs_inline_spawns_waiting_and_contains_panics() {
        let done = Arc::new(AtomicUsize::new(0));

        // ready at once: done before run_or_spawn returns
        let d = done.clone();
        run_or_spawn(Box::pin(async move {
            d.fetch_add(1, Ordering::SeqCst);
        }))
        .await;
        assert_eq!(done.load(Ordering::SeqCst), 1);

        // has to wait: finishes later in a task of its own
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let d = done.clone();
        run_or_spawn(Box::pin(async move {
            let _ = rx.await;
            d.fetch_add(1, Ordering::SeqCst);
        }))
        .await;
        assert_eq!(done.load(Ordering::SeqCst), 1);
        tx.send(()).unwrap();
        for _ in 0..100 {
            if done.load(Ordering::SeqCst) == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(done.load(Ordering::SeqCst), 2);

        // a panic is contained, like in a spawned task
        run_or_spawn(Box::pin(async { panic!("plugin bug") })).await;
    }
}
