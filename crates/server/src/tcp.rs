//! TCP (and DoT) listeners: two-byte length-framed messages, served in
//! order per connection. Like miekg/dns, the first query must arrive within
//! the read timeout (3s), later ones within the idle timeout (10s), writes
//! must finish within the write timeout (5s), and a connection may be
//! limited to a number of queries; `timeouts` changes these. Responses are
//! encoded and signed by [`crate::dispatch::encode`].

use std::net::SocketAddr;
use std::time::Duration;

use kerndns_core::Protocol;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::dispatch::Dispatcher;
use crate::udp::handle;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Bind `n` TCP listeners to `addr` (`multisocket`), all with
/// `SO_REUSEPORT` like CoreDNS (see [`crate::udp::bind_reuseport`]). With
/// port 0 the first listener picks the port and the others join it.
pub async fn bind_reuseport(addr: SocketAddr, n: usize) -> std::io::Result<Vec<TcpListener>> {
    use socket2::{Domain, Protocol as SockProto, Socket, Type};
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let mut addr = addr;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n.max(1) {
        let s = Socket::new(domain, Type::STREAM, Some(SockProto::TCP))?;
        if addr.is_ipv6() {
            // dual stack, like Go's ":53"
            let _ = s.set_only_v6(false);
        }
        s.set_reuse_address(true)?;
        s.set_reuse_port(true)?;
        s.set_nonblocking(true)?;
        s.bind(&addr.into())?;
        s.listen(1024)?;
        addr.set_port(s.local_addr()?.as_socket().expect("inet socket").port());
        out.push(TcpListener::from_std(s.into())?);
    }
    Ok(out)
}

/// Per-connection timeouts and query limit.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub read: Duration,
    pub write: Duration,
    pub idle: Duration,
    /// `None` is unlimited.
    pub max_queries: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            read: Duration::from_secs(3),
            write: Duration::from_secs(5),
            idle: Duration::from_secs(10),
            max_queries: None,
        }
    }
}

impl From<&kerndns_core::plugin::ConnLimits> for Limits {
    fn from(c: &kerndns_core::plugin::ConnLimits) -> Self {
        let d = Limits::default();
        Limits {
            read: c.read.unwrap_or(d.read),
            write: c.write.unwrap_or(d.write),
            idle: c.idle.unwrap_or(d.idle),
            max_queries: c.max_tcp_queries.and_then(|n| u64::try_from(n).ok()),
        }
    }
}

/// Serve DNS over TCP, or over TLS if `tls` is given.
pub fn serve(
    listener: TcpListener,
    dispatcher: Dispatcher,
    local: SocketAddr,
    tls: Option<TlsAcceptor>,
    limits: Limits,
) -> JoinSet<()> {
    let mut set = JoinSet::new();
    set.spawn(async move {
        loop {
            let Ok((stream, src)) = listener.accept().await else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let d = dispatcher.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                match tls {
                    None => connection(stream, &d, src, local, Protocol::Tcp, limits).await,
                    Some(acc) => {
                        if let Ok(Ok(s)) = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acc.accept(stream)).await {
                            connection(s, &d, src, local, Protocol::Tls, limits).await;
                        }
                    }
                }
            });
        }
    });
    set
}

async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    d: &Dispatcher,
    src: SocketAddr,
    local: SocketAddr,
    protocol: Protocol,
    limits: Limits,
) {
    let mut served: u64 = 0;
    loop {
        if limits.max_queries.is_some_and(|m| served >= m) {
            return;
        }
        let wait = if served == 0 { limits.read } else { limits.idle };
        let mut len = [0u8; 2];
        match tokio::time::timeout(wait, s.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        match tokio::time::timeout(limits.read, s.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        for wire in handle(d, &buf, src, local, protocol).await {
            let Ok(n) = u16::try_from(wire.len()) else {
                kerndns_core::error!("dropping a {}-byte response: too big for TCP", wire.len());
                continue;
            };
            let mut out = Vec::with_capacity(wire.len() + 2);
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(&wire);
            if !matches!(tokio::time::timeout(limits.write, s.write_all(&out)).await, Ok(Ok(()))) {
                return;
            }
        }
        if !matches!(tokio::time::timeout(limits.write, s.flush()).await, Ok(Ok(()))) {
            return;
        }
        served += 1;
    }
}
