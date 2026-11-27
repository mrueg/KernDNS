//! TCP (and DoT) listeners: two-byte length-framed messages, served in
//! order per connection, closed after 10s without a query (CoreDNS's idle
//! timeout). Responses are encoded and signed by [`crate::dispatch::encode`].

use std::net::SocketAddr;
use std::time::Duration;

use kerndns_core::Protocol;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::dispatch::Dispatcher;
use crate::udp::handle;

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Serve DNS over TCP, or over TLS if `tls` is given.
pub fn serve(
    listener: TcpListener,
    dispatcher: Dispatcher,
    local: SocketAddr,
    tls: Option<TlsAcceptor>,
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
                    None => connection(stream, &d, src, local, Protocol::Tcp).await,
                    Some(acc) => {
                        if let Ok(Ok(s)) = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acc.accept(stream)).await {
                            connection(s, &d, src, local, Protocol::Tls).await;
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
) {
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(IDLE_TIMEOUT, s.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        match tokio::time::timeout(IDLE_TIMEOUT, s.read_exact(&mut buf)).await {
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
            if s.write_all(&out).await.is_err() {
                return;
            }
        }
        if s.flush().await.is_err() {
            return;
        }
    }
}
