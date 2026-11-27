//! DNS over HTTP/3, a port of CoreDNS's `ServerHTTPS3`
//! (`core/dnsserver/server_https3.go`), on quinn and h3.
//!
//! The requests are DoH's ([`crate::doh::respond`]): `/dns-query`, GET or
//! POST, the same status codes, counted in
//! `coredns_dns_https3_responses_total`. ALPN is `h3`; headers are limited
//! to 16 KiB. Limits (`https3` plugin): `max_streams` concurrent QUIC
//! streams per connection (default 256, 0 = QUIC's default) and
//! `max_connections` (default 200, 0 = unbounded; extra connections are
//! closed with `H3_EXCESSIVE_LOAD`).

use std::net::SocketAddr;
use std::time::Duration;

use bytes::{Buf, Bytes};
use kerndns_core::Protocol;
use kerndns_core::plugin::ListenerLimits;
use quinn::{Endpoint, VarInt};
use tokio::task::JoinSet;

use crate::dispatch::Dispatcher;
use crate::doh::{MAX_QUERY, connection_limit, respond};
use crate::quic::CloseOnDrop;

const DEFAULT_MAX_STREAMS: u64 = 256;
const DEFAULT_MAX_CONNECTIONS: u64 = 200;
/// `DefaultHTTPS3MaxHeaderBytes`.
const MAX_HEADER_BYTES: u64 = 16 << 10;
/// `H3_EXCESSIVE_LOAD`.
const EXCESSIVE_LOAD: u32 = 0x107;

/// DoH3 listener settings.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// `None` keeps QUIC's default.
    pub max_streams: Option<u64>,
    /// 0 is unbounded.
    pub max_connections: u64,
    pub idle_timeout: Duration,
}

impl Settings {
    pub fn new(l: &ListenerLimits, conn: &crate::tcp::Limits) -> Self {
        Settings {
            max_streams: match l.https3_max_streams.unwrap_or(DEFAULT_MAX_STREAMS) {
                0 => None,
                n => Some(n),
            },
            max_connections: l.https3_max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            idle_timeout: conn.idle,
        }
    }
}

/// Serve DoH3 on `ep` until the returned tasks are aborted.
pub fn serve(ep: Endpoint, d: Dispatcher, local: SocketAddr, s: Settings) -> JoinSet<()> {
    let limit = connection_limit(s.max_connections);
    let mut set = JoinSet::new();
    set.spawn(async move {
        let ep = CloseOnDrop(ep);
        while let Some(incoming) = ep.0.accept().await {
            let (d, limit) = (d.clone(), limit.clone());
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let permit = match limit.map(tokio::sync::Semaphore::try_acquire_owned) {
                    None => None,
                    Some(Ok(p)) => Some(p),
                    Some(Err(_)) => {
                        conn.close(VarInt::from_u32(EXCESSIVE_LOAD), b"too many connections");
                        return;
                    }
                };
                connection(d, conn, local).await;
                drop(permit);
            });
        }
    });
    set
}

async fn connection(d: Dispatcher, conn: quinn::Connection, local: SocketAddr) {
    let src = conn.remote_address();
    let mut h3 = match h3::server::builder()
        .max_field_section_size(MAX_HEADER_BYTES)
        .send_grease(false)
        .build::<_, Bytes>(h3_quinn::Connection::new(conn))
        .await
    {
        Ok(c) => c,
        Err(_) => return,
    };
    loop {
        let resolver = match h3.accept().await {
            Ok(Some(r)) => r,
            Ok(None) | Err(_) => return,
        };
        let d = d.clone();
        tokio::spawn(async move {
            let Ok((req, mut stream)) = resolver.resolve_request().await else {
                return;
            };
            let (parts, ()) = req.into_parts();
            let body = async {
                let mut buf = Vec::new();
                while let Some(mut chunk) = stream.recv_data().await.map_err(|_| ())? {
                    if buf.len() + chunk.remaining() > MAX_QUERY {
                        return Err(());
                    }
                    while chunk.has_remaining() {
                        let c = chunk.chunk();
                        buf.extend_from_slice(c);
                        let n = c.len();
                        chunk.advance(n);
                    }
                }
                Ok(buf)
            };
            let resp = respond(
                &d,
                &parts.method,
                &parts.uri,
                body,
                src,
                local,
                Protocol::Https3,
                &kerndns_core::metrics::HTTPS3_RESPONSES,
            )
            .await;
            let (parts, body) = resp.into_parts();
            if stream
                .send_response(http::Response::from_parts(parts, ()))
                .await
                .is_err()
            {
                return;
            }
            if !body.is_empty() && stream.send_data(body).await.is_err() {
                return;
            }
            let _ = stream.finish().await;
        });
    }
}

/// The endpoint for a DoH3 listener.
pub fn endpoint(sock: std::net::UdpSocket, tls: &rustls::ServerConfig, s: &Settings) -> Result<Endpoint, String> {
    crate::quic::endpoint(sock, tls, &[b"h3"], s.max_streams, s.idle_timeout)
}
