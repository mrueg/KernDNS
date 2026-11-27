//! DNS over QUIC (RFC 9250), a port of CoreDNS's `ServerQUIC`
//! (`core/dnsserver/server_quic.go`), on quinn.
//!
//! - ALPN `doq`; one query per client-initiated bidirectional stream, as a
//!   2-byte length and the message; the answer goes back on the same
//!   stream, followed by FIN.
//! - Protocol errors (no length prefix, a short message, a message that
//!   doesn't parse or isn't a plain query, a non-zero ID, the
//!   `edns-tcp-keepalive` option) close the connection with
//!   `DOQ_PROTOCOL_ERROR` (2). A stream whose query doesn't arrive within
//!   the read timeout, or that the client resets, is reset with
//!   `DOQ_INTERNAL_ERROR` (1) and the connection lives on.
//! - Limits: `max_streams` concurrent streams per connection (default 256),
//!   `max_connections` (default 200, 0 = unbounded; extra connections are
//!   closed with code 0 "too many connections") and `worker_pool_size`
//!   streams served at once (default 1024). The idle timeout is the
//!   server's (`timeouts`, default 10s), and 0-RTT is accepted.
//! - `coredns_dns_quic_responses_total{server,status}` counts streams by
//!   the code they ended with (`0x0`, `0x1`, `0x2`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use kerndns_core::Protocol;
use kerndns_core::plugin::ListenerLimits;
use kerndns_core::proto::op::Message;
use quinn::{ConnectionError, Endpoint, ReadError, ReadExactError, RecvStream, SendStream, VarInt};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::dispatch::Dispatcher;
use crate::udp::answer;
use crate::unpack::unpack_request;

const NO_ERROR: u32 = 0;
const INTERNAL_ERROR: u32 = 1;
const PROTOCOL_ERROR: u32 = 2;

const DEFAULT_MAX_STREAMS: u64 = 256;
const DEFAULT_WORKERS: u64 = 1024;
const DEFAULT_MAX_CONNECTIONS: u64 = 200;

/// `edns-tcp-keepalive` (RFC 7828), not allowed over DoQ.
const EDNS_TCP_KEEPALIVE: u16 = 11;

/// A QUIC server endpoint on `sock` with the `tls` certificate, offering
/// `alpn`. `max_streams` limits concurrent bidirectional and unidirectional
/// streams per connection (`None` keeps quinn's default of 100).
pub fn endpoint(
    sock: std::net::UdpSocket,
    tls: &rustls::ServerConfig,
    alpn: &[&[u8]],
    max_streams: Option<u64>,
    idle: Duration,
) -> Result<Endpoint, String> {
    let mut tls = tls.clone();
    tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    // accept 0-RTT, like CoreDNS's Allow0RTT
    tls.max_early_data_size = u32::MAX;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| format!("QUIC TLS: {e}"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    if let Some(n) = max_streams {
        let n = VarInt::from_u64(n).map_err(|e| e.to_string())?;
        transport.max_concurrent_bidi_streams(n);
        transport.max_concurrent_uni_streams(n);
    }
    transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(idle).map_err(|e| e.to_string())?));
    cfg.transport_config(Arc::new(transport));
    let runtime = quinn::default_runtime().ok_or("no async runtime")?;
    Endpoint::new(quinn::EndpointConfig::default(), Some(cfg), sock, runtime).map_err(|e| e.to_string())
}

/// Closes the endpoint (and with it every connection) when the listener's
/// task is aborted, like `quicListener.Close()`.
pub struct CloseOnDrop(pub Endpoint);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close(VarInt::from_u32(NO_ERROR), b"");
    }
}

/// DoQ settings of one listener.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    pub max_streams: u64,
    /// 0 is unbounded.
    pub max_connections: u64,
    pub workers: u64,
    pub read_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Settings {
    pub fn new(l: &ListenerLimits, conn: &crate::tcp::Limits) -> Self {
        Settings {
            max_streams: l.quic_max_streams.unwrap_or(DEFAULT_MAX_STREAMS),
            max_connections: l.quic_max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            workers: l.quic_worker_pool_size.unwrap_or(DEFAULT_WORKERS),
            read_timeout: conn.read,
            idle_timeout: conn.idle,
        }
    }
}

struct Shared {
    d: Dispatcher,
    local: SocketAddr,
    workers: Arc<Semaphore>,
    read_timeout: Duration,
}

impl Shared {
    fn count(&self, code: u32) {
        kerndns_core::metrics::QUIC_RESPONSES
            .with_label_values(&[self.d.label(), &format!("{code:#x}")])
            .inc();
    }

    /// `closeQUICConn`: close the connection; anything but NO_ERROR counts.
    fn close(&self, conn: &quinn::Connection, code: u32) {
        conn.close(VarInt::from_u32(code), b"");
        if code != NO_ERROR {
            self.count(code);
        }
    }
}

/// Serve DoQ on `ep` until the returned tasks are aborted.
pub fn serve(ep: Endpoint, d: Dispatcher, local: SocketAddr, s: Settings) -> JoinSet<()> {
    let shared = Arc::new(Shared {
        d,
        local,
        workers: Arc::new(Semaphore::new(s.workers.min(Semaphore::MAX_PERMITS as u64) as usize)),
        read_timeout: s.read_timeout,
    });
    let conns = (s.max_connections > 0).then(|| {
        Arc::new(Semaphore::new(
            s.max_connections.min(Semaphore::MAX_PERMITS as u64) as usize
        ))
    });
    let mut set = JoinSet::new();
    set.spawn(async move {
        let ep = CloseOnDrop(ep);
        while let Some(incoming) = ep.0.accept().await {
            let (shared, conns) = (shared.clone(), conns.clone());
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let permit = match conns.map(Semaphore::try_acquire_owned) {
                    None => None,
                    Some(Ok(p)) => Some(p),
                    Some(Err(_)) => {
                        conn.close(VarInt::from_u32(NO_ERROR), b"too many connections");
                        return;
                    }
                };
                connection(&shared, conn).await;
                drop(permit);
            });
        }
    });
    set
}

/// `isExpectedErr`: the endpoint was closed, the connection was already
/// closed for a protocol error, or it timed out. Anything else (including
/// a client closing with code 0) is closed as an internal error and
/// counted, as CoreDNS does.
fn expected(e: &ConnectionError) -> bool {
    match e {
        ConnectionError::LocallyClosed | ConnectionError::TimedOut => true,
        ConnectionError::ApplicationClosed(c) => c.error_code == VarInt::from_u32(PROTOCOL_ERROR),
        _ => false,
    }
}

async fn connection(shared: &Arc<Shared>, conn: quinn::Connection) {
    loop {
        let (mut send, recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => {
                let code = if expected(&e) { NO_ERROR } else { INTERNAL_ERROR };
                shared.close(&conn, code);
                return;
            }
        };
        let permit = tokio::select! {
            p = shared.workers.clone().acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => return,
            },
            _ = conn.closed() => {
                let _ = send.finish();
                return;
            }
        };
        let (shared, conn) = (shared.clone(), conn.clone());
        tokio::spawn(async move {
            stream(&shared, &conn, send, recv).await;
            drop(permit);
        });
    }
}

enum ReadFail {
    /// The read timed out or the client reset the stream: abandon it.
    Transient,
    /// Anything else is a DoQ protocol error.
    Protocol,
}

/// `readDOQMessage`: the 2-byte length, then that many bytes.
async fn read_message(recv: &mut RecvStream) -> Result<Vec<u8>, ReadFail> {
    let map = |e: ReadExactError| match e {
        ReadExactError::ReadError(ReadError::Reset(_)) => ReadFail::Transient,
        _ => ReadFail::Protocol,
    };
    let mut len = [0u8; 2];
    recv.read_exact(&mut len).await.map_err(map)?;
    let n = u16::from_be_bytes(len) as usize;
    if n == 0 {
        // "message size is 0: probably unsupported DoQ version"
        return Err(ReadFail::Protocol);
    }
    let mut buf = vec![0u8; n];
    recv.read_exact(&mut buf).await.map_err(map)?;
    Ok(buf)
}

/// `validRequest`: RFC 9250 §4.3.3 protocol errors in the message itself.
fn valid_request(m: &Message) -> bool {
    if m.metadata.id != 0 {
        return false;
    }
    if let Some(e) = &m.edns
        && e.options()
            .as_ref()
            .iter()
            .any(|(code, _)| u16::from(*code) == EDNS_TCP_KEEPALIVE)
    {
        return false;
    }
    true
}

async fn stream(shared: &Shared, conn: &quinn::Connection, mut send: SendStream, mut recv: RecvStream) {
    let raw = match tokio::time::timeout(shared.read_timeout, read_message(&mut recv)).await {
        Ok(Ok(raw)) => raw,
        Err(_) | Ok(Err(ReadFail::Transient)) => {
            // only this stream: RESET_STREAM, no STOP_SENDING (§4.3.3)
            let _ = send.reset(VarInt::from_u32(INTERNAL_ERROR));
            shared.count(INTERNAL_ERROR);
            return;
        }
        Ok(Err(ReadFail::Protocol)) => {
            shared.close(conn, PROTOCOL_ERROR);
            return;
        }
    };
    let msg = match unpack_request(&raw) {
        Ok(m) if valid_request(&m) => m,
        _ => {
            shared.close(conn, PROTOCOL_ERROR);
            return;
        }
    };
    let wires = answer(
        &shared.d,
        msg,
        &raw,
        conn.remote_address(),
        shared.local,
        Protocol::Quic,
    )
    .await;
    // the writer closes the stream after the first message, so later ones
    // (a multi-message transfer) are not sent, as in CoreDNS
    if let Some(w) = wires.first() {
        let mut out = Vec::with_capacity(w.len() + 2);
        out.extend_from_slice(&(w.len() as u16).to_be_bytes());
        out.extend_from_slice(w);
        let _ = send.write_all(&out).await;
    }
    let _ = send.finish();
    // Observe the client's FIN if it is already here, so dropping the
    // receive side doesn't send STOP_SENDING.
    let mut probe = [0u8; 1];
    let _ = recv.read(&mut probe).now_or_never();
    shared.count(NO_ERROR);
}
