//! DNS over QUIC upstreams (RFC 9250), like CoreDNS's
//! `plugin/pkg/proxy/doq.go`: one QUIC connection per upstream, reused for
//! `expire` and at most `max_age`, one bidirectional stream per query.
//!
//! - ALPN `doq`, a 5s handshake timeout, an idle timeout of
//!   max(30s, `expire`, `read_timeout`), no streams from the server.
//! - The query goes out with ID 0 and without the edns-tcp-keepalive
//!   option; the answer must have ID 0 and be the stream's only message,
//!   otherwise the connection is closed with DOQ_PROTOCOL_ERROR.
//! - A query that times out cancels its stream with DOQ_REQUEST_CANCELLED.
//! - AXFR and IXFR are refused (NOTIMP): one stream carries one answer.
//! - Only one connection is dialed at a time; concurrent queries wait for
//!   it. A query waits for a connection at most its read timeout; the
//!   handshake goes on in the background, so a dead upstream costs a
//!   query its read timeout and the next upstream is tried within the
//!   5s forwarding budget.
//!
//! An expired connection is replaced when the next query comes (CoreDNS
//! also sweeps every 10s); queries still running on it finish first.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kerndns_core::proto::op::Message;
use kerndns_core::proto::rr::RecordType;
use kerndns_core::proto::rr::rdata::opt::EdnsCode;
use quinn::VarInt;
use rustls::ClientConfig;

use super::proxy::ExchangeError;

const ALPN: &[u8] = b"doq";
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const NO_ERROR: u32 = 0x0;
const PROTOCOL_ERROR: u32 = 0x2;
const REQUEST_CANCELLED: u32 = 0x3;

struct Conn {
    conn: quinn::Connection,
    /// The connection's own UDP socket, like CoreDNS's per-connection
    /// `quic.Transport`.
    endpoint: quinn::Endpoint,
    created: Instant,
    /// Last use and running queries, under the transport's lock.
    state: Mutex<(Instant, usize)>,
}

impl Conn {
    fn close(&self, code: u32, reason: &str) {
        self.conn.close(VarInt::from_u32(code), reason.as_bytes());
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.conn.close(VarInt::from_u32(NO_ERROR), b"");
        self.endpoint.close(VarInt::from_u32(NO_ERROR), b"");
    }
}

/// Releases a connection when a query is done with it.
struct Lease(Arc<Conn>);

impl Drop for Lease {
    fn drop(&mut self) {
        let mut s = self.0.state.lock().unwrap();
        s.0 = Instant::now();
        s.1 = s.1.saturating_sub(1);
    }
}

pub struct DoqTransport {
    addr: SocketAddr,
    server_name: String,
    config: quinn::ClientConfig,
    source: Option<IpAddr>,
    pub expire: Duration,
    pub max_age: Duration,
    current: Arc<Mutex<Option<Arc<Conn>>>>,
    /// Held while dialing, so there is one dial at a time.
    dialing: Arc<tokio::sync::Mutex<()>>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
}

impl DoqTransport {
    pub fn new(
        addr: SocketAddr,
        tls: &ClientConfig,
        server_name: String,
        source: Option<IpAddr>,
        expire: Duration,
        max_age: Duration,
        read_timeout: Duration,
    ) -> Result<Self, String> {
        let mut tls = tls.clone();
        // DoQ uses its own ALPN and nothing else
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|e| format!("QUIC TLS: {e}"))?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        let idle = DEFAULT_IDLE_TIMEOUT.max(expire).max(read_timeout);
        transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(idle).map_err(|e| e.to_string())?));
        transport.max_concurrent_bidi_streams(VarInt::from_u32(0));
        transport.max_concurrent_uni_streams(VarInt::from_u32(0));
        config.transport_config(Arc::new(transport));
        Ok(Self {
            addr,
            server_name,
            config,
            source,
            expire,
            max_age,
            current: Arc::new(Mutex::new(None)),
            dialing: Arc::new(tokio::sync::Mutex::new(())),
            stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Close the connection; no new ones are dialed.
    pub fn stop(&self) {
        self.stopped.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(c) = self.current.lock().unwrap().take() {
            c.close(NO_ERROR, "");
        }
    }

    /// The current connection if it can still be used, else drop it
    /// (`cleanup`): it closes once its running queries are done.
    fn current(&self, now: Instant) -> Option<Arc<Conn>> {
        let mut cur = self.current.lock().unwrap();
        let c = cur.as_ref()?;
        let usable = {
            let s = c.state.lock().unwrap();
            let dead = c.conn.close_reason().is_some();
            let expired = s.1 == 0 && (self.expire.is_zero() || now.duration_since(s.0) >= self.expire);
            let too_old = !self.max_age.is_zero() && now.duration_since(c.created) >= self.max_age;
            !(dead || expired || too_old)
        };
        if !usable {
            *cur = None;
            return None;
        }
        let c = c.clone();
        c.state.lock().unwrap().1 += 1;
        Some(c)
    }

    /// Drop `c` as the current connection.
    fn retire(&self, c: &Arc<Conn>) {
        let mut cur = self.current.lock().unwrap();
        if cur.as_ref().is_some_and(|x| Arc::ptr_eq(x, c)) {
            *cur = None;
        }
    }

    fn label(&self) -> String {
        self.addr.to_string()
    }

    /// A connection for one query and whether it was reused.
    ///
    /// A new connection is dialed in a task of its own: a query that gives
    /// up waiting (its timeout) doesn't abort the handshake, which goes on
    /// for up to 5s and leaves the connection for the next queries.
    async fn acquire(&self) -> Result<(Lease, bool), ExchangeError> {
        let stopped = || ExchangeError::Io(std::io::Error::other("proxy: transport stopped"));
        loop {
            if self.stopped.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(stopped());
            }
            if let Some(c) = self.current(Instant::now()) {
                cache_metric(true, &self.label());
                return Ok((Lease(c), true));
            }
            let lock = self.dialing.clone().lock_owned().await;
            // someone else may have dialed while we waited
            if self.current.lock().unwrap().is_some() {
                continue;
            }
            cache_metric(false, &self.label());
            let dial = dial(self.addr, self.server_name.clone(), self.config.clone(), self.source);
            let current = self.current.clone();
            let stop = self.stopped.clone();
            let task = tokio::spawn(async move {
                let _lock = lock;
                let c = Arc::new(dial.await?);
                if !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    *current.lock().unwrap() = Some(c.clone());
                }
                Ok::<_, ExchangeError>(c)
            });
            let c = task
                .await
                .map_err(|e| ExchangeError::Quic(format!("DoQ dial: {e}")))??;
            if self.stopped.load(std::sync::atomic::Ordering::Relaxed) {
                c.close(NO_ERROR, "");
                return Err(stopped());
            }
            c.state.lock().unwrap().1 += 1;
            return Ok((Lease(c), false));
        }
    }
}

/// A new QUIC connection on its own UDP socket, within the 5s handshake
/// timeout.
async fn dial(
    addr: SocketAddr,
    server_name: String,
    config: quinn::ClientConfig,
    source: Option<IpAddr>,
) -> Result<Conn, ExchangeError> {
    {
        let bind = match (source, addr) {
            (Some(ip), _) => SocketAddr::new(ip, 0),
            (None, SocketAddr::V4(_)) => SocketAddr::from(([0, 0, 0, 0], 0)),
            (None, SocketAddr::V6(_)) => SocketAddr::from(([0u16; 8], 0)),
        };
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(config);
        let connecting = endpoint
            .connect(addr, &server_name)
            .map_err(|e| ExchangeError::Quic(e.to_string()))?;
        let conn = match tokio::time::timeout(DIAL_TIMEOUT, connecting).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                endpoint.close(VarInt::from_u32(NO_ERROR), b"");
                return Err(ExchangeError::Quic(e.to_string()));
            }
            Err(_) => {
                endpoint.close(VarInt::from_u32(NO_ERROR), b"");
                return Err(ExchangeError::Timeout);
            }
        };
        let now = Instant::now();
        Ok(Conn {
            conn,
            endpoint,
            created: now,
            state: Mutex::new((now, 0)),
        })
    }
}

impl DoqTransport {
    /// Send `msg` and wait up to `timeout` for a connection and the answer,
    /// like `doqTransport.exchange`. Also returns our address on the
    /// connection.
    pub async fn exchange(
        &self,
        msg: &Message,
        timeout: Duration,
    ) -> Result<(Message, Option<SocketAddr>), ExchangeError> {
        if msg.queries.len() == 1 && matches!(msg.queries[0].query_type(), RecordType::AXFR | RecordType::IXFR) {
            return Err(ExchangeError::Unsupported(
                "proxy: unsupported request: zone transfers over DoQ require multi-message response support".into(),
            ));
        }
        let mut query = msg.clone();
        query.metadata.id = 0;
        if let Some(e) = query.edns.as_mut() {
            e.options_mut().remove(EdnsCode::Keepalive);
        }
        let wire = kerndns_core::wire::to_wire(&query).map_err(|e| ExchangeError::InvalidRequest(e.to_string()))?;
        if wire.len() > u16::MAX as usize {
            return Err(ExchangeError::InvalidRequest("DNS message is too large for DoQ".into()));
        }

        let deadline = tokio::time::Instant::now() + timeout;
        let (lease, cached) = tokio::time::timeout_at(deadline, self.acquire())
            .await
            .map_err(|_| ExchangeError::Timeout)??;
        let c = lease.0.clone();
        let local = c.endpoint.local_addr().ok();

        let (mut send, mut recv) = match tokio::time::timeout_at(deadline, c.conn.open_bi()).await {
            Err(_) => return Err(ExchangeError::Timeout),
            Ok(Err(e)) => {
                self.retire(&c);
                return Err(if cached {
                    ExchangeError::CachedClosed
                } else {
                    ExchangeError::Quic(e.to_string())
                });
            }
            Ok(Ok(s)) => s,
        };
        let cancel = |send: &mut quinn::SendStream, recv: &mut quinn::RecvStream| {
            let _ = recv.stop(VarInt::from_u32(REQUEST_CANCELLED));
            let _ = send.reset(VarInt::from_u32(REQUEST_CANCELLED));
        };
        let protocol_error = |reason: String| {
            self.retire(&c);
            c.close(PROTOCOL_ERROR, &reason);
            ExchangeError::BadResponse(format!("DNS-over-QUIC protocol error: {reason}"))
        };
        let conn_error = |e: String| {
            if c.conn.close_reason().is_some() {
                self.retire(&c);
            }
            ExchangeError::Quic(e)
        };

        let mut frame = Vec::with_capacity(wire.len() + 2);
        frame.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        frame.extend_from_slice(&wire);
        let written = tokio::time::timeout_at(deadline, async {
            send.write_all(&frame).await.map_err(|e| e.to_string())?;
            send.finish().map_err(|e| e.to_string())
        })
        .await;
        match written {
            Err(_) => {
                cancel(&mut send, &mut recv);
                return Err(ExchangeError::Timeout);
            }
            Ok(Err(e)) => {
                cancel(&mut send, &mut recv);
                return Err(conn_error(e));
            }
            Ok(Ok(())) => {}
        }

        let read = tokio::time::timeout_at(deadline, async {
            let mut len = [0u8; 2];
            match recv.read_exact(&mut len).await {
                Ok(()) => {}
                Err(quinn::ReadExactError::FinishedEarly(_)) => {
                    return Err(Ok("incomplete message length".to_string()));
                }
                Err(quinn::ReadExactError::ReadError(e)) => return Err(Err(e.to_string())),
            }
            let size = u16::from_be_bytes(len) as usize;
            if size == 0 {
                return Err(Ok("zero-length DNS message".to_string()));
            }
            let mut buf = vec![0u8; size];
            match recv.read_exact(&mut buf).await {
                Ok(()) => {}
                Err(quinn::ReadExactError::FinishedEarly(_)) => {
                    return Err(Ok(format!("message ended before {size} bytes")));
                }
                Err(quinn::ReadExactError::ReadError(e)) => return Err(Err(e.to_string())),
            }
            // the answer must be the stream's last data
            let mut extra = [0u8; 1];
            loop {
                match recv.read(&mut extra).await {
                    Ok(None) => break,
                    Ok(Some(0)) => continue,
                    Ok(Some(_)) => return Err(Ok("multiple responses on one query stream".to_string())),
                    Err(e) => return Err(Err(e.to_string())),
                }
            }
            Ok(buf)
        })
        .await;
        let buf = match read {
            Err(_) => {
                cancel(&mut send, &mut recv);
                return Err(ExchangeError::Timeout);
            }
            Ok(Err(Ok(reason))) => return Err(protocol_error(reason)),
            Ok(Err(Err(e))) => {
                let _ = recv.stop(VarInt::from_u32(REQUEST_CANCELLED));
                return Err(conn_error(e));
            }
            Ok(Ok(buf)) => buf,
        };
        let mut resp = match Message::from_vec(&buf) {
            Ok(m) => m,
            Err(e) => return Err(protocol_error(format!("invalid DNS response: {e}"))),
        };
        if resp.metadata.id != 0 {
            return Err(protocol_error(format!(
                "response message ID is {}, want 0",
                resp.metadata.id
            )));
        }
        resp.metadata.id = msg.metadata.id;
        drop(lease);
        Ok((resp, local))
    }
}

fn cache_metric(hit: bool, to: &str) {
    let m = if hit {
        &crate::pluginmetrics::PROXY_CONN_CACHE_HITS
    } else {
        &crate::pluginmetrics::PROXY_CONN_CACHE_MISSES
    };
    m.with_label_values(&["forward", to, "quic"]).inc();
}
