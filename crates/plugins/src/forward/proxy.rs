//! One upstream: its connection pool, query exchange and health checking,
//! ported from CoreDNS's `plugin/pkg/proxy` and `plugin/pkg/up`.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query};
use kerndns_core::proto::rr::{Name, RecordType};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Write deadline for a query (CoreDNS `maxTimeout`).
const MAX_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
        }
    }
}

/// How a query should be sent, like `proxy.Options`.
#[derive(Debug, Clone)]
pub struct Options {
    pub force_tcp: bool,
    pub prefer_udp: bool,
    pub hc_recursion_desired: bool,
    pub hc_domain: Name,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            force_tcp: false,
            prefer_udp: false,
            hc_recursion_desired: true,
            hc_domain: Name::root(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("i/o timeout")]
    Timeout,
    /// The request couldn't be encoded.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// A pooled connection was closed by the upstream before we used it.
    #[error("cached connection was closed by peer")]
    CachedClosed,
    #[error("bad response: {0}")]
    BadResponse(String),
}

enum Stream {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Stream {
    fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            Stream::Tcp(t) => t.local_addr().ok(),
            Stream::Tls(t) => t.get_ref().0.local_addr().ok(),
        }
    }
}

struct Pooled<T> {
    conn: T,
    created: Instant,
    used: Instant,
}

/// Idle connections, reused for `expire` (and at most `max_age` old).
#[derive(Default)]
struct Pool {
    udp: Vec<Pooled<UdpSocket>>,
    stream: Vec<Pooled<Stream>>,
}

pub struct TlsSettings {
    pub config: Arc<ClientConfig>,
    pub server_name: ServerName<'static>,
}

/// One upstream server.
pub struct Proxy {
    pub addr: SocketAddr,
    tls: Option<TlsSettings>,
    fails: AtomicU32,
    pool: Mutex<Pool>,
    pub expire: Duration,
    pub max_age: Duration,
    pub read_timeout: Duration,
    pub source: Option<IpAddr>,
    // health checking
    hc_interval: Mutex<Duration>,
    probing: AtomicBool,
    stopped: AtomicBool,
    opts: Mutex<Options>,
}

impl Proxy {
    pub fn new(addr: SocketAddr, tls: Option<TlsSettings>) -> Self {
        Self {
            addr,
            tls,
            fails: AtomicU32::new(0),
            pool: Mutex::new(Pool::default()),
            expire: Duration::from_secs(10),
            max_age: Duration::ZERO,
            read_timeout: Duration::from_secs(2),
            source: None,
            hc_interval: Mutex::new(Duration::from_millis(500)),
            probing: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            opts: Mutex::new(Options::default()),
        }
    }

    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// `tls://1.2.3.4:853` or `1.2.3.4:53`.
    pub fn display_addr(&self) -> String {
        if self.tls.is_some() {
            format!("tls://{}", self.addr)
        } else {
            self.addr.to_string()
        }
    }

    pub fn set_health_options(&self, interval: Duration, opts: Options) {
        *self.hc_interval.lock().unwrap() = interval;
        *self.opts.lock().unwrap() = opts;
    }

    pub fn fails(&self) -> u32 {
        self.fails.load(Ordering::Relaxed)
    }

    /// Considered down after more than `max_fails` failed health checks.
    pub fn down(&self, max_fails: u32) -> bool {
        max_fails != 0 && self.fails() > max_fails
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        let mut p = self.pool.lock().unwrap();
        p.udp.clear();
        p.stream.clear();
    }

    /// Start probing until the upstream answers, unless already probing,
    /// like `Proxy.Healthcheck` / `up.Probe.Do`.
    pub fn healthcheck(self: &Arc<Self>) {
        if self.probing.swap(true, Ordering::AcqRel) {
            return;
        }
        let p = self.clone();
        tokio::spawn(async move {
            loop {
                if p.stopped.load(Ordering::Relaxed) {
                    break;
                }
                if p.check().await.is_ok() {
                    break;
                }
                let interval = *p.hc_interval.lock().unwrap();
                tokio::time::sleep(interval).await;
            }
            p.probing.store(false, Ordering::Release);
        });
    }

    /// One health check: `<domain> NS` over a fresh connection.
    async fn check(&self) -> Result<(), ExchangeError> {
        let opts = self.opts.lock().unwrap().clone();
        let mut ping = Message::new(rand_id(), MessageType::Query, OpCode::Query);
        ping.metadata.recursion_desired = opts.hc_recursion_desired;
        ping.add_query(Query::query(opts.hc_domain.clone(), RecordType::NS));
        let wire = ping
            .to_vec()
            .map_err(|e| ExchangeError::InvalidRequest(e.to_string()))?;
        let proto = if opts.force_tcp || self.tls.is_some() {
            Proto::Tcp
        } else {
            Proto::Udp
        };
        let res = tokio::time::timeout(
            Duration::from_secs(1),
            self.exchange_fresh(proto, &wire, ping.metadata.id),
        )
        .await;
        match res {
            Ok(Ok(_)) => {
                self.fails.store(0, Ordering::Relaxed);
                Ok(())
            }
            Ok(Err(e)) => {
                crate::pluginmetrics::PROXY_HC_FAILURES
                    .with_label_values(&["forward", &self.display_addr()])
                    .inc();
                self.fails.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
            Err(_) => {
                crate::pluginmetrics::PROXY_HC_FAILURES
                    .with_label_values(&["forward", &self.display_addr()])
                    .inc();
                self.fails.fetch_add(1, Ordering::Relaxed);
                Err(ExchangeError::Timeout)
            }
        }
    }

    async fn exchange_fresh(&self, proto: Proto, wire: &[u8], id: u16) -> Result<Message, ExchangeError> {
        match proto {
            Proto::Udp => {
                let sock = self.dial_udp().await?;
                udp_exchange(&sock, wire, id, self.read_timeout, MIN_UDP_SIZE).await
            }
            Proto::Tcp => {
                let mut s = self.dial_stream().await?;
                stream_exchange(&mut s, wire, id, self.read_timeout).await
            }
        }
    }

    async fn dial_udp(&self) -> io::Result<UdpSocket> {
        let bind: SocketAddr = match (self.source, self.addr) {
            (Some(ip), _) => SocketAddr::new(ip, 0),
            (None, SocketAddr::V4(_)) => "0.0.0.0:0".parse().unwrap(),
            (None, SocketAddr::V6(_)) => "[::]:0".parse().unwrap(),
        };
        let s = UdpSocket::bind(bind).await?;
        s.connect(self.addr).await?;
        Ok(s)
    }

    async fn dial_stream(&self) -> Result<Stream, ExchangeError> {
        let sock = if self.addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Some(ip) = self.source {
            sock.bind(SocketAddr::new(ip, 0))?;
        }
        let tcp = tokio::time::timeout(MAX_TIMEOUT, sock.connect(self.addr))
            .await
            .map_err(|_| ExchangeError::Timeout)??;
        let _ = tcp.set_nodelay(true);
        match &self.tls {
            None => Ok(Stream::Tcp(tcp)),
            Some(t) => {
                let connector = TlsConnector::from(t.config.clone());
                let tls = tokio::time::timeout(MAX_TIMEOUT, connector.connect(t.server_name.clone(), tcp))
                    .await
                    .map_err(|_| ExchangeError::Timeout)??;
                Ok(Stream::Tls(Box::new(tls)))
            }
        }
    }

    fn take_udp(&self) -> Option<UdpSocket> {
        let mut p = self.pool.lock().unwrap();
        let now = Instant::now();
        while let Some(c) = p.udp.pop() {
            if self.fresh(&c, now) {
                return Some(c.conn);
            }
        }
        None
    }

    fn take_stream(&self) -> Option<(Stream, Instant)> {
        let mut p = self.pool.lock().unwrap();
        let now = Instant::now();
        while let Some(c) = p.stream.pop() {
            if self.fresh(&c, now) {
                return Some((c.conn, c.created));
            }
        }
        None
    }

    fn fresh<T>(&self, c: &Pooled<T>, now: Instant) -> bool {
        now.duration_since(c.used) < self.expire
            && (self.max_age.is_zero() || now.duration_since(c.created) < self.max_age)
    }

    /// Send `req` (whose id is replaced for the upstream and restored in
    /// the answer) over `proto`, reusing pooled connections, like
    /// `Proxy.Connect` + `lookupDNS`. Returns the answer and the protocol
    /// used; `local` gets our address on the upstream socket (for dnstap)
    /// once there is one.
    pub async fn connect(
        &self,
        req: &Message,
        proto: Proto,
        local: &mut Option<SocketAddr>,
    ) -> Result<(Message, Proto), ExchangeError> {
        let start = Instant::now();
        let origin_id = req.metadata.id;
        let id = rand_id();
        let mut m = req.clone();
        m.metadata.id = id;
        let wire = kerndns_core::wire::to_wire(&m).map_err(|e| ExchangeError::InvalidRequest(e.to_string()))?;

        // DoT always uses the stream transport
        let proto = if self.tls.is_some() { Proto::Tcp } else { proto };
        let mut ret = match proto {
            Proto::Udp => {
                let (sock, cached) = match self.take_udp() {
                    Some(s) => (s, true),
                    None => (self.dial_udp().await?, false),
                };
                let _ = cached;
                *local = sock.local_addr().ok();
                let created = Instant::now();
                // like `pc.c.UDPSize = max(state.Size(), 512)`: the upstream
                // answers within the client's EDNS size
                let size = req
                    .edns
                    .as_ref()
                    .map_or(0, |e| e.max_payload() as usize)
                    .max(MIN_UDP_SIZE);
                let r = udp_exchange(&sock, &wire, id, self.read_timeout, size).await?;
                self.pool.lock().unwrap().udp.push(Pooled {
                    conn: sock,
                    created,
                    used: Instant::now(),
                });
                r
            }
            Proto::Tcp => {
                let (mut s, created, cached) = match self.take_stream() {
                    Some((s, created)) => (s, created, true),
                    None => (self.dial_stream().await?, Instant::now(), false),
                };
                *local = s.local_addr();
                match stream_exchange(&mut s, &wire, id, self.read_timeout).await {
                    Ok(r) => {
                        self.pool.lock().unwrap().stream.push(Pooled {
                            conn: s,
                            created,
                            used: Instant::now(),
                        });
                        r
                    }
                    Err(ExchangeError::Io(e)) if cached && is_closed(&e) => return Err(ExchangeError::CachedClosed),
                    Err(e) => return Err(e),
                }
            }
        };
        ret.metadata.id = origin_id;
        crate::pluginmetrics::PROXY_REQUEST_DURATION
            .with_label_values(&[
                "forward",
                &self.display_addr(),
                &kerndns_core::metrics::rcode_string(ret.metadata.response_code),
            ])
            .observe(start.elapsed().as_secs_f64());
        Ok((ret, proto))
    }
}

fn is_closed(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}

/// Smallest UDP read buffer (`dns.MinMsgSize`).
const MIN_UDP_SIZE: usize = 512;

async fn udp_exchange(
    sock: &UdpSocket,
    wire: &[u8],
    id: u16,
    read_timeout: Duration,
    size: usize,
) -> Result<Message, ExchangeError> {
    tokio::time::timeout(MAX_TIMEOUT, sock.send(wire))
        .await
        .map_err(|_| ExchangeError::Timeout)??;
    let deadline = tokio::time::Instant::now() + read_timeout;
    let mut buf = vec![0u8; size];
    loop {
        let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
            .await
            .map_err(|_| ExchangeError::Timeout)??;
        // ignore short reads and answers to other (earlier, timed-out) queries
        let Ok(m) = Message::from_vec(&buf[..n]) else { continue };
        if m.metadata.id == id {
            return Ok(m);
        }
    }
}

async fn stream_exchange(
    s: &mut Stream,
    wire: &[u8],
    id: u16,
    read_timeout: Duration,
) -> Result<Message, ExchangeError> {
    match s {
        Stream::Tcp(t) => framed_exchange(t, wire, id, read_timeout).await,
        Stream::Tls(t) => framed_exchange(t.as_mut(), wire, id, read_timeout).await,
    }
}

async fn framed_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    wire: &[u8],
    id: u16,
    read_timeout: Duration,
) -> Result<Message, ExchangeError> {
    let mut out = Vec::with_capacity(wire.len() + 2);
    out.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    out.extend_from_slice(wire);
    tokio::time::timeout(MAX_TIMEOUT, async {
        s.write_all(&out).await?;
        s.flush().await
    })
    .await
    .map_err(|_| ExchangeError::Timeout)??;
    let deadline = tokio::time::Instant::now() + read_timeout;
    loop {
        let mut len = [0u8; 2];
        tokio::time::timeout_at(deadline, s.read_exact(&mut len))
            .await
            .map_err(|_| ExchangeError::Timeout)??;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        tokio::time::timeout_at(deadline, s.read_exact(&mut buf))
            .await
            .map_err(|_| ExchangeError::Timeout)??;
        let m = Message::from_vec(&buf).map_err(|e| ExchangeError::BadResponse(e.to_string()))?;
        if m.metadata.id == id {
            return Ok(m);
        }
    }
}

/// A random 16-bit message id.
pub fn rand_id() -> u16 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = Cell::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9e3779b97f4a7c15)
                ^ (std::process::id() as u64) << 32
                | 1,
        );
    }
    STATE.with(|s| {
        // xorshift64*
        let mut x = s.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s.set(x);
        (x.wrapping_mul(0x2545F4914F6CDD1D) >> 48) as u16
    })
}

/// A random index below `n`.
pub fn rand_below(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let v = ((rand_id() as u64) << 16) | rand_id() as u64;
    (v % n as u64) as usize
}
