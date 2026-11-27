//! Outgoing dnstap connections (`dio`): a queue of encoded messages and a
//! task that writes them to a unix, TCP or TLS socket, reconnecting when
//! the connection breaks.

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, UnixStream};
use tokio::sync::{mpsc, watch};

use super::framestream::Encoder;

/// Messages per queue multiple (`queueSize`).
pub const QUEUE_SIZE: usize = 10000;
/// TCP send buffer per write buffer multiple (`tcpWriteBufSize`).
pub const TCP_WRITE_BUF_SIZE: usize = 1024 * 1024;
pub const TCP_TIMEOUT: Duration = Duration::from_secs(4);
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(1);
pub const ERROR_CHECK_INTERVAL: Duration = Duration::from_secs(10);

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub type Conn = Encoder<Box<dyn Io>>;

/// Where warnings go (`WarnLogger`); tests count them.
pub type Logger = Arc<dyn Fn(String) + Send + Sync>;

pub fn default_logger() -> Logger {
    Arc::new(|m| kerndns_core::warning!(plugin = "dnstap", "{m}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Unix,
    Tcp,
    Tls,
}

impl Proto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Proto::Unix => "unix",
            Proto::Tcp => "tcp",
            Proto::Tls => "tls",
        }
    }
}

/// Connection settings, also used by tests to shorten the timers.
#[derive(Clone)]
pub struct Settings {
    pub proto: Proto,
    pub endpoint: String,
    pub skip_verify: bool,
    pub tcp_write_buf_size: usize,
    pub tcp_timeout: Duration,
    pub flush_timeout: Duration,
    pub error_check_interval: Duration,
    pub logger: Logger,
}

impl Settings {
    pub fn new(proto: Proto, endpoint: &str, multiple_tcp_write_buf: usize) -> Self {
        Self {
            proto,
            endpoint: endpoint.to_string(),
            skip_verify: false,
            tcp_write_buf_size: multiple_tcp_write_buf * TCP_WRITE_BUF_SIZE,
            tcp_timeout: TCP_TIMEOUT,
            flush_timeout: FLUSH_TIMEOUT,
            error_check_interval: ERROR_CHECK_INTERVAL,
            logger: default_logger(),
        }
    }

    /// Open a connection and do the Frame Streams handshake.
    pub async fn dial(&self) -> io::Result<Conn> {
        let t = self.tcp_timeout;
        let timed = |e: tokio::time::error::Elapsed| {
            let _ = e;
            io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
        };
        let io: Box<dyn Io> = match self.proto {
            Proto::Unix => Box::new(
                tokio::time::timeout(t, UnixStream::connect(&self.endpoint))
                    .await
                    .map_err(timed)??,
            ),
            Proto::Tcp | Proto::Tls => {
                let tcp = tokio::time::timeout(t, self.connect_tcp()).await.map_err(timed)??;
                if self.proto == Proto::Tcp {
                    Box::new(tcp)
                } else {
                    let config = if self.skip_verify {
                        crate::tlsconfig::insecure_client_config()
                    } else {
                        crate::tlsconfig::client_config(&[]).map_err(io::Error::other)?
                    };
                    let host = host_of(&self.endpoint);
                    let name = ServerName::try_from(host.to_string()).map_err(io::Error::other)?;
                    let c = tokio_rustls::TlsConnector::from(config);
                    Box::new(tokio::time::timeout(t, c.connect(name, tcp)).await.map_err(timed)??)
                }
            }
        };
        Encoder::new(io, t).await
    }

    async fn connect_tcp(&self) -> io::Result<tokio::net::TcpStream> {
        let mut last = io::Error::new(io::ErrorKind::NotFound, format!("no address for {}", self.endpoint));
        for addr in tokio::net::lookup_host(&self.endpoint).await? {
            let sock = if addr.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            let _ = sock.set_send_buffer_size(self.tcp_write_buf_size.min(u32::MAX as usize) as u32);
            let _ = sock.set_nodelay(false);
            match sock.connect(addr).await {
                Ok(s) => return Ok(s),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

/// The host of `host:port` (brackets removed).
fn host_of(endpoint: &str) -> &str {
    let h = match endpoint.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => h,
        _ => endpoint,
    };
    h.trim_start_matches('[').trim_end_matches(']')
}

/// An outgoing dnstap connection with its queue.
pub struct Dio {
    pub settings: Settings,
    tx: mpsc::Sender<Bytes>,
    rx: Mutex<Option<mpsc::Receiver<Bytes>>>,
    dropped: Arc<AtomicU32>,
    quit: watch::Sender<bool>,
}

impl Dio {
    /// `newIO`: a queue of `multiple_queue` × 10000 messages.
    pub fn new(settings: Settings, multiple_queue: usize) -> Self {
        Self::with_queue(settings, multiple_queue * QUEUE_SIZE)
    }

    pub fn with_queue(settings: Settings, size: usize) -> Self {
        let (tx, rx) = mpsc::channel(size.max(1));
        Self {
            settings,
            tx,
            rx: Mutex::new(Some(rx)),
            dropped: Arc::new(AtomicU32::new(0)),
            quit: watch::channel(false).0,
        }
    }

    /// Enqueue an encoded `Dnstap` message, or count it as dropped when
    /// the queue is full.
    pub fn dnstap(&self, payload: Bytes) {
        if self.tx.try_send(payload).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Messages waiting in the queue.
    pub fn queued(&self) -> usize {
        self.tx.max_capacity() - self.tx.capacity()
    }

    /// Start the writer task (`connect` + `serve`). The first connection
    /// attempt failing is logged as an error; the task retries.
    pub fn connect(&self) {
        let Some(rx) = self.rx.lock().unwrap().take() else {
            return;
        };
        let s = self.settings.clone();
        let dropped = self.dropped.clone();
        let quit = self.quit.subscribe();
        tokio::spawn(serve(s, rx, dropped, quit));
    }

    /// Stop the writer task: flush and close the connection.
    pub fn close(&self) {
        let _ = self.quit.send(true);
    }
}

async fn close_conn(c: Option<Conn>) {
    if let Some(mut c) = c {
        let _ = c.flush().await;
        let _ = c.close().await;
    }
}

/// `dial`: close the previous connection first, so a reconnect doesn't
/// leak it.
async fn redial(s: &Settings, enc: &mut Option<Conn>) -> io::Result<()> {
    close_conn(enc.take()).await;
    *enc = Some(s.dial().await?);
    Ok(())
}

async fn serve(s: Settings, mut rx: mpsc::Receiver<Bytes>, dropped: Arc<AtomicU32>, mut quit: watch::Receiver<bool>) {
    let mut enc: Option<Conn> = None;
    if let Err(e) = redial(&s, &mut enc).await {
        kerndns_core::error!(plugin = "dnstap", "No connection to dnstap endpoint: {e}");
    }
    let start = tokio::time::Instant::now();
    let mut flush = tokio::time::interval_at(start + s.flush_timeout, s.flush_timeout);
    let mut check = tokio::time::interval_at(start + s.error_check_interval, s.error_check_interval);
    loop {
        tokio::select! {
            _ = quit.changed() => {
                close_conn(enc.take()).await;
                return;
            }
            p = rx.recv() => {
                let Some(p) = p else {
                    close_conn(enc.take()).await;
                    return;
                };
                match enc.as_mut() {
                    // errNoOutput: dropped, wait for the error check to redial
                    None => {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Some(c) => {
                        if c.write_frame(&p).await.is_err() {
                            dropped.fetch_add(1, Ordering::Relaxed);
                            let _ = redial(&s, &mut enc).await;
                        }
                    }
                }
            }
            _ = flush.tick() => {
                if let Some(c) = enc.as_mut()
                    && c.flush().await.is_err()
                {
                    // the buffered messages are lost; reconnect
                    let _ = redial(&s, &mut enc).await;
                }
            }
            _ = check.tick() => {
                let n = dropped.swap(0, Ordering::Relaxed);
                if n > 0 {
                    (s.logger)(format!("Dropped dnstap messages: {n}\n"));
                }
                if enc.is_none() {
                    let _ = redial(&s, &mut enc).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnstap::framestream::read_stream;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::{TcpListener, UnixListener};

    fn fast(s: &mut Settings) {
        s.tcp_timeout = Duration::from_millis(500);
        s.flush_timeout = Duration::from_millis(30);
        s.error_check_interval = Duration::from_millis(50);
    }

    /// `accept`: take one connection and read `count` frames.
    async fn accept_tcp(l: &TcpListener, count: usize) {
        let (s, _) = l.accept().await.unwrap();
        read_n(s, count).await;
    }

    async fn read_n<S: AsyncRead + AsyncWrite + Unpin>(s: S, count: usize) {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let fut = read_stream(s, move |_| {
            n2.fetch_add(1, Ordering::Relaxed);
        });
        let wait = async {
            while n.load(Ordering::Relaxed) < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::select! {
            _ = fut => {}
            _ = wait => {}
        }
        assert!(n.load(Ordering::Relaxed) >= count);
    }

    fn frame() -> Bytes {
        Bytes::from_static(&[0x78, 0x01])
    }

    // TestTransport
    #[tokio::test]
    async fn transport() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut s = Settings::new(Proto::Tcp, &l.local_addr().unwrap().to_string(), 1);
        fast(&mut s);
        let d = Dio::new(s, 1);
        d.connect();
        d.dnstap(frame());
        accept_tcp(&l, 1).await;
        d.close();

        let path = std::env::temp_dir().join(format!("kerndns-dnstap-io-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let l = UnixListener::bind(&path).unwrap();
        let mut s = Settings::new(Proto::Unix, path.to_str().unwrap(), 1);
        fast(&mut s);
        let d = Dio::new(s, 1);
        d.connect();
        d.dnstap(frame());
        let (c, _) = l.accept().await.unwrap();
        read_n(c, 1).await;
        d.close();
        let _ = std::fs::remove_file(&path);
    }

    // TestRace
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn race() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut s = Settings::new(Proto::Tcp, &l.local_addr().unwrap().to_string(), 1);
        fast(&mut s);
        let d = Arc::new(Dio::new(s, 1));
        d.connect();
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let d = d.clone();
            tasks.push(tokio::spawn(async move { d.dnstap(frame()) }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        accept_tcp(&l, 10).await;
        d.close();
    }

    /// `require.Eventually(len(dio.queue) == 0)`
    async fn eventually_empty(d: &Dio) {
        for _ in 0..100 {
            if d.queued() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("queue should be drained by the writer task");
    }

    fn counting_logger() -> (Logger, Arc<Mutex<Vec<String>>>) {
        let log: Arc<Mutex<Vec<String>>> = Default::default();
        let l = log.clone();
        (Arc::new(move |m| l.lock().unwrap().push(m)), log)
    }

    // TestReconnect/ConnectedOnStart
    #[tokio::test]
    async fn reconnect_connected_on_start() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (logger, log) = counting_logger();
        let mut s = Settings::new(Proto::Tcp, &addr.to_string(), 1);
        fast(&mut s);
        s.logger = logger;
        let d = Dio::new(s, 1);
        d.connect();
        d.dnstap(frame());
        accept_tcp(&l, 1).await;
        // the sink goes away and comes back on the same port
        drop(l);
        let l = TcpListener::bind(addr).await.unwrap();
        let reader = tokio::spawn(async move { accept_tcp(&l, 1).await });
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            d.dnstap(frame());
        }
        tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        eventually_empty(&d).await;
        assert!(log.lock().unwrap().len() < 5);
        d.close();
    }

    // TestReconnect/NotConnectedOnStart
    #[tokio::test]
    async fn reconnect_not_connected_on_start() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let (logger, log) = counting_logger();
        let mut s = Settings::new(Proto::Tcp, &addr.to_string(), 1);
        fast(&mut s);
        s.logger = logger;
        let d = Dio::new(s, 1);
        d.connect();
        d.dnstap(frame());
        let l = TcpListener::bind(addr).await.unwrap();
        let reader = tokio::spawn(async move { accept_tcp(&l, 5).await });
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            d.dnstap(frame());
        }
        tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .unwrap()
            .unwrap();
        eventually_empty(&d).await;
        assert!(log.lock().unwrap().len() < 5);
        d.close();
    }

    // TestFullQueueWriteFail
    #[tokio::test]
    async fn full_queue_drops_are_logged() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (logger, log) = counting_logger();
        let mut s = Settings::new(Proto::Tcp, &l.local_addr().unwrap().to_string(), 1);
        fast(&mut s);
        s.flush_timeout = Duration::from_millis(500);
        s.logger = logger;
        let d = Dio::with_queue(s, 1);
        for _ in 0..100 {
            d.dnstap(frame());
        }
        d.connect();
        accept_tcp(&l, 1).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let log = log.lock().unwrap();
        assert!(!log.is_empty());
        assert!(log[0].contains("Dropped dnstap messages"), "{log:?}");
        d.close();
    }

    // TestReconnectClosesPreviousConnection
    #[tokio::test]
    async fn reconnect_closes_previous_connection() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let s = Settings::new(Proto::Tcp, &l.local_addr().unwrap().to_string(), 1);
        let (first_closed_tx, first_closed) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (c1, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                // returns once the client sends STOP and we answer FINISH
                let _ = read_stream(c1, |_| {}).await;
                let _ = first_closed_tx.send(());
            });
            let (c2, _) = l.accept().await.unwrap();
            let _ = read_stream(c2, |_| {}).await;
        });
        let mut enc = None;
        redial(&s, &mut enc).await.unwrap();
        redial(&s, &mut enc).await.unwrap();
        assert!(enc.is_some());
        tokio::time::timeout(Duration::from_secs(2), first_closed)
            .await
            .expect("previous connection was not closed on reconnect")
            .unwrap();
    }

    #[test]
    fn hosts() {
        assert_eq!(host_of("example.com:6000"), "example.com");
        assert_eq!(host_of("[::1]:6000"), "::1");
        assert_eq!(host_of("127.0.0.1:6000"), "127.0.0.1");
    }
}
