//! Incoming dnstap connections (`dnstap listen ...`): sinks connect to
//! KernDNS, which writes every message to each of them. There is no queue
//! to speak of: a sink that can't keep up (or whose connection fails) is
//! disconnected, and only it misses messages.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;

use super::framestream::Encoder;
use super::io::{Io, Logger, Proto, TCP_TIMEOUT, default_logger};

/// Messages a sink may fall behind before it is disconnected.
const CLIENT_BACKLOG: usize = 1024;

#[derive(Clone)]
pub struct ListenerSettings {
    pub proto: Proto,
    pub endpoint: String,
    pub skip_verify: bool,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ca_file: Option<String>,
    pub tcp_timeout: Duration,
    pub logger: Logger,
}

impl ListenerSettings {
    pub fn new(proto: Proto, endpoint: &str) -> Self {
        Self {
            proto,
            endpoint: endpoint.to_string(),
            skip_verify: false,
            cert_file: None,
            key_file: None,
            ca_file: None,
            tcp_timeout: TCP_TIMEOUT,
            logger: default_logger(),
        }
    }
}

type Clients = Arc<Mutex<HashMap<u64, mpsc::Sender<Bytes>>>>;

pub struct Listener {
    pub settings: ListenerSettings,
    clients: Clients,
    quit: watch::Sender<bool>,
    /// Listening (between `listen` and `close`).
    open: std::sync::atomic::AtomicBool,
}

enum Accepting {
    Tcp(TcpListener, Option<TlsAcceptor>),
    Unix(UnixListener),
}

impl Listener {
    pub fn new(settings: ListenerSettings) -> Self {
        Self {
            settings,
            clients: Default::default(),
            quit: watch::channel(false).0,
            open: Default::default(),
        }
    }

    /// The number of connected sinks.
    pub fn clients(&self) -> usize {
        self.clients.lock().unwrap().len()
    }

    /// Bind and start accepting sinks.
    pub fn listen(&self) -> io::Result<()> {
        let s = &self.settings;
        let acc = match s.proto {
            Proto::Tls => {
                let (Some(cert), Some(key)) = (&s.cert_file, &s.key_file) else {
                    (s.logger)("TLS listener requires cert and key files".into());
                    return Ok(());
                };
                use crate::tlsconfig::ClientAuth;
                let auth = match (&s.ca_file, s.skip_verify) {
                    (None, _) => ClientAuth::NoCert,
                    (Some(_), true) => ClientAuth::VerifyIfGiven,
                    (Some(_), false) => ClientAuth::RequireAndVerify,
                };
                let cfg =
                    crate::tlsconfig::server_config(cert, key, s.ca_file.as_deref(), auth).map_err(io::Error::other)?;
                Accepting::Tcp(tcp_listener(&s.endpoint)?, Some(TlsAcceptor::from(cfg)))
            }
            Proto::Tcp => Accepting::Tcp(tcp_listener(&s.endpoint)?, None),
            Proto::Unix => {
                let l = std::os::unix::net::UnixListener::bind(&s.endpoint)?;
                l.set_nonblocking(true)?;
                Accepting::Unix(UnixListener::from_std(l)?)
            }
        };
        let clients = self.clients.clone();
        // listening again after `close`: the old accept loop saw the change
        self.quit.send_replace(false);
        self.open.store(true, std::sync::atomic::Ordering::Relaxed);
        let quit = self.quit.subscribe();
        let timeout = s.tcp_timeout;
        let logger = s.logger.clone();
        tokio::spawn(accept_loop(acc, clients, quit, timeout, logger));
        Ok(())
    }

    /// Write an encoded `Dnstap` message to every sink. A sink that is
    /// gone or too slow is dropped.
    pub fn dnstap(&self, payload: Bytes) {
        let mut c = self.clients.lock().unwrap();
        if c.is_empty() {
            return;
        }
        c.retain(|_, tx| tx.try_send(payload.clone()).is_ok());
    }

    /// Stop accepting and disconnect every sink (unlinking a unix socket).
    pub fn close(&self) {
        // closed already: the socket file may be another listener's now
        if !self.open.swap(false, std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let _ = self.quit.send(true);
        self.clients.lock().unwrap().clear();
        if self.settings.proto == Proto::Unix {
            let _ = std::fs::remove_file(&self.settings.endpoint);
        }
    }
}

fn tcp_listener(endpoint: &str) -> io::Result<TcpListener> {
    use std::net::ToSocketAddrs;
    let addr = endpoint
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {endpoint}")))?;
    let s = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    // a reload binds the new listener while the old one's task is still
    // winding down
    s.set_reuseaddr(true)?;
    s.set_reuseport(true)?;
    s.bind(addr)?;
    s.listen(1024)
}

async fn accept_loop(
    acc: Accepting,
    clients: Clients,
    mut quit: watch::Receiver<bool>,
    timeout: Duration,
    logger: Logger,
) {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    loop {
        let accepted: io::Result<Box<dyn Io>> = tokio::select! {
            _ = quit.changed() => return,
            r = async {
                match &acc {
                    Accepting::Unix(l) => l.accept().await.map(|(s, _)| Box::new(s) as Box<dyn Io>),
                    Accepting::Tcp(l, tls) => {
                        let (s, _) = l.accept().await?;
                        let _ = s.set_nodelay(false);
                        match tls {
                            None => Ok(Box::new(s) as Box<dyn Io>),
                            Some(a) => tokio::time::timeout(timeout, a.accept(s))
                                .await
                                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timeout"))
                                .and_then(|r| r)
                                .map(|s| Box::new(s) as Box<dyn Io>),
                        }
                    }
                }
            } => r,
        };
        let conn = match accepted {
            Ok(c) => c,
            Err(e) => {
                if *quit.borrow() {
                    return;
                }
                logger(format!("Error accepting dnstap connection: {e}"));
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let clients = clients.clone();
        let logger = logger.clone();
        let mut quit = quit.clone();
        tokio::spawn(async move {
            let mut enc = match Encoder::new(conn, timeout).await {
                Ok(e) => e,
                Err(e) => {
                    logger(format!("Error creating encoder for dnstap client: {e}"));
                    return;
                }
            };
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let (tx, mut rx) = mpsc::channel::<Bytes>(CLIENT_BACKLOG);
            clients.lock().unwrap().insert(id, tx);
            loop {
                tokio::select! {
                    _ = quit.changed() => break,
                    m = rx.recv() => {
                        let Some(m) = m else { break };
                        if enc.write_frame(&m).await.is_err() || enc.flush().await.is_err() {
                            break;
                        }
                    }
                }
            }
            clients.lock().unwrap().remove(&id);
            let _ = enc.flush().await;
            let _ = enc.close().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnstap::framestream::read_stream;
    use tokio::net::{TcpStream, UnixStream};

    async fn wait_for(l: &Listener, n: usize) {
        for _ in 0..200 {
            if l.clients() == n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("expected {n} clients, have {}", l.clients());
    }

    // TestListenerCreation, TestListenerBroadcast (no clients)
    #[tokio::test]
    async fn creation_and_broadcast_without_clients() {
        let l = Listener::new(ListenerSettings::new(Proto::Tcp, "127.0.0.1:0"));
        assert_eq!(l.settings.proto, Proto::Tcp);
        assert!(!l.settings.skip_verify);
        assert_eq!(l.clients(), 0);
        l.dnstap(Bytes::from_static(b"x"));
    }

    // broadcast to two sinks; one disconnecting doesn't affect the other
    // (TestListenerRemoveClient, TestListenerDnstapFlushErrorNoDeadlock)
    #[tokio::test]
    async fn broadcast() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let l = Listener::new(ListenerSettings::new(Proto::Tcp, &addr.to_string()));
        l.listen().unwrap();
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let s1 = TcpStream::connect(addr).await.unwrap();
        let r1 = tokio::spawn(async move { read_stream(s1, move |f| tx1.send(f).unwrap()).await });
        let s2 = TcpStream::connect(addr).await.unwrap();
        let r2 = tokio::spawn(async move { read_stream(s2, |_| {}).await });
        wait_for(&l, 2).await;
        r2.abort();
        let _ = r2.await;
        l.dnstap(Bytes::from_static(b"one"));
        assert_eq!(rx1.recv().await.unwrap(), b"one");
        // the broken sink is gone after a failed write
        for _ in 0..3 {
            l.dnstap(Bytes::from_static(b"more"));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        wait_for(&l, 1).await;
        l.close();
        // TestListenerClose: closing sends STOP to the remaining sink
        r1.await.unwrap().unwrap();
        assert_eq!(l.clients(), 0);
    }

    #[tokio::test]
    async fn unix_socket_is_removed_on_close() {
        let path = std::env::temp_dir().join(format!("kerndns-dnstap-listen-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let l = Listener::new(ListenerSettings::new(Proto::Unix, path.to_str().unwrap()));
        l.listen().unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let s = UnixStream::connect(&path).await.unwrap();
        tokio::spawn(async move { read_stream(s, move |f| tx.send(f).unwrap()).await });
        wait_for(&l, 1).await;
        l.dnstap(Bytes::from_static(b"frame"));
        assert_eq!(rx.recv().await.unwrap(), b"frame");
        l.close();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn tls_without_cert_is_not_started() {
        let (logger, log) = {
            let log: Arc<Mutex<Vec<String>>> = Default::default();
            let l2 = log.clone();
            (Arc::new(move |m: String| l2.lock().unwrap().push(m)) as Logger, log)
        };
        let mut s = ListenerSettings::new(Proto::Tls, "127.0.0.1:0");
        s.logger = logger;
        Listener::new(s).listen().unwrap();
        assert_eq!(log.lock().unwrap()[0], "TLS listener requires cert and key files");
    }
}
