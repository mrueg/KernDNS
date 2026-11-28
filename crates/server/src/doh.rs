//! DNS over HTTPS (RFC 8484): HTTP/1.1 and HTTP/2 (by ALPN) on
//! `/dns-query`, POST with `application/dns-message` or GET with `?dns=`.
//! Behaves like CoreDNS's `ServerHTTPS`: 404 for other paths, 400 for
//! requests that don't parse (or that miekg/dns's accept policy rejects),
//! 500 if nothing answered, and `Cache-Control: max-age` from the answer's
//! lowest TTL. Each status is counted in
//! `coredns_dns_https_responses_total`.
//!
//! Limits (`https` plugin): `max_connections` (default 200, 0 = unbounded)
//! connections at once (further ones wait in the accept queue, before the
//! TLS handshake), and `max_streams` concurrent HTTP/2 streams per
//! connection (default 250).
//!
//! Timeouts (`timeouts`, defaults 3s read, 5s write, 10s idle) follow Go's
//! `http.Server`, on which CoreDNS sets them:
//! - the TLS handshake must finish within the shorter of read and write;
//! - HTTP/1: a request (headers and body) must arrive within the read
//!   timeout, its answer must be written within the write timeout after
//!   its headers (else the connection is closed), and a kept-alive
//!   connection is closed when the next request doesn't start within the
//!   idle timeout;
//! - HTTP/2: a stream's body must arrive within the read timeout, its
//!   answer within the write timeout (else the stream is reset with
//!   `INTERNAL_ERROR`), and a connection without streams for the idle
//!   timeout is closed with GOAWAY.
//!
//! A body that doesn't arrive in time is a 400, as in CoreDNS.
//!
//! The request handling is shared with DoH3 ([`crate::doh3`]).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{Method, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use kerndns_core::proxyproto::ProxyProtoConfig;
use kerndns_core::typify::{MAXIMUM_DEFAULT_TTL, minimal_ttl, typify};
use kerndns_core::{Protocol, Request};
use prometheus::CounterVec;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, Sleep};
use tokio_rustls::TlsAcceptor;

use crate::dispatch::{Dispatcher, encode};
use crate::unpack::unpack_request;

pub const MIME: &str = "application/dns-message";
pub const PATH: &str = "/dns-query";
/// `maxDNSQuerySize`.
pub const MAX_QUERY: usize = 65536;
const MAX_RESPONSE: usize = 65535;

const DEFAULT_MAX_CONNECTIONS: u64 = 200;
/// Go's HTTP/2 default, also used for `max_streams 0`.
const DEFAULT_MAX_STREAMS: u32 = 250;

/// `http.Error`: a plain-text body ending in a newline.
fn text(status: StatusCode, body: &str) -> Response<Bytes> {
    let body = Bytes::from(format!("{body}\n"));
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff")
        // net/http sets it for small bodies; HTTP/3 doesn't add it by itself
        .header("Content-Length", body.len())
        .body(body)
        .expect("valid response")
}

/// `requestToMsgGet`: the one `dns` query parameter, base64url.
fn get_query(uri: &Uri) -> Result<Vec<u8>, ()> {
    let q = uri.query().unwrap_or("");
    let mut vals = q.split('&').filter_map(|kv| kv.strip_prefix("dns="));
    let (Some(b64), None) = (vals.next(), vals.next()) else {
        return Err(());
    };
    if b64.len() > (MAX_QUERY * 8).div_ceil(6) {
        return Err(());
    }
    data_encoding::BASE64URL_NOPAD
        .decode(b64.trim_end_matches('=').as_bytes())
        .map_err(|_| ())
}

/// Answer one DoH request (HTTP/1.1, HTTP/2 or HTTP/3). `body` reads a POST
/// body of at most [`MAX_QUERY`] bytes; it is only polled for POST.
#[allow(clippy::too_many_arguments)]
pub async fn respond<B>(
    d: &Dispatcher,
    method: &Method,
    uri: &Uri,
    body: B,
    src: SocketAddr,
    local: SocketAddr,
    protocol: Protocol,
    responses: &CounterVec,
) -> Response<Bytes>
where
    B: Future<Output = Result<Vec<u8>, ()>>,
{
    let resp = respond_inner(d, method, uri, body, src, local, protocol).await;
    responses.with_label_values(&[d.label(), resp.status().as_str()]).inc();
    resp
}

async fn respond_inner<B>(
    d: &Dispatcher,
    method: &Method,
    uri: &Uri,
    body: B,
    src: SocketAddr,
    local: SocketAddr,
    protocol: Protocol,
) -> Response<Bytes>
where
    B: Future<Output = Result<Vec<u8>, ()>>,
{
    if uri.path() != PATH {
        return text(StatusCode::NOT_FOUND, "");
    }
    let raw = match *method {
        Method::GET => get_query(uri),
        Method::POST => body.await,
        _ => Err(()),
    };
    let Ok(raw) = raw else {
        return text(StatusCode::BAD_REQUEST, "invalid request");
    };
    let Ok(msg) = unpack_request(&raw) else {
        return text(StatusCode::BAD_REQUEST, "invalid request");
    };
    let mut r = Request::new(msg, local, src, protocol);
    r.wire = Some(Arc::from(raw.as_slice()));
    let answer = d.answer(&r).await;
    // like CoreDNS, only the last message written is returned
    let age = answer
        .msgs
        .last()
        .map(|m| minimal_ttl(m, typify(m, SystemTime::now()), MAXIMUM_DEFAULT_TTL).as_secs())
        .unwrap_or(0);
    // DoH3's remote is a UDP address, so its answers are truncated to the
    // client's EDNS size like UDP's; DoH's are not
    let size = crate::dispatch::effective_request(&r, answer.edns.as_deref(), answer.bufsize).size() as usize;
    let Some(wire) = encode(answer, size.min(MAX_RESPONSE)).pop() else {
        return text(StatusCode::INTERNAL_SERVER_ERROR, "No response");
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", MIME)
        .header("Cache-Control", format!("max-age={age}"))
        .header("Content-Length", wire.len())
        .body(Bytes::from(wire))
        .expect("valid response")
}

/// DoH listener settings.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// 0 is unbounded.
    pub max_connections: u64,
    pub max_streams: u32,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Settings {
    pub fn new(l: &kerndns_core::plugin::ListenerLimits, conn: &crate::tcp::Limits) -> Self {
        Settings {
            max_connections: l.https_max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            max_streams: match l.https_max_streams {
                None | Some(0) => DEFAULT_MAX_STREAMS,
                Some(n) => n.min(u32::MAX as u64) as u32,
            },
            read_timeout: conn.read,
            write_timeout: conn.write,
            idle_timeout: conn.idle,
        }
    }

    /// `http.Server.tlsHandshakeTimeout`: the shorter of read and write.
    fn handshake_timeout(&self) -> Duration {
        self.read_timeout.min(self.write_timeout)
    }
}

/// Where an HTTP/1 connection is, for its read deadline (Go sets
/// deadlines on the connection; hyper has nothing like them).
#[derive(Debug, Clone, Copy)]
enum Phase {
    /// Reading a request's headers: they must arrive by then.
    Head(Instant),
    /// Waiting for the next request on a kept-alive connection.
    Idle(Instant),
    /// A request is being served: its body has its own deadline.
    Busy,
}

#[derive(Debug)]
struct Deadlines {
    phase: Phase,
    write: Option<Instant>,
}

/// A connection with Go-style read and write deadlines (HTTP/1 only;
/// HTTP/2 connections never set them).
struct Timed<S> {
    inner: S,
    deadlines: Arc<Mutex<Deadlines>>,
    read_timeout: Duration,
    read_sleep: Pin<Box<Sleep>>,
    write_sleep: Pin<Box<Sleep>>,
}

impl<S> Timed<S> {
    fn new(inner: S, deadlines: Arc<Mutex<Deadlines>>, read_timeout: Duration) -> Self {
        let now = Instant::now();
        Timed {
            inner,
            deadlines,
            read_timeout,
            read_sleep: Box::pin(tokio::time::sleep_until(now)),
            write_sleep: Box::pin(tokio::time::sleep_until(now)),
        }
    }
}

/// Whether `deadline` has passed, registering for a wakeup if not.
fn expired(sleep: &mut Pin<Box<Sleep>>, deadline: Instant, cx: &mut Context<'_>) -> bool {
    if sleep.deadline() != deadline {
        sleep.as_mut().reset(deadline);
    }
    sleep.as_mut().poll(cx).is_ready()
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

impl<S: AsyncRead + Unpin> AsyncRead for Timed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let deadline = match this.deadlines.lock().unwrap().phase {
            Phase::Head(d) | Phase::Idle(d) => Some(d),
            Phase::Busy => None,
        };
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Err(timed_out()));
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    // the next request started: its headers have the read timeout
                    let mut d = this.deadlines.lock().unwrap();
                    if let Phase::Idle(_) = d.phase {
                        d.phase = Phase::Head(Instant::now() + this.read_timeout);
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => match deadline {
                Some(d) if expired(&mut this.read_sleep, d, cx) => Poll::Ready(Err(timed_out())),
                _ => Poll::Pending,
            },
            r => r,
        }
    }
}

impl<S: AsyncWrite + Unpin> Timed<S> {
    fn poll_deadline<T>(
        &mut self,
        cx: &mut Context<'_>,
        op: impl FnOnce(Pin<&mut S>, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let deadline = self.deadlines.lock().unwrap().write;
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Err(timed_out()));
        }
        match op(Pin::new(&mut self.inner), cx) {
            Poll::Pending => match deadline {
                Some(d) if expired(&mut self.write_sleep, d, cx) => Poll::Ready(Err(timed_out())),
                _ => Poll::Pending,
            },
            r => r,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Timed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_deadline(cx, |s, cx| s.poll_write(cx, buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_deadline(cx, |s, cx| s.poll_flush(cx))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Open HTTP/2 streams, for the idle timeout: Go closes a connection
/// that has had no streams for that long.
#[derive(Debug)]
struct Streams {
    open: AtomicUsize,
    /// When the last stream closed (or the connection opened).
    since: Mutex<Instant>,
}

struct StreamGuard(Arc<Streams>);

impl Streams {
    fn new() -> Arc<Self> {
        Arc::new(Streams {
            open: AtomicUsize::new(0),
            since: Mutex::new(Instant::now()),
        })
    }

    fn open(self: &Arc<Self>) -> StreamGuard {
        self.open.fetch_add(1, Ordering::SeqCst);
        StreamGuard(self.clone())
    }

    /// Resolves once the connection has had no streams for `idle`.
    async fn idle(&self, idle: Duration) {
        loop {
            let at = *self.since.lock().unwrap() + idle;
            tokio::time::sleep_until(at).await;
            if self.open.load(Ordering::SeqCst) == 0 && *self.since.lock().unwrap() + idle <= Instant::now() {
                return;
            }
        }
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let mut since = self.0.since.lock().unwrap();
        if self.0.open.fetch_sub(1, Ordering::SeqCst) == 1 {
            *since = Instant::now();
        }
    }
}

/// A semaphore for `max_connections` (`None` when unbounded).
pub fn connection_limit(max: u64) -> Option<Arc<Semaphore>> {
    (max > 0).then(|| Arc::new(Semaphore::new(max.min(Semaphore::MAX_PERMITS as u64) as usize)))
}

/// Serve DoH on `listener` with `tls` (whose ALPN should offer h2 and http/1.1).
pub fn serve(
    listener: TcpListener,
    d: Dispatcher,
    local: SocketAddr,
    tls: TlsAcceptor,
    s: Settings,
    proxy: Option<Arc<ProxyProtoConfig>>,
) -> JoinSet<()> {
    let limit = connection_limit(s.max_connections);
    let mut set = JoinSet::new();
    set.spawn(async move {
        loop {
            // like netutil.LimitListener: don't accept beyond the limit
            let permit = match &limit {
                Some(l) => Some(l.clone().acquire_owned().await.expect("never closed")),
                None => None,
            };
            let Ok((stream, src)) = listener.accept().await else {
                continue;
            };
            let (d, tls, proxy) = (d.clone(), tls.clone(), proxy.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let Some((stream, src)) = crate::proxyproto::maybe_accept(proxy.as_deref(), stream, src).await else {
                    return;
                };
                let Ok(Ok(conn)) = tokio::time::timeout(s.handshake_timeout(), tls.accept(stream)).await else {
                    return;
                };
                let h2 = conn.get_ref().1.alpn_protocol() == Some(b"h2");
                connection(conn, h2, d, src, local, s).await;
            });
        }
    });
    set
}

/// Serve one connection after the TLS handshake: HTTP/2 if the client
/// chose it by ALPN, else HTTP/1 (Go only speaks HTTP/2 after ALPN).
async fn connection<S>(conn: S, h2: bool, d: Dispatcher, src: SocketAddr, local: SocketAddr, s: Settings)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let deadlines = Arc::new(Mutex::new(Deadlines {
        phase: if h2 {
            Phase::Busy
        } else {
            Phase::Head(Instant::now() + s.read_timeout)
        },
        write: None,
    }));
    let streams = Streams::new();
    let io = Timed::new(conn, deadlines.clone(), s.read_timeout);
    let open = streams.clone();
    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let d = d.clone();
        let now = Instant::now();
        // Go: the whole request must be read by the deadline set when its
        // headers started (HTTP/1) or when the stream opened (HTTP/2)
        let body_deadline = if h2 {
            now + s.read_timeout
        } else {
            let mut dl = deadlines.lock().unwrap();
            let at = match dl.phase {
                Phase::Head(at) => at,
                _ => now + s.read_timeout,
            };
            dl.phase = Phase::Busy;
            dl.write = Some(now + s.write_timeout);
            at
        };
        let deadlines = deadlines.clone();
        let stream = h2.then(|| open.open());
        async move {
            let (parts, body) = req.into_parts();
            let body = async move {
                match tokio::time::timeout_at(body_deadline, Limited::new(body, MAX_QUERY).collect()).await {
                    Ok(Ok(b)) => Ok(b.to_bytes().to_vec()),
                    _ => Err(()),
                }
            };
            let answer = async move {
                respond(
                    &d,
                    &parts.method,
                    &parts.uri,
                    body,
                    src,
                    local,
                    Protocol::Https,
                    &kerndns_core::metrics::HTTPS_RESPONSES,
                )
                .await
            };
            if h2 {
                // the stream is reset at the write deadline; the handler
                // still runs to the end, as in Go
                let resp = tokio::time::timeout(s.write_timeout, tokio::spawn(answer)).await;
                drop(stream);
                match resp {
                    Ok(Ok(resp)) => Ok(resp.map(Full::new)),
                    _ => Err(timed_out()),
                }
            } else {
                // a late answer fails at the connection's write deadline
                let resp = answer.await;
                deadlines.lock().unwrap().phase = Phase::Idle(Instant::now() + s.idle_timeout);
                Ok::<_, io::Error>(resp.map(Full::new))
            }
        }
    });
    let mut b = auto::Builder::new(TokioExecutor::new());
    if h2 {
        b = b.http2_only();
        b.http2().max_concurrent_streams(s.max_streams);
    } else {
        b = b.http1_only();
    }
    let conn = b.serve_connection(TokioIo::new(io), svc);
    tokio::pin!(conn);
    if !h2 {
        let _ = conn.await;
        return;
    }
    tokio::select! {
        _ = conn.as_mut() => return,
        () = streams.idle(s.idle_timeout) => {}
    }
    // idle: GOAWAY, then close
    conn.as_mut().graceful_shutdown();
    let _ = conn.await;
}
