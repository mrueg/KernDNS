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
//! The request handling is shared with DoH3 ([`crate::doh3`]).

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use http::{Method, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use kerndns_core::proxyproto::ProxyProtoConfig;
use kerndns_core::typify::{MAXIMUM_DEFAULT_TTL, minimal_ttl, typify};
use kerndns_core::{Protocol, Request};
use prometheus::CounterVec;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
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
}

impl Settings {
    pub fn new(l: &kerndns_core::plugin::ListenerLimits) -> Self {
        Settings {
            max_connections: l.https_max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            max_streams: match l.https_max_streams {
                None | Some(0) => DEFAULT_MAX_STREAMS,
                Some(n) => n.min(u32::MAX as u64) as u32,
            },
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
    let max_streams = s.max_streams;
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
                let Ok(Ok(conn)) = tokio::time::timeout(std::time::Duration::from_secs(5), tls.accept(stream)).await
                else {
                    return;
                };
                let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let d = d.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = async move {
                            Limited::new(body, MAX_QUERY)
                                .collect()
                                .await
                                .map(|b| b.to_bytes().to_vec())
                                .map_err(|_| ())
                        };
                        let resp = respond(
                            &d,
                            &parts.method,
                            &parts.uri,
                            body,
                            src,
                            local,
                            Protocol::Https,
                            &kerndns_core::metrics::HTTPS_RESPONSES,
                        )
                        .await;
                        Ok::<_, Infallible>(resp.map(Full::new))
                    }
                });
                let mut b = auto::Builder::new(TokioExecutor::new());
                b.http2().max_concurrent_streams(max_streams);
                let _ = b.serve_connection(TokioIo::new(conn), svc).await;
            });
        }
    });
    set
}
