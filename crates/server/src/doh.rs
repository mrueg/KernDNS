//! DNS over HTTPS (RFC 8484): HTTP/1.1 and HTTP/2 (by ALPN) on
//! `/dns-query`, POST with `application/dns-message` or GET with `?dns=`.
//! Behaves like CoreDNS's `ServerHTTPS`: 404 for other paths, 400 for
//! requests that don't parse, 500 if nothing answered, and
//! `Cache-Control: max-age` from the answer's lowest TTL.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request as HttpRequest, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use kerndns_core::proto::op::{Message, MessageType};
use kerndns_core::typify::{MAXIMUM_DEFAULT_TTL, minimal_ttl, typify};
use kerndns_core::{Protocol, Request};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::dispatch::{Dispatcher, encode};

pub const MIME: &str = "application/dns-message";
const MAX_QUERY: usize = 65535;

fn text(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(format!("{body}\n"))))
        .expect("valid response")
}

async fn query_bytes(req: HttpRequest<hyper::body::Incoming>) -> Result<Vec<u8>, ()> {
    match *req.method() {
        Method::POST => {
            let body = Limited::new(req.into_body(), MAX_QUERY)
                .collect()
                .await
                .map_err(|_| ())?;
            Ok(body.to_bytes().to_vec())
        }
        Method::GET => {
            let q = req.uri().query().unwrap_or("");
            let mut vals = q.split('&').filter_map(|kv| kv.strip_prefix("dns="));
            let (Some(b64), None) = (vals.next(), vals.next()) else {
                return Err(());
            };
            data_encoding::BASE64URL_NOPAD
                .decode(b64.trim_end_matches('=').as_bytes())
                .map_err(|_| ())
        }
        _ => Err(()),
    }
}

async fn serve_http(
    d: Dispatcher,
    path: Arc<str>,
    src: SocketAddr,
    local: SocketAddr,
    req: HttpRequest<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() != &*path {
        return Ok(text(StatusCode::NOT_FOUND, ""));
    }
    let Ok(raw) = query_bytes(req).await else {
        return Ok(text(StatusCode::BAD_REQUEST, "invalid request"));
    };
    let Ok(msg) = Message::from_vec(&raw) else {
        return Ok(text(StatusCode::BAD_REQUEST, "invalid request"));
    };
    if msg.metadata.message_type == MessageType::Response {
        return Ok(text(StatusCode::BAD_REQUEST, "invalid request"));
    }
    let mut r = Request::new(msg, local, src, Protocol::Https);
    r.wire = Some(Arc::from(raw.as_slice()));
    let answer = d.answer(&r).await;
    // like CoreDNS, only the last message written is returned
    let age = answer
        .msgs
        .last()
        .map(|m| minimal_ttl(m, typify(m, SystemTime::now()), MAXIMUM_DEFAULT_TTL).as_secs())
        .unwrap_or(0);
    let Some(wire) = encode(answer, MAX_QUERY).pop() else {
        return Ok(text(StatusCode::INTERNAL_SERVER_ERROR, "No response"));
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", MIME)
        .header("Cache-Control", format!("max-age={age}"))
        .header("Content-Length", wire.len())
        .body(Full::new(Bytes::from(wire)))
        .expect("valid response"))
}

/// Serve DoH on `listener` with `tls` (whose ALPN should offer h2 and http/1.1).
pub fn serve(listener: TcpListener, d: Dispatcher, local: SocketAddr, tls: TlsAcceptor, path: &str) -> JoinSet<()> {
    let path: Arc<str> = Arc::from(path);
    let mut set = JoinSet::new();
    set.spawn(async move {
        loop {
            let Ok((stream, src)) = listener.accept().await else {
                continue;
            };
            let (d, tls, path) = (d.clone(), tls.clone(), path.clone());
            tokio::spawn(async move {
                let Ok(Ok(s)) = tokio::time::timeout(std::time::Duration::from_secs(5), tls.accept(stream)).await
                else {
                    return;
                };
                let svc = hyper::service::service_fn(move |req| serve_http(d.clone(), path.clone(), src, local, req));
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    set
}
