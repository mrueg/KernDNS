//! DNS over gRPC, a port of CoreDNS's `ServergRPC`
//! (`core/dnsserver/server_grpc.go`): the unary method
//! `coredns.dns.DnsService/Query` from CoreDNS's `pb/dns.proto`, taking
//! and returning a `DnsPacket { bytes msg = 1; }`.
//!
//! The service is small enough that it is served directly on hyper's
//! HTTP/2 server rather than through a gRPC framework: requests are one
//! length-prefixed protobuf message, answers one message plus a
//! `grpc-status` trailer, and errors trailers-only responses, with the
//! status codes and messages grpc-go uses.
//!
//! Without the `tls` plugin the listener speaks HTTP/2 in cleartext (h2c);
//! with it, TLS with ALPN `h2`. Limits (`grpc_server` plugin):
//! `max_streams` concurrent streams per connection (default 256, 0 =
//! unbounded) and `max_connections` (default 200, 0 = unbounded; further
//! connections wait in the accept queue).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo};
use kerndns_core::Protocol;
use kerndns_core::plugin::ListenerLimits;
use kerndns_core::proxyproto::ProxyProtoConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::dispatch::Dispatcher;
use crate::doh::connection_limit;
use crate::unpack::unpack_request;

pub use kerndns_core::protobuf::{decode_packet, encode_packet};

pub const SERVICE: &str = "coredns.dns.DnsService";
pub const QUERY_PATH: &str = "/coredns.dns.DnsService/Query";

/// `dns.MaxMsgSize`.
const MAX_DNS: usize = 65535;
/// `maxProtobufPayloadBytes`: grpc.MaxRecvMsgSize / MaxSendMsgSize.
const MAX_PAYLOAD: usize = MAX_DNS + 4;

const DEFAULT_MAX_STREAMS: u64 = 256;
const DEFAULT_MAX_CONNECTIONS: u64 = 200;

/// gRPC status codes used here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Ok = 0,
    Unknown = 2,
    InvalidArgument = 3,
    ResourceExhausted = 8,
    Unimplemented = 12,
    Internal = 13,
}

/// gRPC listener settings.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// 0 is unbounded.
    pub max_streams: u64,
    /// 0 is unbounded.
    pub max_connections: u64,
}

impl Settings {
    pub fn new(l: &ListenerLimits) -> Self {
        Settings {
            max_streams: l.grpc_max_streams.unwrap_or(DEFAULT_MAX_STREAMS),
            max_connections: l.grpc_max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
        }
    }
}

/// A unary gRPC response body: at most one data frame, then trailers.
pub struct GrpcBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl Body for GrpcBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(d) = self.data.take() {
            return Poll::Ready(Some(Ok(Frame::data(d))));
        }
        Poll::Ready(self.trailers.take().map(|t| Ok(Frame::trailers(t))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none() && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.as_ref().map_or(0, |d| d.len() as u64))
    }
}

/// `grpc-message` is percent-encoded outside printable ASCII.
fn encode_message(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    for b in msg.bytes() {
        if (0x20..0x7f).contains(&b) && b != b'%' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn status_headers(h: &mut HeaderMap, code: Code, msg: &str) {
    h.insert("grpc-status", HeaderValue::from(code as u16));
    if !msg.is_empty()
        && let Ok(v) = HeaderValue::from_str(&encode_message(msg))
    {
        h.insert("grpc-message", v);
    }
}

/// A trailers-only error response.
fn error(http_status: StatusCode, code: Code, msg: &str) -> Response<GrpcBody> {
    let mut r = Response::new(GrpcBody {
        data: None,
        trailers: None,
    });
    *r.status_mut() = http_status;
    r.headers_mut()
        .insert("content-type", HeaderValue::from_static("application/grpc"));
    status_headers(r.headers_mut(), code, msg);
    r
}

fn ok(payload: &[u8]) -> Response<GrpcBody> {
    let pb = encode_packet(payload);
    let mut frame = BytesMut::with_capacity(pb.len() + 5);
    frame.extend_from_slice(&[0]);
    frame.extend_from_slice(&(pb.len() as u32).to_be_bytes());
    frame.extend_from_slice(&pb);
    let mut trailers = HeaderMap::new();
    status_headers(&mut trailers, Code::Ok, "");
    let mut r = Response::new(GrpcBody {
        data: Some(frame.freeze()),
        trailers: Some(trailers),
    });
    r.headers_mut()
        .insert("content-type", HeaderValue::from_static("application/grpc"));
    r
}

/// Read the one request message of a unary call.
async fn read_message(mut body: Incoming) -> Result<(bool, Vec<u8>), Box<Response<GrpcBody>>> {
    let mut buf = BytesMut::new();
    let mut want: Option<usize> = None;
    loop {
        if want.is_none() && buf.len() >= 5 {
            let n = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if n > MAX_PAYLOAD {
                return Err(Box::new(error(
                    StatusCode::OK,
                    Code::ResourceExhausted,
                    &format!("grpc: received message larger than max ({n} vs. {MAX_PAYLOAD})"),
                )));
            }
            want = Some(n + 5);
        }
        if let Some(w) = want
            && buf.len() >= w
        {
            let compressed = buf[0] & 1 != 0;
            return Ok((compressed, buf[5..w].to_vec()));
        }
        match body.frame().await {
            Some(Ok(f)) => {
                if let Ok(mut d) = f.into_data() {
                    while d.has_remaining() {
                        let c = d.chunk();
                        buf.extend_from_slice(c);
                        let n = c.len();
                        d.advance(n);
                    }
                }
            }
            Some(Err(e)) => return Err(Box::new(error(StatusCode::OK, Code::Internal, &e.to_string()))),
            None => {
                let msg = if buf.is_empty() { "EOF" } else { "unexpected EOF" };
                return Err(Box::new(error(StatusCode::OK, Code::Internal, msg)));
            }
        }
    }
}

/// Serve one HTTP/2 request.
pub async fn handle(
    d: &Dispatcher,
    src: SocketAddr,
    local: SocketAddr,
    req: hyper::Request<Incoming>,
) -> Response<GrpcBody> {
    let (parts, body) = req.into_parts();
    if parts.method != Method::POST {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            Code::Internal,
            &format!(
                "http2Server.operateHeaders parsed a :method field: {} which should be POST",
                parts.method
            ),
        );
    }
    let ct = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let grpc_ct = ct
        .strip_prefix("application/grpc")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('+') || rest.starts_with(';'));
    if !grpc_ct {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Code::InvalidArgument,
            &format!("invalid gRPC request content-type {ct:?}"),
        );
    }
    let path = parts.uri.path();
    if path != QUERY_PATH {
        let msg = match path.strip_prefix('/').and_then(|p| p.rsplit_once('/')) {
            None => format!("malformed method name: {path:?}"),
            Some((svc, m)) if svc == SERVICE => format!("unknown method {m} for service {SERVICE}"),
            Some((svc, _)) => format!("unknown service {svc}"),
        };
        return error(StatusCode::OK, Code::Unimplemented, &msg);
    }
    let encoding = parts
        .headers
        .get("grpc-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("identity");
    if encoding != "identity" {
        return error(
            StatusCode::OK,
            Code::Unimplemented,
            &format!("grpc: Decompressor is not installed for grpc-encoding {encoding:?}"),
        );
    }
    let (compressed, pb) = match read_message(body).await {
        Ok(m) => m,
        Err(r) => return *r,
    };
    if compressed {
        return error(
            StatusCode::OK,
            Code::Internal,
            "grpc: compressed flag set with identity or empty encoding",
        );
    }
    let Some(raw) = decode_packet(&pb) else {
        return error(
            StatusCode::OK,
            Code::Internal,
            "grpc: error unmarshalling request: proto: cannot parse invalid wire-format data",
        );
    };
    query(d, src, local, &raw).await
}

/// `ServergRPC.Query`.
async fn query(d: &Dispatcher, src: SocketAddr, local: SocketAddr, raw: &[u8]) -> Response<GrpcBody> {
    if raw.len() > MAX_DNS {
        return error(
            StatusCode::OK,
            Code::Unknown,
            &format!("dns message exceeds size limit: {}", raw.len()),
        );
    }
    let msg = match unpack_request(raw) {
        Ok(m) => m,
        Err(e) => return error(StatusCode::OK, Code::Unknown, &e),
    };
    let wires = crate::udp::answer(d, msg, raw, src, local, Protocol::Grpc, Default::default()).await;
    // the writer keeps the last message written, and starts out holding
    // the request itself
    match wires.last() {
        Some(w) => ok(w),
        None => ok(raw),
    }
}

/// Serve DNS over gRPC on `listener`, over TLS if `tls` is given.
pub fn serve(
    listener: TcpListener,
    d: Dispatcher,
    local: SocketAddr,
    tls: Option<TlsAcceptor>,
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
            let _ = stream.set_nodelay(true);
            let (d, tls, proxy) = (d.clone(), tls.clone(), proxy.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let Some((stream, src)) = crate::proxyproto::maybe_accept(proxy.as_deref(), stream, src).await else {
                    return;
                };
                match tls {
                    None => connection(stream, d, src, local, s).await,
                    Some(acc) => {
                        if let Ok(Ok(st)) =
                            tokio::time::timeout(std::time::Duration::from_secs(120), acc.accept(stream)).await
                        {
                            connection(st, d, src, local, s).await;
                        }
                    }
                }
            });
        }
    });
    set
}

async fn connection<S>(io: S, d: Dispatcher, src: SocketAddr, local: SocketAddr, s: Settings)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let d = Arc::new(d);
    let svc = hyper::service::service_fn(move |req| {
        let d = d.clone();
        async move { Ok::<_, Infallible>(handle(&d, src, local, req).await) }
    });
    let mut b = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    b.max_concurrent_streams(match s.max_streams {
        0 => u32::MAX,
        n => n.min(u32::MAX as u64) as u32,
    });
    let _ = b.serve_connection(TokioIo::new(io), svc).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_message() {
        assert_eq!(encode_message("a b%\n"), "a b%25%0A");
    }
}
