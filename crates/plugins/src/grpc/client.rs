//! A gRPC client for CoreDNS's `DnsService` (`pb/dns.proto`), the
//! counterpart of KernDNS's `grpc://` listener (`kerndns_server::grpc`):
//! one unary method, `/coredns.dns.DnsService/Query`, taking and returning
//! a `DnsPacket { bytes msg = 1; }`.
//!
//! Like grpc-go's `ClientConn`, each upstream keeps one HTTP/2 connection
//! (cleartext h2c, or TLS with ALPN `h2`) and multiplexes queries over it,
//! dialing again when it breaks. Calls carry `grpc-timeout` from the
//! query's deadline, and errors are reported with grpc-go's status codes
//! and messages.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use bytes::{Buf, Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use kerndns_core::async_trait;
use kerndns_core::protobuf::{decode_packet, encode_packet};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

const QUERY_PATH: &str = "/coredns.dns.DnsService/Query";

/// `maxProtobufPayloadBytes`: grpc.MaxCallRecvMsgSize / MaxCallSendMsgSize.
pub const MAX_PAYLOAD: usize = 65535 + 4;

/// A gRPC status code with grpc-go's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code(pub u32);

impl Code {
    pub const OK: Code = Code(0);
    pub const CANCELED: Code = Code(1);
    pub const UNKNOWN: Code = Code(2);
    pub const DEADLINE_EXCEEDED: Code = Code(4);
    pub const NOT_FOUND: Code = Code(5);
    pub const RESOURCE_EXHAUSTED: Code = Code(8);
    pub const UNIMPLEMENTED: Code = Code(12);
    pub const INTERNAL: Code = Code(13);
    pub const UNAVAILABLE: Code = Code(14);
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [&str; 17] = [
            "OK",
            "Canceled",
            "Unknown",
            "InvalidArgument",
            "DeadlineExceeded",
            "NotFound",
            "AlreadyExists",
            "PermissionDenied",
            "ResourceExhausted",
            "FailedPrecondition",
            "Aborted",
            "OutOfRange",
            "Unimplemented",
            "Internal",
            "Unavailable",
            "DataLoss",
            "Unauthenticated",
        ];
        match NAMES.get(self.0 as usize) {
            Some(n) => f.write_str(n),
            None => write!(f, "Code({})", self.0),
        }
    }
}

/// A failed call, shown like grpc-go's `status.Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    pub code: Code,
    pub msg: String,
}

impl RpcError {
    pub fn new(code: Code, msg: impl Into<String>) -> Self {
        Self { code, msg: msg.into() }
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rpc error: code = {} desc = {}", self.code, self.msg)
    }
}

impl std::error::Error for RpcError {}

/// `pb.DnsServiceClient`: sends a DNS message, returns the answer's bytes.
/// Tests replace it with canned answers.
#[async_trait]
pub trait DnsServiceClient: Send + Sync {
    async fn query(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, RpcError>;

    /// Close the connection; later calls fail.
    fn close(&self) {}
}

/// Where an upstream listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

/// TLS for the connection: the client config (ALPN `h2` is added) and the
/// name to verify.
pub struct Tls {
    pub config: Arc<ClientConfig>,
    pub server_name: ServerName<'static>,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type Sender = SendRequest<Full<Bytes>>;

/// The HTTP/2 client of one upstream.
pub struct H2Client {
    target: Target,
    tls: Option<Tls>,
    /// `:authority` and `:scheme` of every request.
    uri: String,
    conn: tokio::sync::Mutex<Option<Sender>>,
    closed: AtomicBool,
}

impl H2Client {
    pub fn new(target: Target, tls: Option<Tls>) -> Self {
        let authority = match &target {
            Target::Tcp(a) => a.to_string(),
            Target::Unix(_) => "localhost".to_string(),
        };
        let scheme = if tls.is_some() { "https" } else { "http" };
        let tls = tls.map(|mut t| {
            let mut c = (*t.config).clone();
            c.alpn_protocols = vec![b"h2".to_vec()];
            t.config = Arc::new(c);
            t
        });
        Self {
            target,
            tls,
            uri: format!("{scheme}://{authority}{QUERY_PATH}"),
            conn: tokio::sync::Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    async fn dial(&self) -> Result<Sender, RpcError> {
        let unavailable = |e: &dyn fmt::Display| {
            RpcError::new(
                Code::UNAVAILABLE,
                format!("connection error: desc = \"transport: Error while dialing: {e}\""),
            )
        };
        let io: Box<dyn Io> = match &self.target {
            Target::Tcp(a) => {
                let s = TcpStream::connect(a).await.map_err(|e| unavailable(&e))?;
                let _ = s.set_nodelay(true);
                Box::new(s)
            }
            Target::Unix(p) => Box::new(UnixStream::connect(p).await.map_err(|e| unavailable(&e))?),
        };
        let io: Box<dyn Io> = match &self.tls {
            None => io,
            Some(t) => {
                let c = tokio_rustls::TlsConnector::from(t.config.clone());
                let s = c.connect(t.server_name.clone(), io).await.map_err(|e| {
                    RpcError::new(
                        Code::UNAVAILABLE,
                        format!("connection error: desc = \"transport: authentication handshake failed: {e}\""),
                    )
                })?;
                Box::new(s)
            }
        };
        let (send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(io))
            .await
            .map_err(|e| unavailable(&e))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(send)
    }

    /// The live connection, dialing a new one if there is none.
    async fn sender(&self) -> Result<Sender, RpcError> {
        let mut c = self.conn.lock().await;
        if self.closed.load(Ordering::Relaxed) {
            return Err(RpcError::new(Code::CANCELED, "grpc: the client connection is closing"));
        }
        if let Some(s) = c.as_ref()
            && !s.is_closed()
        {
            return Ok(s.clone());
        }
        let s = self.dial().await?;
        *c = Some(s.clone());
        Ok(s)
    }

    async fn call(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, RpcError> {
        let mut send = self.sender().await?;
        let pb = encode_packet(msg);
        let mut frame = BytesMut::with_capacity(pb.len() + 5);
        frame.extend_from_slice(&[0]);
        frame.extend_from_slice(&(pb.len() as u32).to_be_bytes());
        frame.extend_from_slice(&pb);
        let timeout = deadline.saturating_duration_since(Instant::now());
        let req = hyper::Request::post(&self.uri)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("user-agent", concat!("kerndns-grpc/", env!("CARGO_PKG_VERSION")))
            .header("grpc-timeout", format!("{}u", timeout.as_micros().clamp(1, 99_999_999)))
            .body(Full::new(frame.freeze()))
            .map_err(|e| RpcError::new(Code::INTERNAL, e.to_string()))?;
        send.ready()
            .await
            .map_err(|e| RpcError::new(Code::UNAVAILABLE, format!("connection error: desc = \"{e}\"")))?;
        let resp = send
            .send_request(req)
            .await
            .map_err(|e| RpcError::new(Code::UNAVAILABLE, format!("error reading from server: {e}")))?;
        read_response(resp).await
    }
}

#[async_trait]
impl DnsServiceClient for H2Client {
    async fn query(&self, msg: &[u8], deadline: Instant) -> Result<Vec<u8>, RpcError> {
        match tokio::time::timeout_at(deadline.into(), self.call(msg, deadline)).await {
            Ok(r) => r,
            Err(_) => Err(RpcError::new(Code::DEADLINE_EXCEEDED, "context deadline exceeded")),
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        if let Ok(mut c) = self.conn.try_lock() {
            *c = None;
        }
    }
}

/// The status from `grpc-status` / `grpc-message`, if present.
fn status_of(h: &http::HeaderMap) -> Option<RpcError> {
    let code = h.get("grpc-status")?.to_str().ok()?.parse().ok()?;
    let msg = h
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .map(decode_message)
        .unwrap_or_default();
    Some(RpcError::new(Code(code), msg))
}

/// `grpc-message` is percent-encoded.
fn decode_message(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// grpc-go's mapping of an HTTP status without `grpc-status`.
fn http_status_code(status: u16) -> Code {
    match status {
        400 => Code::INTERNAL,
        401 => Code(16),
        403 => Code(7),
        404 => Code::UNIMPLEMENTED,
        429 | 502 | 503 | 504 => Code::UNAVAILABLE,
        _ => Code::UNKNOWN,
    }
}

async fn read_response(resp: hyper::Response<hyper::body::Incoming>) -> Result<Vec<u8>, RpcError> {
    let pb = read_unary(resp, MAX_PAYLOAD).await?;
    decode_packet(&pb).ok_or_else(|| {
        RpcError::new(
            Code::INTERNAL,
            "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data",
        )
    })
}

/// The one message of a unary call's response (its protobuf bytes), or the
/// call's status as an error. Messages larger than `max` are refused.
pub(crate) async fn read_unary(resp: hyper::Response<hyper::body::Incoming>, max: usize) -> Result<Vec<u8>, RpcError> {
    let status = resp.status();
    // trailers-only: the status is in the headers
    if let Some(st) = status_of(resp.headers()) {
        return Err(if st.code == Code::OK {
            RpcError::new(Code::INTERNAL, "server closed the stream without sending trailers")
        } else {
            st
        });
    }
    if status != http::StatusCode::OK {
        return Err(RpcError::new(
            http_status_code(status.as_u16()),
            format!(
                "unexpected HTTP status code received from server: {} ({})",
                status.as_u16(),
                status.canonical_reason().unwrap_or("")
            ),
        ));
    }
    let mut body = resp.into_body();
    let mut buf = BytesMut::new();
    let mut trailers = None;
    while let Some(f) = body.frame().await {
        let f = f.map_err(|e| RpcError::new(Code::INTERNAL, format!("error reading from server: {e}")))?;
        match f.into_data() {
            Ok(mut d) => {
                while d.has_remaining() {
                    let c = d.chunk();
                    buf.extend_from_slice(c);
                    let n = c.len();
                    d.advance(n);
                }
                if buf.len() >= 5 {
                    let n = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
                    if n > max {
                        return Err(RpcError::new(
                            Code::RESOURCE_EXHAUSTED,
                            format!("grpc: received message larger than max ({n} vs. {max})"),
                        ));
                    }
                }
            }
            Err(f) => {
                if let Ok(t) = f.into_trailers() {
                    trailers = Some(t);
                }
            }
        }
    }
    let st = trailers
        .as_ref()
        .and_then(status_of)
        .unwrap_or_else(|| RpcError::new(Code::INTERNAL, "server closed the stream without sending trailers"));
    if st.code != Code::OK {
        return Err(st);
    }
    if buf.len() < 5 {
        return Err(RpcError::new(
            Code::INTERNAL,
            "cardinality violation: received no response message from non-server-streaming RPC",
        ));
    }
    if buf[0] & 1 != 0 {
        return Err(RpcError::new(
            Code::INTERNAL,
            "grpc: compressed flag set with identity or empty encoding",
        ));
    }
    let n = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if buf.len() < n + 5 {
        return Err(RpcError::new(Code::INTERNAL, "unexpected EOF"));
    }
    buf.truncate(n + 5);
    Ok(buf.split_off(5).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages() {
        assert_eq!(decode_message("a b%25%0A"), "a b%\n");
        assert_eq!(decode_message("50%"), "50%");
        assert_eq!(
            RpcError::new(Code::NOT_FOUND, "x").to_string(),
            "rpc error: code = NotFound desc = x"
        );
        assert_eq!(Code(99).to_string(), "Code(99)");
    }
}
