//! `timeouts` on DoH listeners, which follow Go's `http.Server` as in
//! CoreDNS (`read 1s`, `write 2s`, `idle 3s` here, so each limit shows by
//! when it hits). Every scenario reports what the client saw and after how
//! many whole seconds; `against_coredns` runs them against CoreDNS too.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use kerndns_core::proto::op::{Message, MessageType, OpCode, Query};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_server::{Instance, Options};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

const TLS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/coredns/plugin/tls");

/// The server blocks: `fast` answers at once, `slow` after 3s (beyond the
/// write timeout).
fn corefile(fast: u16, slow: u16) -> String {
    let tls = format!("tls {TLS_DIR}/test_cert.pem {TLS_DIR}/test_key.pem {TLS_DIR}/test_ca.pem");
    let timeouts = "timeouts {\n  read 1s\n  write 2s\n  idle 3s\n }";
    format!(
        "https://.:{fast} {{\n bind 127.0.0.1\n {tls}\n {timeouts}\n whoami\n}}\n\
         https://.:{slow} {{\n bind 127.0.0.1\n {tls}\n {timeouts}\n erratic {{\n  delay 1 3s\n }}\n}}\n"
    )
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

type Tls = tokio_rustls::client::TlsStream<TcpStream>;

async fn connect(port: u16, alpn: &[u8]) -> Tls {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut c = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    c.alpn_protocols = vec![alpn.to_vec()];
    let tcp = TcpStream::connect(localhost(port)).await.unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(c))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}

fn query() -> Vec<u8> {
    let mut m = Message::new(0, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii("example.org.").unwrap(), RecordType::A));
    m.to_vec().unwrap()
}

fn get_path() -> String {
    format!("/dns-query?dns={}", data_encoding::BASE64URL_NOPAD.encode(&query()))
}

/// Whole seconds since `t`, rounded.
fn secs(t: Instant) -> u64 {
    (t.elapsed().as_millis() as u64 + 500) / 1000
}

/// What a client saw.
#[derive(Debug, PartialEq, Eq, Clone)]
enum Seen {
    /// The connection was closed after this many seconds, after these
    /// bytes (only the status line is kept).
    Closed { secs: u64, got: String },
    /// An HTTP status after this many seconds.
    Status { status: u16, secs: u64 },
    /// The stream was reset with this HTTP/2 error code.
    Reset { code: String, secs: u64 },
}

/// Read until EOF (or 10s); the status line of what came.
async fn read_to_close<S: tokio::io::AsyncRead + Unpin>(s: &mut S, t: Instant) -> Seen {
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut got)).await;
    let line = String::from_utf8_lossy(&got).lines().next().unwrap_or("").to_string();
    Seen::Closed {
        secs: secs(t),
        got: line,
    }
}

/// A TCP connection that never starts TLS is closed at the handshake
/// timeout (the shorter of read and write).
async fn handshake_stall(port: u16) -> Seen {
    let t = Instant::now();
    let mut s = TcpStream::connect(localhost(port)).await.unwrap();
    read_to_close(&mut s, t).await
}

/// HTTP/1 headers that never end: closed at the read timeout.
async fn h1_partial_headers(port: u16) -> Seen {
    let mut s = connect(port, b"http/1.1").await;
    let t = Instant::now();
    s.write_all(format!("GET {} HTTP/1.1\r\nHost: localhost\r\n", get_path()).as_bytes())
        .await
        .unwrap();
    read_to_close(&mut s, t).await
}

/// An HTTP/1 body that never ends: 400 at the read timeout.
async fn h1_partial_body(port: u16) -> Seen {
    let mut s = connect(port, b"http/1.1").await;
    let t = Instant::now();
    s.write_all(
        b"POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: 100\r\n\r\n0123456789",
    )
    .await
    .unwrap();
    read_to_close(&mut s, t).await
}

/// After an HTTP/1 answer, the kept-alive connection is closed at the
/// idle timeout.
async fn h1_idle(port: u16) -> Seen {
    let mut s = connect(port, b"http/1.1").await;
    s.write_all(format!("GET {} HTTP/1.1\r\nHost: localhost\r\n\r\n", get_path()).as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    let t = Instant::now();
    let first = String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    match read_to_close(&mut s, t).await {
        Seen::Closed { secs, .. } => Seen::Closed { secs, got: first },
        s => s,
    }
}

/// An HTTP/1 answer later than the write timeout is never written: the
/// connection closes when the handler is done.
async fn h1_slow(port: u16) -> Seen {
    let mut s = connect(port, b"http/1.1").await;
    let t = Instant::now();
    s.write_all(format!("GET {} HTTP/1.1\r\nHost: localhost\r\n\r\n", get_path()).as_bytes())
        .await
        .unwrap();
    read_to_close(&mut s, t).await
}

type H2 = hyper::client::conn::http2::SendRequest<http_body_util::combinators::BoxBody<Bytes, std::io::Error>>;

async fn h2(port: u16) -> (H2, tokio::task::JoinHandle<()>) {
    let s = connect(port, b"h2").await;
    let (send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(s))
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });
    (send, task)
}

fn full(b: Vec<u8>) -> http_body_util::combinators::BoxBody<Bytes, std::io::Error> {
    Full::new(Bytes::from(b)).map_err(|e| match e {}).boxed()
}

async fn h2_send(
    send: &mut H2,
    req: http::Request<http_body_util::combinators::BoxBody<Bytes, std::io::Error>>,
    t: Instant,
) -> Seen {
    match send.send_request(req).await {
        Ok(r) => {
            let status = r.status().as_u16();
            let _ = r.into_body().collect().await;
            Seen::Status { status, secs: secs(t) }
        }
        Err(e) => Seen::Reset {
            code: reason(&format!("{e:?}")),
            secs: secs(t),
        },
    }
}

/// The HTTP/2 error code named in a hyper error.
fn reason(debug: &str) -> String {
    [
        "INTERNAL_ERROR",
        "CANCEL",
        "NO_ERROR",
        "PROTOCOL_ERROR",
        "REFUSED_STREAM",
    ]
    .iter()
    .find(|c| debug.contains(*c))
    .map(|c| c.to_string())
    .unwrap_or_else(|| debug.to_string())
}

/// An HTTP/2 answer later than the write timeout: the stream is reset.
async fn h2_slow(port: u16) -> Seen {
    let (mut send, _conn) = h2(port).await;
    let t = Instant::now();
    let req = http::Request::get(format!("https://localhost:{port}{}", get_path()))
        .body(full(Vec::new()))
        .unwrap();
    h2_send(&mut send, req, t).await
}

/// An HTTP/2 body that never ends: 400 at the read timeout.
async fn h2_partial_body(port: u16) -> Seen {
    let (mut send, _conn) = h2(port).await;
    let t = Instant::now();
    let first =
        futures_util::stream::once(async { Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(b"0123456789"))) });
    let body = StreamBody::new(futures_util::StreamExt::chain(first, futures_util::stream::pending()));
    let req = http::Request::post(format!("https://localhost:{port}/dns-query"))
        .header("content-type", "application/dns-message")
        .body(BodyExt::boxed(body))
        .unwrap();
    h2_send(&mut send, req, t).await
}

/// After an HTTP/2 answer, the connection without streams is closed at
/// the idle timeout.
async fn h2_idle(port: u16) -> Seen {
    let (mut send, conn) = h2(port).await;
    let req = http::Request::get(format!("https://localhost:{port}{}", get_path()))
        .body(full(Vec::new()))
        .unwrap();
    let r = h2_send(&mut send, req, Instant::now()).await;
    let t = Instant::now();
    let _ = tokio::time::timeout(Duration::from_secs(10), conn).await;
    match r {
        Seen::Status { status, .. } => Seen::Closed {
            secs: secs(t),
            got: status.to_string(),
        },
        r => r,
    }
}

async fn scenarios(fast: u16, slow: u16) -> Vec<(&'static str, Seen)> {
    // concurrently, as each one waits for timeouts
    let (a, b, c, d, e, f, g, h) = tokio::join!(
        handshake_stall(fast),
        h1_partial_headers(fast),
        h1_partial_body(fast),
        h1_idle(fast),
        h1_slow(slow),
        h2_partial_body(fast),
        h2_idle(fast),
        h2_slow(slow),
    );
    vec![
        ("handshake_stall", a),
        ("h1_partial_headers", b),
        ("h1_partial_body", c),
        ("h1_idle", d),
        ("h1_slow", e),
        ("h2_partial_body", f),
        ("h2_idle", g),
        ("h2_slow", h),
    ]
}

fn closed(secs: u64, got: &str) -> Seen {
    Seen::Closed { secs, got: got.into() }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// What CoreDNS's clients see.
fn want() -> Vec<(&'static str, Seen)> {
    vec![
        ("handshake_stall", closed(1, "")),
        ("h1_partial_headers", closed(1, "")),
        ("h1_partial_body", closed(1, "HTTP/1.1 400 Bad Request")),
        ("h1_idle", closed(3, "HTTP/1.1 200 OK")),
        ("h1_slow", closed(3, "")),
        ("h2_partial_body", Seen::Status { status: 400, secs: 1 }),
        ("h2_idle", closed(3, "200")),
        (
            "h2_slow",
            Seen::Reset {
                code: "INTERNAL_ERROR".into(),
                secs: 2,
            },
        ),
    ]
}

#[tokio::test]
async fn doh_timeouts() {
    let (fast, slow) = (free_port(), free_port());
    let _inst = Instance::start(
        &corefile(fast, slow),
        "Corefile",
        &kerndns_plugins::registry(),
        &Options::default(),
    )
    .await
    .unwrap();
    assert_eq!(scenarios(fast, slow).await, want());
}

/// The same scenarios against CoreDNS (`target/coredns-ref`, from
/// `cargo xtask difftest`, or `$COREDNS_REF`).
#[tokio::test]
#[ignore = "needs a CoreDNS binary"]
async fn against_coredns() {
    let bin = std::env::var("COREDNS_REF")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/coredns-ref").to_string());
    let (fast, slow) = (free_port(), free_port());
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("doh-timeouts-{fast}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Corefile"), corefile(fast, slow)).unwrap();
    let mut child = std::process::Command::new(bin)
        .arg("-conf")
        .arg(dir.join("Corefile"))
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if TcpStream::connect(localhost(slow)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let got = scenarios(fast, slow).await;
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(got, want());
}
