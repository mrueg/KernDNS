//! Ported from `plugin/grpc/{grpc,proxy,setup,setup_policy}_test.go`
//! (`policy_test.go` is in `forward::policy`).

use std::convert::Infallible;
use std::sync::Mutex;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use kerndns_core::proto::op::{Message, MessageType, OpCode};
use kerndns_core::proto::rr::rdata::{A, TXT};
use kerndns_core::proto::rr::{Name, RData, Record, RecordType};

use super::*;
use crate::testutil::*;

/// `testServiceClient`: a canned answer or error.
struct Canned {
    packet: Option<Vec<u8>>,
    /// Deadlines of the calls seen (`deadlineCheckingClient`).
    deadlines: Arc<Mutex<Vec<Instant>>>,
}

#[async_trait]
impl DnsServiceClient for Canned {
    async fn query(&self, _: &[u8], deadline: Instant) -> Result<Vec<u8>, RpcError> {
        self.deadlines.lock().unwrap().push(deadline);
        self.packet
            .clone()
            .ok_or_else(|| RpcError::new(Code::UNKNOWN, "server error"))
    }
}

fn canned(packet: Option<Vec<u8>>) -> Arc<Proxy> {
    Arc::new(Proxy::new(
        "canned".into(),
        Box::new(Canned {
            packet,
            deadlines: Default::default(),
        }),
    ))
}

/// A NOERROR answer to `example.org. A`.
fn answer() -> Vec<u8> {
    let req = query("example.org.", RecordType::A, "10.0.0.1:53");
    let mut m = req.reply();
    m.answers.push(Record::from_rdata(
        Name::from_ascii("example.org.").unwrap(),
        3600,
        RData::A(A::new(127, 0, 0, 1)),
    ));
    m.to_vec().unwrap()
}

fn handler(proxies: Vec<Arc<Proxy>>, policy: Policy, fall: Fall, next: Next) -> Grpc {
    let mut core = GrpcCore::new(".");
    core.proxies = proxies;
    core.picker = Picker::new(policy);
    core.fall = fall;
    Grpc {
        core: Arc::new(core),
        next,
    }
}

// TestGRPC
#[tokio::test]
async fn grpc() {
    let ok = || canned(Some(answer()));
    let ko = || canned(None);
    let cases: Vec<(&str, Vec<Arc<Proxy>>, bool)> = vec![
        ("single_proxy_ok", vec![ok()], false),
        ("multiple_proxies_ok", vec![ok(), ok(), ok()], false),
        ("single_proxy_ko", vec![ko()], true),
        ("multiple_proxies_one_ko", vec![ok(), ko(), ok()], false),
        ("multiple_proxies_ko", vec![ko(), ko(), ko()], true),
    ];
    for (name, proxies, want_err) in cases {
        let g = handler(proxies, Policy::Random, Fall::default(), None);
        let (rc, w) = serve(&g, &query("example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(rc.is_err(), want_err, "{name}: {rc:?}");
        if !want_err {
            let m = w.msg().unwrap();
            assert_eq!(m.answers.len(), 1, "{name}");
            assert_eq!(m.metadata.id, 1, "{name}");
        }
    }
}

// TestGRPCFallthroughNoNext
#[tokio::test]
async fn fallthrough_no_next() {
    let mut fall = Fall::default();
    fall.set_zones_from_args(&[]);
    let g = handler(vec![], Policy::Random, fall, None);
    let (rc, w) = serve(&g, &query("test.example.org.", RecordType::A, "10.0.0.1:53")).await;
    let err = rc.unwrap_err();
    assert_eq!(err.rcode, ResponseCode::ServFail);
    assert!(!err.msg.contains("no next plugin found"), "{err}");
    assert!(!w.written());
}

#[tokio::test]
async fn fallthrough_nxdomain() {
    let nx = {
        let req = query("nx.example.org.", RecordType::A, "10.0.0.1:53");
        req.error_reply(ResponseCode::NXDomain).to_vec().unwrap()
    };
    let next = || {
        reply(|r: &Request| {
            let mut m = r.reply();
            m.metadata.authoritative = true;
            m
        })
    };
    // NXDOMAIN from the backend goes to the next plugin with fallthrough
    let mut fall = Fall::default();
    fall.set_zones_from_args(&["example.org".into()]);
    let g = handler(vec![canned(Some(nx.clone()))], Policy::Random, fall.clone(), next());
    let (rc, w) = serve(&g, &query("nx.example.org.", RecordType::A, "10.0.0.1:53")).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    assert!(w.msg().unwrap().metadata.authoritative);
    // ... and is returned without it, or outside its zones
    let g = handler(vec![canned(Some(nx))], Policy::Random, Fall::default(), next());
    let (_, w) = serve(&g, &query("nx.example.org.", RecordType::A, "10.0.0.1:53")).await;
    assert_eq!(w.msg().unwrap().metadata.response_code, ResponseCode::NXDomain);
    // all upstreams failing falls through too
    let g = handler(vec![canned(None)], Policy::Random, fall, next());
    let (rc, w) = serve(&g, &query("a.example.org.", RecordType::A, "10.0.0.1:53")).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    assert!(w.msg().unwrap().metadata.authoritative);
}

// the deadline part of TestGRPC_SpansOnErrorPath
#[tokio::test]
async fn deadline_on_every_attempt() {
    let seen: Arc<Mutex<Vec<Instant>>> = Default::default();
    let p = |packet| {
        Arc::new(Proxy::new(
            "p".into(),
            Box::new(Canned {
                packet,
                deadlines: seen.clone(),
            }),
        ))
    };
    let g = handler(
        vec![p(None), p(Some(answer()))],
        Policy::Sequential,
        Fall::default(),
        None,
    );
    let before = Instant::now();
    let (rc, _) = serve(&g, &query("example.org.", RecordType::A, "10.0.0.1:53")).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(
        seen.iter()
            .all(|d| *d > before && *d <= Instant::now() + DEFAULT_TIMEOUT)
    );
}

#[tokio::test]
async fn wrong_reply_is_formerr() {
    let other = query("example.net.", RecordType::A, "10.0.0.1:53")
        .reply()
        .to_vec()
        .unwrap();
    let g = handler(vec![canned(Some(other))], Policy::Random, Fall::default(), None);
    let (rc, w) = serve(&g, &query("example.org.", RecordType::A, "10.0.0.1:53")).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    assert_eq!(w.msg().unwrap().metadata.response_code, ResponseCode::FormErr);
}

#[tokio::test]
async fn except_and_from() {
    let mut core = GrpcCore::new("example.org.");
    core.ignored = vec!["internal.example.org.".into()];
    core.proxies = vec![canned(Some(answer()))];
    let g = Grpc {
        core: Arc::new(core),
        next: None,
    };
    // not ours, no next plugin: SERVFAIL
    let (rc, w) = serve(&g, &query("example.net.", RecordType::A, "10.0.0.1:53")).await;
    assert_eq!(rc.unwrap(), ResponseCode::ServFail);
    assert!(!w.written());
    let (rc, _) = serve(&g, &query("a.internal.example.org.", RecordType::A, "10.0.0.1:53")).await;
    assert_eq!(rc.unwrap(), ResponseCode::ServFail);
    let (rc, _) = serve(&g, &query("example.org.", RecordType::A, "10.0.0.1:53")).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
}

// TestProxy
#[tokio::test]
async fn proxy() {
    let req = query("example.org.", RecordType::A, "10.0.0.1:53");
    let deadline = Instant::now() + DEFAULT_TIMEOUT;
    assert!(canned(Some(answer())).query(&req, deadline).await.is_ok());
    assert!(canned(None).query(&req, deadline).await.is_err());
}

#[tokio::test]
async fn proxy_not_found_is_nxdomain() {
    struct NotFound;
    #[async_trait]
    impl DnsServiceClient for NotFound {
        async fn query(&self, _: &[u8], _: Instant) -> Result<Vec<u8>, RpcError> {
            Err(RpcError::new(Code::NOT_FOUND, "nope"))
        }
    }
    let p = Proxy::new("nf".into(), Box::new(NotFound));
    let req = query("example.org.", RecordType::A, "10.0.0.1:53");
    let m = p.query(&req, Instant::now() + DEFAULT_TIMEOUT).await.unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(m.queries, req.msg.queries);
}

// TestProxy_RejectsOversizedReply
#[tokio::test]
async fn proxy_rejects_oversized_reply() {
    let p = canned(Some(vec![0; MAX_DNS_MESSAGE_BYTES + 1]));
    let req = query("example.org.", RecordType::A, "10.0.0.1:53");
    let err = p.query(&req, Instant::now() + DEFAULT_TIMEOUT).await.unwrap_err();
    assert_eq!(err, GrpcError::TooLarge(MAX_DNS_MESSAGE_BYTES + 1));
}

// TestProxy_RejectsOversizedRequest
#[tokio::test]
async fn proxy_rejects_oversized_request() {
    let p = canned(Some(b"ok".to_vec()));
    let mut req = query("example.org.", RecordType::A, "10.0.0.1:53");
    let txt = Record::from_rdata(
        Name::from_ascii("example.org.").unwrap(),
        300,
        RData::TXT(
            TXT::try_from("very long text record to make the message oversized when packed".to_string()).unwrap(),
        ),
    );
    req.msg.additionals = vec![txt; 2000];
    let err = p.query(&req, Instant::now() + DEFAULT_TIMEOUT).await.unwrap_err();
    assert!(matches!(err, GrpcError::TooLarge(_)), "{err}");
}

/// `grpcDnsServiceServer`: answers every query with
/// `example.org. IN A 127.0.0.1`.
async fn serve_dns_service<S>(io: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
        let mut body = req.into_body().collect().await.unwrap().to_bytes();
        body.advance(5);
        let raw = kerndns_core::protobuf::decode_packet(&body).unwrap();
        let q = Message::from_vec(&raw).unwrap();
        let mut a = Message::new(q.metadata.id, MessageType::Response, OpCode::Query);
        a.queries = q.queries.clone();
        a.answers.push(Record::from_rdata(
            Name::from_ascii("example.org.").unwrap(),
            3600,
            RData::A(A::new(127, 0, 0, 1)),
        ));
        let pb = kerndns_core::protobuf::encode_packet(&a.to_vec().unwrap());
        let mut frame = vec![0];
        frame.extend_from_slice(&(pb.len() as u32).to_be_bytes());
        frame.extend_from_slice(&pb);
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        let body = Full::new(Bytes::from(frame)).with_trailers(async { Some(Ok(trailers)) });
        let mut resp = hyper::Response::new(body);
        resp.headers_mut()
            .insert("content-type", http::HeaderValue::from_static("application/grpc"));
        Ok::<_, Infallible>(resp)
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), svc)
        .await;
}

// TestProxyUnix
#[tokio::test]
async fn proxy_unix() {
    let dir = std::env::temp_dir().join(format!("kerndns-grpc-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("test.grpc");
    let _ = std::fs::remove_file(&path);
    let l = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(serve_dns_service(s));
        }
    });
    let core = with_controller("grpc", &format!("grpc . unix://{}", path.display()), parse_grpc).unwrap();
    assert_eq!(core.proxies[0].addr, format!("unix://{}", path.display()));
    let g = Grpc {
        core: Arc::new(core),
        next: None,
    };
    let (rc, w) = serve(&g, &query("example.org.", RecordType::A, "10.0.0.1:53")).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    assert_eq!(w.msg().unwrap().answers[0].name.to_ascii(), "example.org.");
    let _ = std::fs::remove_dir_all(&dir);
}

// TestShutdownClosesClientConnection
#[tokio::test]
async fn shutdown_closes_client_connection() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(serve_dns_service(s));
        }
    });
    let core = with_controller("grpc", &format!("grpc . {addr}"), parse_grpc).unwrap();
    let core = Arc::new(core);
    let g = Grpc {
        core: core.clone(),
        next: None,
    };
    let req = query("example.org.", RecordType::A, "10.0.0.1:53");
    let (rc, w) = serve(&g, &req).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    assert_eq!(w.msg().unwrap().metadata.response_code, ResponseCode::NoError);
    for p in &core.proxies {
        p.close();
    }
    let (rc, w) = serve(&g, &req).await;
    assert!(rc.is_err() && !w.written(), "connection still usable after shutdown");
}

fn parse(input: &str) -> Result<GrpcCore, String> {
    with_controller("grpc", input, parse_grpc).map_err(|e| e.to_string())
}

// TestSetup
#[test]
fn setup() {
    let ok = [
        ("grpc . 127.0.0.1", "."),
        ("grpc . 127.0.0.1 {\nexcept miek.nl\n}\n", "."),
        ("grpc . 127.0.0.1:53", "."),
        ("grpc . 127.0.0.1:8080", "."),
        ("grpc . [::1]:53", "."),
        ("grpc . [2003::1]:53", "."),
        ("grpc . unix:///var/run/g.sock", "."),
        ("grpc example.org 127.0.0.1", "example.org."),
    ];
    for (input, from) in ok {
        let g = parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(g.from, from, "{input}");
    }
    let g = parse("grpc . 127.0.0.1 {\nexcept miek.nl example.ORG\n}\n").unwrap();
    assert_eq!(g.ignored, ["miek.nl.", "example.org."]);
    assert_eq!(parse("grpc . 127.0.0.1").unwrap().proxies[0].addr, "127.0.0.1:53");
    assert_eq!(parse("grpc . [::1]").unwrap().proxies[0].addr, "[::1]:53");

    let bad = [
        ("grpc . a27.0.0.1", "not an IP"),
        ("grpc . 127.0.0.1 {\nblaatl\n}\n", "unknown property"),
        ("grpc . ::1\ngrpc com ::2", "plugin"),
        (
            "grpc xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 127.0.0.1",
            "unable to normalize 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
        ),
        ("grpc .", "Wrong argument count"),
        ("grpc . tls://127.0.0.1", "not supported"),
    ];
    for (input, want) in bad {
        let e = parse(input)
            .err()
            .unwrap_or_else(|| panic!("{input}: expected an error"));
        assert!(e.contains(want), "{input}: {e}");
    }
    assert!(setup_err(&Setup, "grpc . ::1\ngrpc com ::2").contains("only be used once"));
    let many: Vec<String> = (1..=16).map(|i| format!("127.0.0.{i}")).collect();
    assert!(
        parse(&format!("grpc . {}", many.join(" ")))
            .unwrap_err()
            .contains("more than 15 TOs")
    );
}

// TestSetupTLS
#[test]
fn setup_tls() {
    let g = parse("grpc . 127.0.0.1 {\ntls_servername dns\n}").unwrap();
    assert!(g.tls);
    assert_eq!(g.tls_server_name.as_deref(), Some("dns"));
    assert!(parse("grpc . 127.0.0.1 {\ntls\n}").unwrap().tls);
    assert!(!parse("grpc . 127.0.0.1").unwrap().tls);
    let e = parse("grpc . 127.0.0.1 {\ntls a b c d\n}").unwrap_err();
    assert!(e.contains("Wrong argument count"), "{e}");
}

// TestSetupResolvconf
#[test]
fn setup_resolvconf() {
    let path = std::env::temp_dir().join(format!("kerndns-grpc-resolv-{}.conf", std::process::id()));
    std::fs::write(&path, "nameserver 10.10.255.252\nnameserver 10.10.255.253").unwrap();
    let g = parse(&format!("grpc . {}", path.display())).unwrap();
    let _ = std::fs::remove_file(&path);
    let addrs: Vec<_> = g.proxies.iter().map(|p| p.addr.as_str()).collect();
    assert_eq!(addrs, ["10.10.255.252:53", "10.10.255.253:53"]);
}

// TestSetupFallthrough
#[test]
fn setup_fallthrough() {
    let zones = |input: &str| parse(input).unwrap().fall.zones;
    assert_eq!(zones("grpc . 127.0.0.1 {\n\tfallthrough\n}"), ["."]);
    assert_eq!(
        zones("grpc . 127.0.0.1 {\n\tfallthrough example.org\n}"),
        ["example.org."]
    );
    assert_eq!(
        zones("grpc . 127.0.0.1 {\n\tfallthrough example.org example.com\n}"),
        ["example.org.", "example.com."]
    );
    assert!(zones("grpc . 127.0.0.1").is_empty());
}

// TestSetupPolicy
#[test]
fn setup_policy() {
    for p in ["random", "round_robin", "sequential"] {
        let g = parse(&format!("grpc . 127.0.0.1 {{\npolicy {p}\n}}\n")).unwrap();
        assert_eq!(g.picker.policy.as_str(), p);
    }
    assert_eq!(parse("grpc . 127.0.0.1").unwrap().picker.policy, Policy::Random);
    let e = parse("grpc . 127.0.0.1 {\npolicy random2\n}\n").unwrap_err();
    assert!(e.contains("unknown policy"), "{e}");
}
