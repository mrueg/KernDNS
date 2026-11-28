//! A reload whose new configuration fails to start rolls back to the
//! running one, like caddy's `Instance.Restart`: the old listeners keep
//! answering with the old plugin chains throughout, the old
//! configuration's restart hooks (`OnRestart`: `health`, `ready` and
//! `prometheus` stop their endpoints) are undone by its restart-failed
//! hooks (`OnRestartFailed`: they start them again), the new
//! configuration's shutdown hooks release what its startup took, and its
//! global state (readiness checks, `reload` interval) is replaced by the
//! old one's again. Its own test binary, as that state is process-wide.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_core::{readiness, reload};
use kerndns_server::{Instance, Options, StartError, load};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The rcode for `whoami.example.org. A` over UDP, or `None` on timeout.
async fn rcode(port: u16, id: u16) -> Option<ResponseCode> {
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(
        Name::from_ascii("whoami.example.org.").unwrap(),
        RecordType::A,
    ));
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&m.to_vec().unwrap(), SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .unwrap();
    let mut buf = vec![0; 4096];
    let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    let r = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(r.metadata.id, id);
    Some(r.metadata.response_code)
}

/// Status code of `GET path` on `127.0.0.1:port`, `None` if nothing listens.
async fn http_status(port: u16, path: &str) -> Option<u16> {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.ok()?;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut resp))
        .await
        .ok()?
        .ok()?;
    let head = String::from_utf8_lossy(&resp);
    head.split_whitespace().nth(1)?.parse().ok()
}

/// Query `port` in a loop until stopped; counts answers and misses.
struct Hammer {
    stop: Arc<AtomicBool>,
    ok: Arc<AtomicUsize>,
    missed: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Hammer {
    fn start(port: u16) -> Self {
        let (stop, ok, missed) = (Arc::new(AtomicBool::new(false)), Arc::default(), Arc::default());
        let (s, o, m): (Arc<AtomicBool>, Arc<AtomicUsize>, Arc<AtomicUsize>) =
            (stop.clone(), Arc::clone(&ok), Arc::clone(&missed));
        let task = tokio::spawn(async move {
            let mut id = 0u16;
            while !s.load(Ordering::Relaxed) {
                id = id.wrapping_add(1);
                match rcode(port, id).await {
                    Some(ResponseCode::NoError) => o.fetch_add(1, Ordering::Relaxed),
                    _ => m.fetch_add(1, Ordering::Relaxed),
                };
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        });
        Hammer { stop, ok, missed, task }
    }

    async fn finish(self) -> (usize, usize) {
        self.stop.store(true, Ordering::Relaxed);
        self.task.await.unwrap();
        (self.ok.load(Ordering::Relaxed), self.missed.load(Ordering::Relaxed))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_reload_rolls_back_to_running_config() {
    let registry = kerndns_plugins::registry();
    let opts = Options::default();
    let (dns, dns2) = (free_port(), free_port());
    let (health, ready, prom) = (free_port(), free_port(), free_port());

    // the running configuration: answers whoami.example.org
    let running = format!(
        ".:{dns} {{\n bind 127.0.0.1\n reload 2s 0s\n ready 127.0.0.1:{ready}\n health 127.0.0.1:{health}\n prometheus 127.0.0.1:{prom}\n whoami\n}}\n"
    );
    let plan = load(&running, "Corefile", &registry, &opts).unwrap();
    let mut inst = Instance::start_plan(plan).await.unwrap();
    assert_eq!(rcode(dns, 1).await, Some(ResponseCode::NoError));
    assert_eq!(http_status(health, "/health").await, Some(200));
    assert_eq!(http_status(ready, "/ready").await, Some(200));
    assert_eq!(http_status(prom, "/metrics").await, Some(200));
    assert_eq!(reload::interval(), Some(Duration::from_secs(2)));

    // 1. a startup hook fails: pprof can't bind an address held without
    // SO_REUSEPORT. Its block only serves example.net (so whoami.example.org
    // would be REFUSED), adds a listener and a not-ready plugin, drops
    // `reload`, and moves health to a new address, started (by the hooks
    // before pprof's) and then released again.
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_port = busy.local_addr().unwrap().port();
    let health2 = free_port();
    let failing = format!(
        "example.net:{dns} {{\n bind 127.0.0.1\n ready 127.0.0.1:{ready}\n health 127.0.0.1:{health2}\n pprof 127.0.0.1:{busy_port}\n prometheus 127.0.0.1:{prom}\n erratic\n whoami\n}}\n.:{dns2} {{\n bind 127.0.0.1\n whoami\n}}\n"
    );
    let plan = load(&failing, "Corefile", &registry, &opts).unwrap();
    assert_eq!(reload::interval(), None, "the failing plan's setup ran");
    let hammer = Hammer::start(dns);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let err = inst.reload(plan).await.unwrap_err();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (ok, missed) = hammer.finish().await;
    assert!(matches!(err, StartError::Other(_)), "{err:?}");
    assert!(err.to_string().starts_with("plugin/pprof: "), "{err}");
    assert!(ok > 10, "{ok} answers");
    assert_eq!(missed, 0, "old listener missed queries during the failed reload");

    // the old chains, listeners, endpoints and global state are back
    assert_eq!(rcode(dns, 2).await, Some(ResponseCode::NoError));
    assert_eq!(rcode(dns2, 3).await, None, "the new listener was not kept");
    assert_eq!(inst.listeners().len(), 1);
    assert_eq!(http_status(health, "/health").await, Some(200));
    assert_eq!(
        http_status(health2, "/health").await,
        None,
        "the new health endpoint was stopped"
    );
    assert_eq!(
        http_status(ready, "/ready").await,
        Some(200),
        "readiness is the old config's"
    );
    assert_eq!(http_status(prom, "/metrics").await, Some(200));
    assert_eq!(readiness::ready(), (true, vec![]));
    assert_eq!(reload::interval(), Some(Duration::from_secs(2)));

    // 2. a new listener's address is taken (a UDP socket without
    // SO_REUSEPORT): the bind fails after the startup hooks ran
    let taken = std::net::UdpSocket::bind(("127.0.0.1", dns2)).unwrap();
    let health3 = free_port();
    let unbindable = format!(
        ".:{dns} {{\n bind 127.0.0.1\n health 127.0.0.1:{health3}\n whoami\n}}\n.:{dns2} {{\n bind 127.0.0.1\n whoami\n}}\n"
    );
    let plan = load(&unbindable, "Corefile", &registry, &opts).unwrap();
    let hammer = Hammer::start(dns);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let err = inst.reload(plan).await.unwrap_err();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (ok, missed) = hammer.finish().await;
    assert!(matches!(err, StartError::Bind { .. }), "{err:?}");
    assert!(ok > 10, "{ok} answers");
    assert_eq!(missed, 0, "old listener missed queries during the failed reload");
    assert_eq!(rcode(dns, 4).await, Some(ResponseCode::NoError));
    assert_eq!(
        http_status(health3, "/health").await,
        None,
        "the new health endpoint was stopped"
    );
    assert_eq!(http_status(health, "/health").await, Some(200));
    assert_eq!(http_status(ready, "/ready").await, Some(200));
    assert_eq!(http_status(prom, "/metrics").await, Some(200));
    assert_eq!(reload::interval(), Some(Duration::from_secs(2)));
    drop(taken);

    // 3. a good reload still switches: example.net only, endpoints moved
    let good = format!(
        "example.net:{dns} {{\n bind 127.0.0.1\n ready 127.0.0.1:{ready}\n health 127.0.0.1:{health2}\n prometheus 127.0.0.1:{prom}\n whoami\n}}\n"
    );
    let plan = load(&good, "Corefile", &registry, &opts).unwrap();
    inst.reload(plan).await.unwrap();
    assert_eq!(rcode(dns, 5).await, Some(ResponseCode::Refused));
    assert_eq!(http_status(health2, "/health").await, Some(200));
    assert_eq!(
        http_status(health, "/health").await,
        None,
        "the old health endpoint is gone"
    );
    assert_eq!(http_status(ready, "/ready").await, Some(200));
    assert_eq!(http_status(prom, "/metrics").await, Some(200));
    assert_eq!(reload::interval(), None);

    inst.stop().await;
    assert_eq!(http_status(ready, "/ready").await, None);
    assert_eq!(http_status(prom, "/metrics").await, None);
    drop(busy);
}
