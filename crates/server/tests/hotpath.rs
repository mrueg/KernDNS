//! Per-query CPU cost of the server path (parse, dispatch, plugin chain,
//! encode) without the network, for a few cheap chains. Run with
//! `cargo test --release -p kerndns-server --test hotpath -- --ignored --nocapture`.

use std::net::SocketAddr;
use std::time::Instant;

use kerndns_core::Protocol;
use kerndns_core::proto::op::{Edns, Message, MessageType, OpCode, Query};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_server::config::{Options, load};
use kerndns_server::dispatch::Dispatcher;
use kerndns_server::udp::handle;

fn packet(name: &str, t: RecordType) -> Vec<u8> {
    let mut m = Message::new(4242, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
    let mut e = Edns::new();
    e.set_max_payload(1232);
    m.edns = Some(e);
    m.to_vec().unwrap()
}

async fn measure(label: &str, corefile: &str, q: &[u8]) {
    measure_with(label, corefile, q, &kerndns_plugins::registry()).await
}

async fn measure_with(label: &str, corefile: &str, q: &[u8], registry: &kerndns_core::Registry) {
    measure_proto(label, corefile, q, registry, Protocol::Udp, 300_000).await
}

async fn measure_proto(
    label: &str,
    corefile: &str,
    q: &[u8],
    registry: &kerndns_core::Registry,
    proto: Protocol,
    default_n: usize,
) {
    if std::env::var("HOTPATH_ONLY").is_ok_and(|o| o != label) {
        return;
    }
    let registry = registry.clone();
    let plan = load(corefile, "bench", &registry, &Options::default()).unwrap();
    let l = &plan.listeners[0];
    let local: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let src: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let d = Dispatcher::new("dns://:53".into(), &l.zones, l.class_chaos, local, local);
    let n: usize = std::env::var("HOTPATH_N")
        .ok()
        .and_then(|n| n.parse().ok())
        .map_or(default_n, |n: usize| n * default_n / 300_000);
    for _ in 0..(n / 15).max(1) {
        assert!(!handle(&d, q, src, local, proto, Default::default()).await.is_empty());
    }
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(handle(&d, q, src, local, proto, Default::default()).await);
    }
    println!("{label:<24} {:>6.0} ns/query", t.elapsed().as_nanos() as f64 / n as f64);
}

#[tokio::test(flavor = "current_thread")]
#[ignore]
async fn hotpath() {
    let dir = std::env::temp_dir().join(format!("kerndns-hotpath-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let hosts = dir.join("hosts");
    let mut h = String::new();
    for i in 0..10_000 {
        h.push_str(&format!("10.0.{}.{} host{i}.example.org\n", i / 250, i % 250));
    }
    std::fs::write(&hosts, h).unwrap();
    let zone = dir.join("zone");
    let mut z = String::from(
        "example.org. 300 IN SOA ns.example.org. h.example.org. 1 60 60 60 60\nexample.org. 300 IN NS ns.example.org.\n",
    );
    for i in 0..10_000 {
        z.push_str(&format!("host{i}.example.org. 300 IN A 10.1.{}.{}\n", i / 250, i % 250));
    }
    std::fs::write(&zone, z).unwrap();

    let whoami = packet("example.org.", RecordType::A);
    let n = 300_000;
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(Message::from_vec(std::hint::black_box(&whoami)).unwrap());
    }
    println!("{:<24} {:>6.0} ns", "parse", t.elapsed().as_nanos() as f64 / n as f64);
    let m = Message::from_vec(&whoami).unwrap();
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(std::hint::black_box(&m).to_vec().unwrap());
    }
    println!("{:<24} {:>6.0} ns", "encode", t.elapsed().as_nanos() as f64 / n as f64);
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(std::hint::black_box(&m).clone());
    }
    println!(
        "{:<24} {:>6.0} ns",
        "clone msg",
        t.elapsed().as_nanos() as f64 / n as f64
    );
    let host = packet("host1234.example.org.", RecordType::A);
    measure("whoami", ".:53 {\n whoami\n}", &whoami).await;
    measure(
        "prometheus + whoami",
        ".:53 {\n prometheus 127.0.0.1:0\n whoami\n}",
        &whoami,
    )
    .await;
    measure(
        "hosts 10k",
        &format!(".:53 {{\n hosts {} {{\n fallthrough\n }}\n whoami\n}}", hosts.display()),
        &host,
    )
    .await;
    measure(
        "file 10k",
        &format!("example.org:53 {{\n file {}\n}}", zone.display()),
        &host,
    )
    .await;
    measure("cache (hit) + whoami", ".:53 {\n cache\n whoami\n}", &whoami).await;
    // the zone of bench/plugins/transfer/axfr.Corefile: 100 names, 136 records
    let small = dir.join("zone100");
    let mut z = String::from(
        "$ORIGIN example.org.\n$TTL 3600\n@ IN SOA ns1 hostmaster 2024010101 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.53\n*.wild IN A 192.0.2.99\n",
    );
    for i in 0..100 {
        z.push_str(&format!("www{i} IN A 10.0.0.{i}\n"));
        if i % 4 == 0 {
            z.push_str(&format!("www{i} IN AAAA fd00::{i:x}\n"));
        }
        if i % 10 == 0 {
            z.push_str(&format!("alias{i} IN CNAME www{i}\n"));
        }
    }
    std::fs::write(&small, z).unwrap();
    let axfr = packet("example.org.", RecordType::AXFR);
    measure_proto(
        "axfr 100 names (tcp)",
        &format!(
            "example.org:53 {{\n file {}\n transfer {{\n to *\n }}\n}}",
            small.display()
        ),
        &axfr,
        &kerndns_plugins::registry(),
        Protocol::Tcp,
        20_000,
    )
    .await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cost of a request crossing into Go and back, with the bridge library
/// from `cargo xtask build-bridge` (default plugins) in HOTPATH_BRIDGE:
///
/// `HOTPATH_BRIDGE=target/bridge/libkerndns_bridge.so cargo test --release
///  -p kerndns-server --test hotpath -- --ignored --nocapture bridge`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn bridge() {
    let Ok(path) = std::env::var("HOTPATH_BRIDGE") else {
        eprintln!("set HOTPATH_BRIDGE to the bridge library");
        return;
    };
    let q = packet("example.org.", RecordType::A);
    let rust = kerndns_plugins::registry();
    let b = kerndns_go_bridge::Bridge::load(std::path::Path::new(&path)).unwrap();
    let mut go = kerndns_plugins::registry();
    b.register(&mut go, &["whoami".to_string(), "metadata".to_string()]);
    let whoami = ".:53 {\n whoami\n}";
    measure_with("whoami (Rust)", whoami, &q, &rust).await;
    measure_with("whoami (Go, bridged)", whoami, &q, &go).await;
    // a Go plugin that calls next: metadata (Go) -> whoami (Rust)
    let mut mixed = rust.clone();
    b.register(&mut mixed, &["metadata".to_string()]);
    measure_with("metadata (Go) + whoami", ".:53 {\n metadata\n whoami\n}", &q, &mixed).await;
    measure_with("metadata + whoami (Rust)", ".:53 {\n metadata\n whoami\n}", &q, &rust).await;
    // the same through the synchronous mode; set_sync applies to plugins set
    // up from now on
    kerndns_go_bridge::set_sync(vec!["whoami".into(), "metadata".into()]);
    measure_with("whoami (Go, sync)", whoami, &q, &go).await;
    measure_with(
        "metadata (Go, sync) + whoami",
        ".:53 {\n metadata\n whoami\n}",
        &q,
        &mixed,
    )
    .await;
}
