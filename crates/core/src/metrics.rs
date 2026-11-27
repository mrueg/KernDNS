//! Prometheus metrics with CoreDNS's names, labels and buckets
//! (`plugin/metrics/vars`), so dashboards and alerts keep working.
//!
//! Everything registers in the process-wide default registry; the
//! `prometheus` plugin serves it.

use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use prometheus::{
    CounterVec, GaugeVec, HistogramOpts, HistogramVec, IntCounter, Opts, exponential_buckets, register_counter_vec,
    register_gauge_vec, register_histogram_vec, register_int_counter,
};

use crate::request::Request;

/// Zone label for requests the server answered itself (no matching zone).
pub const DROPPED: &str = "dropped";

/// From 0.25 ms to 8 s (`plugin.TimeBuckets`).
pub fn time_buckets() -> Vec<f64> {
    exponential_buckets(0.00025, 2.0, 16).expect("valid buckets")
}

/// From 0.25 ms to 2.5 s (`plugin.SlimTimeBuckets`).
pub fn slim_time_buckets() -> Vec<f64> {
    exponential_buckets(0.00025, 10.0, 5).expect("valid buckets")
}

const SIZE_BUCKETS: &[f64] = &[
    0.0, 100.0, 200.0, 300.0, 400.0, 511.0, 1023.0, 2047.0, 4095.0, 8291.0, 16e3, 32e3, 48e3, 64e3,
];

pub static REQUEST_COUNT: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "requests_total",
            "Counter of DNS requests made per zone, protocol and family."
        )
        .namespace("coredns")
        .subsystem("dns"),
        &["server", "zone", "view", "proto", "family", "type"]
    )
    .unwrap()
});

pub static REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "request_duration_seconds",
            "Histogram of the time (in seconds) each request took per zone."
        )
        .namespace("coredns")
        .subsystem("dns")
        .buckets(time_buckets()),
        &["server", "zone", "view"]
    )
    .unwrap()
});

pub static REQUEST_SIZE: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "request_size_bytes",
            "Size of the EDNS0 UDP buffer in bytes (64K for TCP) per zone and protocol."
        )
        .namespace("coredns")
        .subsystem("dns")
        .buckets(SIZE_BUCKETS.to_vec()),
        &["server", "zone", "view", "proto"]
    )
    .unwrap()
});

pub static REQUEST_DO: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new("do_requests_total", "Counter of DNS requests with DO bit set per zone.")
            .namespace("coredns")
            .subsystem("dns"),
        &["server", "zone", "view"]
    )
    .unwrap()
});

pub static RESPONSE_SIZE: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new("response_size_bytes", "Size of the returned response in bytes.")
            .namespace("coredns")
            .subsystem("dns")
            .buckets(SIZE_BUCKETS.to_vec()),
        &["server", "zone", "view", "proto"]
    )
    .unwrap()
});

pub static RESPONSE_RCODE: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new("responses_total", "Counter of response status codes.")
            .namespace("coredns")
            .subsystem("dns"),
        &["server", "zone", "view", "rcode", "plugin"]
    )
    .unwrap()
});

pub static PANICS: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(Opts::new("panics_total", "A metrics that counts the number of panics.").namespace("coredns"))
        .unwrap()
});

pub static PLUGIN_ENABLED: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "plugin_enabled",
            "A metric that indicates whether a plugin is enabled on per server and zone basis."
        )
        .namespace("coredns"),
        &["server", "zone", "view", "name"]
    )
    .unwrap()
});

pub static BUILD_INFO: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new("build_info", "A metric with a constant '1' value labeled by version, revision, and goversion from which CoreDNS was built.")
            .namespace("coredns"),
        &["version", "revision", "goversion"]
    )
    .unwrap()
});

/// Response code names as miekg/dns prints them.
pub fn rcode_string(rc: ResponseCode) -> String {
    match rc {
        ResponseCode::NoError => "NOERROR".into(),
        ResponseCode::FormErr => "FORMERR".into(),
        ResponseCode::ServFail => "SERVFAIL".into(),
        ResponseCode::NXDomain => "NXDOMAIN".into(),
        ResponseCode::NotImp => "NOTIMP".into(),
        ResponseCode::Refused => "REFUSED".into(),
        ResponseCode::YXDomain => "YXDOMAIN".into(),
        ResponseCode::YXRRSet => "YXRRSET".into(),
        ResponseCode::NXRRSet => "NXRRSET".into(),
        ResponseCode::NotAuth => "NOTAUTH".into(),
        ResponseCode::NotZone => "NOTZONE".into(),
        ResponseCode::BADVERS => "BADVERS".into(),
        other => u16::from(other).to_string(),
    }
}

/// Query types reported by name; everything else is "other".
fn qtype_string(t: RecordType) -> String {
    use RecordType::*;
    match t {
        AAAA | A | CNAME | DNSKEY | DS | MX | NSEC3 | NSEC | NS | PTR | RRSIG | SOA | SRV | TXT | HTTPS | SVCB
        | IXFR | AXFR | ANY => t.to_string(),
        _ => "other".into(),
    }
}

/// Record one request, like `vars.Report`.
#[allow(clippy::too_many_arguments)]
pub fn report(
    server: &str,
    req: &Request,
    zone: &str,
    view: &str,
    rcode: ResponseCode,
    plugin: &str,
    size: usize,
    start: Instant,
) {
    let proto = req.proto();
    let family = if req.family() == 2 { "2" } else { "1" };
    if req.do_bit() {
        REQUEST_DO.with_label_values(&[server, zone, view]).inc();
    }
    let qtype = if req.msg.queries.is_empty() {
        "other".to_string()
    } else {
        qtype_string(req.qtype())
    };
    REQUEST_COUNT
        .with_label_values(&[server, zone, view, proto, family, &qtype])
        .inc();
    REQUEST_DURATION
        .with_label_values(&[server, zone, view])
        .observe(start.elapsed().as_secs_f64());
    RESPONSE_SIZE
        .with_label_values(&[server, zone, view, proto])
        .observe(size as f64);
    let req_len = match &req.wire {
        Some(w) => w.len(),
        None => crate::wire::to_wire(&req.msg).map(|v| v.len()).unwrap_or(0),
    };
    REQUEST_SIZE
        .with_label_values(&[server, zone, view, proto])
        .observe(req_len as f64);
    RESPONSE_RCODE
        .with_label_values(&[server, zone, view, &rcode_string(rcode), plugin])
        .inc();
}

/// All metrics, in the protobuf exposition format if `accept` asks for
/// it (as Prometheus and client_golang's scrapers do), else in text.
/// Returns (content type, body).
pub fn gather(accept: &str) -> (String, Vec<u8>) {
    use prometheus::Encoder;
    LazyLock::force(&BUILD_INFO)
        .with_label_values(&[crate::VERSION, "", "rust"])
        .set(1.0);
    let families = prometheus::gather();
    let mut buf = Vec::new();
    if accept.contains("application/vnd.google.protobuf") && accept.contains("encoding=delimited") {
        let enc = prometheus::ProtobufEncoder::new();
        if enc.encode(&families, &mut buf).is_ok() {
            return (enc.format_type().to_string(), buf);
        }
        buf.clear();
    }
    let enc = prometheus::TextEncoder::new();
    let _ = enc.encode(&families, &mut buf);
    (enc.format_type().to_string(), buf)
}

static LISTEN_ADDRS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Remember where a metrics endpoint listens (reported for tests).
pub fn add_listen_addr(addr: String) {
    LISTEN_ADDRS.lock().unwrap().push(addr);
}

pub fn listen_addrs() -> Vec<String> {
    LISTEN_ADDRS.lock().unwrap().clone()
}
