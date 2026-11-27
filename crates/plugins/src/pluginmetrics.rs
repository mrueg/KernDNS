//! Plugin-specific Prometheus metrics, with CoreDNS's names and labels.

use std::sync::LazyLock;

use prometheus::{
    CounterVec, GaugeVec, HistogramOpts, HistogramVec, IntCounter, Opts, register_counter_vec, register_gauge_vec,
    register_histogram_vec, register_int_counter,
};

fn counter(subsystem: &str, name: &str, help: &str, labels: &[&str]) -> CounterVec {
    register_counter_vec!(Opts::new(name, help).namespace("coredns").subsystem(subsystem), labels).unwrap()
}

fn gauge(subsystem: &str, name: &str, help: &str, labels: &[&str]) -> GaugeVec {
    register_gauge_vec!(Opts::new(name, help).namespace("coredns").subsystem(subsystem), labels).unwrap()
}

// cache
pub static CACHE_ENTRIES: LazyLock<GaugeVec> = LazyLock::new(|| {
    gauge(
        "cache",
        "entries",
        "The number of elements in the cache.",
        &["server", "type", "zones", "view"],
    )
});
pub static CACHE_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "cache",
        "requests_total",
        "The count of cache requests.",
        &["server", "zones", "view"],
    )
});
pub static CACHE_HITS: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "cache",
        "hits_total",
        "The count of cache hits.",
        &["server", "type", "zones", "view"],
    )
});
pub static CACHE_MISSES: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "cache",
        "misses_total",
        "The count of cache misses. Deprecated, derive misses from cache hits/requests counters.",
        &["server", "zones", "view"],
    )
});
pub static CACHE_PREFETCHES: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "cache",
        "prefetch_total",
        "The number of times the cache has prefetched a cached item.",
        &["server", "zones", "view"],
    )
});
pub static CACHE_DROPS: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "cache",
        "drops_total",
        "The number responses that are not cached, because the reply is malformed.",
        &["server", "zones", "view"],
    )
});
pub static CACHE_SERVED_STALE: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "cache",
        "served_stale_total",
        "The number of requests served from stale cache entries.",
        &["server", "zones", "view"],
    )
});
pub static CACHE_EVICTIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "cache",
        "evictions_total",
        "The count of cache evictions.",
        &["server", "type", "zones", "view"],
    )
});

// dnssec
pub static DNSSEC_CACHE_ENTRIES: LazyLock<GaugeVec> = LazyLock::new(|| {
    gauge(
        "dnssec",
        "cache_entries",
        "The number of elements in the dnssec cache.",
        &["server", "type"],
    )
});
pub static DNSSEC_CACHE_HITS: LazyLock<CounterVec> =
    LazyLock::new(|| counter("dnssec", "cache_hits_total", "The count of cache hits.", &["server"]));
pub static DNSSEC_CACHE_MISSES: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "dnssec",
        "cache_misses_total",
        "The count of cache misses.",
        &["server"],
    )
});

// forward / proxy
pub static PROXY_REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new("request_duration_seconds", "Histogram of the time each request took.")
            .namespace("coredns")
            .subsystem("proxy")
            .buckets(kerndns_core::metrics::time_buckets()),
        &["proxy_name", "to", "rcode"]
    )
    .unwrap()
});
pub static PROXY_HC_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "proxy",
        "healthcheck_failures_total",
        "Counter of the number of failed healthchecks.",
        &["proxy_name", "to"],
    )
});
pub static FORWARD_HC_BROKEN: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        Opts::new(
            "healthcheck_broken_total",
            "Counter of the number of complete failures of the healthchecks."
        )
        .namespace("coredns")
        .subsystem("forward")
    )
    .unwrap()
});
pub static FORWARD_MAX_CONCURRENT_REJECTS: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        Opts::new(
            "max_concurrent_rejects_total",
            "Counter of the number of queries rejected because the concurrent queries were at maximum."
        )
        .namespace("coredns")
        .subsystem("forward")
    )
    .unwrap()
});

// grpc
pub static GRPC_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "grpc",
        "requests_total",
        "Counter of requests made per upstream.",
        &["to"],
    )
});
pub static GRPC_RESPONSES: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "grpc",
        "responses_total",
        "Counter of requests made per upstream.",
        &["rcode", "to"],
    )
});
pub static GRPC_REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new("request_duration_seconds", "Histogram of the time each request took.")
            .namespace("coredns")
            .subsystem("grpc")
            .buckets(kerndns_core::metrics::time_buckets()),
        &["to"]
    )
    .unwrap()
});

// hosts
pub static HOSTS_ENTRIES: LazyLock<GaugeVec> = LazyLock::new(|| {
    gauge(
        "hosts",
        "entries",
        "The combined number of entries in hosts and Corefile.",
        &["hostsfile"],
    )
});
pub static HOSTS_RELOAD_TIME: LazyLock<GaugeVec> = LazyLock::new(|| {
    gauge(
        "hosts",
        "reload_timestamp_seconds",
        "The timestamp of the last reload of hosts file.",
        &[],
    )
});

// acl
fn acl(name: &str, help: &str, labels: &[&str]) -> CounterVec {
    counter("acl", name, help, labels)
}
pub static ACL_BLOCKED: LazyLock<CounterVec> = LazyLock::new(|| {
    acl(
        "blocked_requests_total",
        "Counter of DNS requests being blocked.",
        &["server", "zone", "view"],
    )
});
pub static ACL_FILTERED: LazyLock<CounterVec> = LazyLock::new(|| {
    acl(
        "filtered_requests_total",
        "Counter of DNS requests being filtered.",
        &["server", "zone", "view"],
    )
});
pub static ACL_ALLOWED: LazyLock<CounterVec> = LazyLock::new(|| {
    acl(
        "allowed_requests_total",
        "Counter of DNS requests being allowed.",
        &["server", "view"],
    )
});
pub static ACL_DROPPED: LazyLock<CounterVec> = LazyLock::new(|| {
    acl(
        "dropped_requests_total",
        "Counter of DNS requests being dropped.",
        &["server", "zone", "view"],
    )
});

// local
pub static LOCALHOST_REQUESTS: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        Opts::new(
            "localhost_requests_total",
            "Counter of special localhost subdomain requests."
        )
        .namespace("coredns")
        .subsystem("local")
    )
    .unwrap()
});

// template
pub static TEMPLATE_MATCHES: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "template",
        "matches_total",
        "Counter of template regex matches.",
        &["server", "zone", "view", "class", "type"],
    )
});
pub static TEMPLATE_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "template",
        "template_failures_total",
        "Counter of go template failures.",
        &["server", "zone", "view", "class", "type", "section", "template"],
    )
});
pub static TEMPLATE_RR_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "template",
        "rr_failures_total",
        "Counter of mis-templated RRs.",
        &["server", "zone", "view", "class", "type", "section", "template"],
    )
});

// autopath
pub static AUTOPATH_SUCCESS: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "autopath",
        "success_total",
        "Counter of requests that did autopath.",
        &["server"],
    )
});

// dns64
pub static DNS64_REQUESTS_TRANSLATED: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "dns64",
        "requests_translated_total",
        "Counter of DNS requests translated by dns64.",
        &["server"],
    )
});

// shed
pub static SHED_DROPPED: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "shed",
        "dropped_total",
        "Counter of queries and responses dropped, per server, by reason.",
        &["server", "reason"],
    )
});

// siit
pub static SIIT_REQUESTS_TRANSLATED: LazyLock<CounterVec> = LazyLock::new(|| {
    counter(
        "siit",
        "requests_translated_total",
        "Counter of DNS requests translated by siit.",
        &["server"],
    )
});
