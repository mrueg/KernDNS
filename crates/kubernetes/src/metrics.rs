//! The plugin's `coredns_kubernetes_*` metrics (`metrics.go`,
//! `object/metrics.go`).

use std::sync::LazyLock;
use std::time::{Duration, SystemTime};

use prometheus::{
    CounterVec, DEFAULT_BUCKETS, HistogramOpts, HistogramVec, Opts, exponential_buckets, register_counter_vec,
    register_histogram_vec,
};

fn histogram(name: &str, help: &str, buckets: Vec<f64>, labels: &[&str]) -> HistogramVec {
    register_histogram_vec!(
        HistogramOpts::new(name, help)
            .namespace("coredns")
            .subsystem("kubernetes")
            .buckets(buckets),
        labels
    )
    .expect("valid histogram")
}

/// The DNS programming latency SLI: how long after an EndpointSlice change
/// (its `endpoints.kubernetes.io/last-change-trigger-time`) the change
/// could be answered.
pub static DNS_PROGRAMMING_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    histogram(
        "dns_programming_duration_seconds",
        "Histogram of the time (in seconds) it took to program a dns instance.",
        // from 1 millisecond to ~17 minutes
        exponential_buckets(0.001, 2.0, 20).expect("valid buckets"),
        &["service_kind"],
    )
});

/// API server request latency by verb and host.
pub static REQUEST_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    histogram(
        "rest_client_request_duration_seconds",
        "Request latency in seconds. Broken down by verb and host.",
        DEFAULT_BUCKETS.to_vec(),
        &["verb", "host"],
    )
});

/// Time API server requests waited for the client side rate limiter.
pub static RATE_LIMITER_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    histogram(
        "rest_client_rate_limiter_duration_seconds",
        "Client side rate limiter latency in seconds. Broken down by verb and host.",
        DEFAULT_BUCKETS.to_vec(),
        &["verb", "host"],
    )
});

/// API server requests by status code, method and host.
pub static REQUEST_RESULT: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "rest_client_requests_total",
            "Number of HTTP requests, partitioned by status code, method, and host."
        )
        .namespace("coredns")
        .subsystem("kubernetes"),
        &["code", "method", "host"]
    )
    .expect("valid counter")
});

/// Register the metrics (CoreDNS registers them at init).
pub fn init() {
    LazyLock::force(&DNS_PROGRAMMING_LATENCY);
    LazyLock::force(&REQUEST_LATENCY);
    LazyLock::force(&RATE_LIMITER_LATENCY);
    LazyLock::force(&REQUEST_RESULT);
}

/// The annotation the EndpointSlice controller sets to the time of the
/// change that triggered an update.
pub const LAST_CHANGE_TRIGGER_TIME: &str = "endpoints.kubernetes.io/last-change-trigger-time";

/// `EndpointLatencyRecorder.record`: observe the latency of a change
/// triggered at `trigger` (RFC 3339) for a service that is `headless` or
/// not. Nothing for an unparseable trigger time.
pub fn record_programming_latency(trigger: &str, headless: bool, now: SystemTime) {
    let Some(t) = parse_rfc3339(trigger) else {
        kerndns_core::warning!(
            plugin = "kubernetes",
            "DnsProgrammingLatency cannot be calculated; invalid {LAST_CHANGE_TRIGGER_TIME:?} annotation RFC3339 value of {trigger:?}"
        );
        return;
    };
    let since = now.duration_since(t).unwrap_or(Duration::ZERO);
    let kind = if headless {
        "headless_with_selector"
    } else {
        "cluster_ip"
    };
    DNS_PROGRAMMING_LATENCY
        .with_label_values(&[kind])
        .observe(since.as_secs_f64());
}

/// Parse an RFC 3339 timestamp, like Go's `time.Parse(time.RFC3339Nano, s)`.
pub fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    let t: k8s_openapi::jiff::Timestamp = s.parse().ok()?;
    Some(SystemTime::from(t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn rfc3339() {
        let t = |s: &str| parse_rfc3339(s).map(|t| t.duration_since(UNIX_EPOCH).unwrap());
        assert_eq!(t("1970-01-01T00:00:00Z"), Some(Duration::ZERO));
        assert_eq!(t("2023-11-14T22:13:20Z"), Some(Duration::from_secs(1_700_000_000)));
        assert_eq!(
            t("2023-11-14T22:13:20.5Z"),
            Some(Duration::from_millis(1_700_000_000_500))
        );
        assert_eq!(t("2023-11-15T00:13:20+02:00"), Some(Duration::from_secs(1_700_000_000)));
        assert_eq!(t("wrong-value"), None);
    }

    /// object/metrics_test.go: a change 132s ago lands in the bucket up to
    /// 262.144s, a bad annotation is ignored.
    #[test]
    fn programming_latency() {
        init();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let before = |s: i64| {
            k8s_openapi::jiff::Timestamp::from_second(1_700_000_000 - s)
                .unwrap()
                .to_string()
        };
        let h = DNS_PROGRAMMING_LATENCY.with_label_values(&["headless_with_selector"]);
        let n0 = h.get_sample_count();
        record_programming_latency(&before(132), true, now);
        record_programming_latency("wrong-value", true, now);
        assert_eq!(h.get_sample_count(), n0 + 1);
        let c = DNS_PROGRAMMING_LATENCY.with_label_values(&["cluster_ip"]);
        let c0 = c.get_sample_count();
        record_programming_latency(&before(8), false, now);
        assert_eq!(c.get_sample_count(), c0 + 1);
    }
}
