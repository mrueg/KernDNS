//! Query-name parsing, a port of `plugin/kubernetes/parse.go`.
//!
//! `[[endpoint.]service.]namespace.svc|pod.zone` and the SRV form
//! `_port._protocol.service.namespace.svc.zone`.

use crate::Error;

pub const SVC: &str = "svc";
pub const POD: &str = "pod";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordRequest {
    pub port: String,
    pub protocol: String,
    pub endpoint: String,
    pub service: String,
    pub namespace: String,
    /// "svc" or "pod" (empty for the zone itself).
    pub pod_or_svc: String,
}

/// Labels of `name` before `zone` (both FQDNs), or `None` if `name` isn't in it.
pub fn trim_zone(name: &str, zone: &str) -> Option<String> {
    let (n, z) = (name.to_ascii_lowercase(), zone.to_ascii_lowercase());
    if n == z {
        return Some(String::new());
    }
    if z == "." {
        return Some(name.trim_end_matches('.').to_string());
    }
    n.strip_suffix(&format!(".{z}"))
        .map(|_| name[..name.len() - z.len() - 1].to_string())
}

fn strip_underscore(s: &str) -> String {
    s.strip_prefix('_').unwrap_or(s).to_string()
}

pub fn parse_request(name: &str, zone: &str) -> Result<RecordRequest, Error> {
    let mut r = RecordRequest::default();
    let base = trim_zone(name, zone).unwrap_or_default();
    if base.is_empty() || base == SVC || base == POD {
        return Ok(r);
    }
    let segs: Vec<&str> = base.split('.').filter(|s| !s.is_empty()).collect();
    let Some(mut last) = segs.len().checked_sub(1) else {
        return Ok(r);
    };
    r.pod_or_svc = segs[last].to_string();
    if r.pod_or_svc != POD && r.pod_or_svc != SVC {
        return Err(Error::InvalidRequest);
    }
    let Some(l) = last.checked_sub(1) else { return Ok(r) };
    last = l;
    r.namespace = segs[last].to_string();
    let Some(l) = last.checked_sub(1) else { return Ok(r) };
    last = l;
    r.service = segs[last].to_string();
    let Some(l) = last.checked_sub(1) else { return Ok(r) };
    last = l;
    match last {
        0 => r.endpoint = segs[0].to_string(),
        1 => {
            r.protocol = strip_underscore(segs[1]);
            r.port = strip_underscore(segs[0]);
        }
        _ => return Err(Error::InvalidRequest),
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests() {
        let z = "cluster.local.";
        let p = |n: &str| parse_request(n, z);
        assert_eq!(p("cluster.local.").unwrap(), RecordRequest::default());
        let r = p("_http._tcp.webs.mynamespace.svc.cluster.local.").unwrap();
        assert_eq!(
            (
                r.port.as_str(),
                r.protocol.as_str(),
                r.service.as_str(),
                r.namespace.as_str()
            ),
            ("http", "tcp", "webs", "mynamespace")
        );
        let r = p("ep-1.webs.mynamespace.svc.cluster.local.").unwrap();
        assert_eq!(r.endpoint, "ep-1");
        let r = p("10-0-0-1.mynamespace.pod.cluster.local.").unwrap();
        assert_eq!((r.service.as_str(), r.pod_or_svc.as_str()), ("10-0-0-1", "pod"));
        assert_eq!(p("webs.mynamespace.foo.cluster.local."), Err(Error::InvalidRequest));
        assert_eq!(p("a.b.c.d.mynamespace.svc.cluster.local."), Err(Error::InvalidRequest));
        assert_eq!(trim_zone("A.B.Cluster.Local.", z).unwrap(), "A.B");
    }
}
