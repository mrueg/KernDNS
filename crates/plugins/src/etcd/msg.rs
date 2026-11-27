//! SkyDNS records in etcd, like CoreDNS's `plugin/etcd/msg`: the JSON
//! encoding of a [`Service`], the etcd key of a name, and `Group`.

use std::fmt;

use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};

use crate::backend::Service;

/// `json.Unmarshal(value, &msg.Service{})`: fields are matched without
/// regard to case, unknown ones are ignored, `null` leaves a field (or the
/// whole service) unset, and a value of the wrong type is an error.
pub fn decode_service(b: &[u8]) -> Result<Service, String> {
    let mut de = serde_json::Deserializer::from_slice(b);
    let s = de.deserialize_any(ServiceVisitor).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(s)
}

struct ServiceVisitor;

impl<'de> Visitor<'de> for ServiceVisitor {
    type Value = Service;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a SkyDNS service object")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Service, E> {
        Ok(Service::default())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Service, A::Error> {
        let mut s = Service::default();
        while let Some(k) = map.next_key::<String>()? {
            let k = k.to_ascii_lowercase();
            match k.as_str() {
                "host" => set(&mut s.host, map.next_value()?),
                "text" => set(&mut s.text, map.next_value()?),
                "group" => set(&mut s.group, map.next_value()?),
                // Go's int is 64 bits; the record fields take the low bits
                // when they are used, as Go's uint16 conversions do
                "port" => set(&mut s.port, map.next_value::<Option<i64>>()?.map(|v| v as i32)),
                "priority" => set(&mut s.priority, map.next_value::<Option<i64>>()?.map(|v| v as i32)),
                "weight" => set(&mut s.weight, map.next_value::<Option<i64>>()?.map(|v| v as i32)),
                "targetstrip" => set(
                    &mut s.target_strip,
                    map.next_value::<Option<i64>>()?.map(|v| v.max(0) as usize),
                ),
                "mail" => set(&mut s.mail, map.next_value()?),
                "ttl" => set(&mut s.ttl, map.next_value()?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(s)
    }
}

fn set<T>(field: &mut T, v: Option<T>) {
    if let Some(v) = v {
        *field = v;
    }
}

/// `dns.SplitDomainName`: the labels of a name, escapes kept as written.
pub fn split_domain_name(s: &str) -> Vec<&str> {
    let s = s.strip_suffix('.').filter(|_| !s.ends_with("\\.")).unwrap_or(s);
    if s.is_empty() {
        return Vec::new();
    }
    let b = s.as_bytes();
    let mut out = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'.' => {
                out.push(&s[start..i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    out.push(&s[start.min(s.len())..]);
    out
}

/// Go's `path.Clean`.
pub fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|l| *l != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// `path.Join("/" + prefix + "/", labels...)`.
fn join(prefix: &str, labels: &[&str]) -> String {
    let mut p = format!("/{prefix}/");
    for l in labels {
        p.push('/');
        p.push_str(l);
    }
    clean(&p)
}

/// `msg.Path`: the etcd key of a name, e.g. `/skydns/local/skydns/x`.
pub fn path(name: &str, prefix: &str) -> String {
    let mut l = split_domain_name(name);
    l.reverse();
    join(prefix, &l)
}

/// `msg.PathWithWildcard`: like [`path`], but cut at the first `*` or `any`
/// label, and whether it was cut.
pub fn path_with_wildcard(name: &str, prefix: &str) -> (String, bool) {
    let mut l = split_domain_name(name);
    l.reverse();
    match l.iter().position(|k| *k == "*" || *k == "any") {
        Some(i) => (join(prefix, &l[..i]), true),
        None => (join(prefix, &l), false),
    }
}

/// `msg.Group`: if the service closest to the name (fewest slashes in its
/// key) has a group, keep only the services of that group and those
/// without one; if services on that level disagree, keep everything.
pub fn group(sx: Vec<Service>) -> Vec<Service> {
    let Some(first) = sx.first() else { return sx };
    let slashes_of = |s: &Service| s.key.matches('/').count();
    let mut group = first.group.clone();
    let mut slashes = slashes_of(first);
    // like Go, entries after a groupless shorter key keep length 0
    let mut length = vec![0; sx.len()];
    for (i, s) in sx.iter().enumerate() {
        let x = slashes_of(s);
        length[i] = x;
        if x < slashes {
            if s.group.is_empty() {
                break;
            }
            slashes = x;
            group = s.group.clone();
        }
    }
    if group.is_empty() {
        return sx;
    }
    let mut ret = Vec::new();
    for (i, s) in sx.iter().enumerate() {
        if s.group.is_empty() {
            ret.push(s.clone());
            continue;
        }
        if length[i] == slashes && s.group != group {
            return sx;
        }
        if s.group == group {
            ret.push(s.clone());
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{HostType, domain, split255};

    // msg/path_test.go
    #[test]
    fn test_path() {
        for prefix in ["mydns", "skydns"] {
            assert_eq!(
                path("service.staging.skydns.local.", prefix),
                format!("/{prefix}/local/skydns/staging/service")
            );
        }
        // a leading or trailing slash in the prefix is cleaned away
        assert_eq!(path("x.skydns.local.", "/skydns/"), "/skydns/local/skydns/x");
        assert_eq!(path(".", "skydns"), "/skydns");
    }

    #[test]
    fn test_domain() {
        assert_eq!(
            domain("/skydns/local/cluster/staging/service/"),
            "service.staging.cluster.local."
        );
        assert_eq!(
            domain("/skydns/local/cluster/staging/service"),
            "service.staging.cluster.local."
        );
    }

    #[test]
    fn test_path_with_wildcard() {
        assert_eq!(
            path_with_wildcard("*.region1.skydns.test.", "skydns"),
            ("/skydns/test/skydns/region1".to_string(), true)
        );
        assert_eq!(
            path_with_wildcard("prod.any.skydns.test.", "skydns"),
            ("/skydns/test/skydns".to_string(), true)
        );
        assert_eq!(
            path_with_wildcard("a.skydns.test.", "skydns"),
            ("/skydns/test/skydns/a".to_string(), false)
        );
    }

    #[test]
    fn test_split_domain_name() {
        assert_eq!(split_domain_name("a.b.c."), vec!["a", "b", "c"]);
        assert_eq!(split_domain_name("a\\.b.c"), vec!["a\\.b", "c"]);
        assert!(split_domain_name(".").is_empty());
        assert_eq!(clean("//skydns/../x/./y/"), "/x/y");
    }

    // msg/service_test.go
    #[test]
    fn test_split255() {
        assert_eq!(split255("abc"), vec![b"abc".to_vec()]);
        let mut s = "a".repeat(255);
        // CoreDNS adds an empty string after exactly 255 bytes
        assert_eq!(split255(&s).len(), 2);
        s.push('b');
        let xs = split255(&s);
        assert_eq!(xs.len(), 2);
        assert_eq!(xs[1], b"b");
        s.push_str(&"a".repeat(255));
        let xs = split255(&s);
        assert_eq!(xs.len(), 3);
        assert_eq!(xs[2], b"a");
    }

    #[test]
    fn test_target_strip_large_value_returns() {
        let s = Service {
            host: "b.z1.test.".into(),
            target_strip: usize::MAX >> 1,
            ..Default::default()
        };
        let r = s.new_srv("x.", 1);
        assert!(r.to_string().ends_with("b.z1.test."), "{r}");
    }

    fn sv(host: &str, group: &str, key: &str) -> Service {
        Service {
            host: host.into(),
            group: group.into(),
            key: key.into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_group() {
        // keys are in the wrong order, but for this test it does not matter
        let sx = group(vec![
            sv("127.0.0.1", "g1", "b/sub/dom1/skydns/test"),
            sv("127.0.0.2", "g2", "a/dom1/skydns/test"),
        ]);
        // the shortest key with a group wins
        assert_eq!(sx.len(), 1);
        assert_eq!(sx[0].key, "a/dom1/skydns/test");
        // groups disagree: nothing is dropped
        let sx = group(vec![
            sv("server1", "g1", "region1/skydns/test"),
            sv("server2", "g2", "region1/skydns/test"),
        ]);
        assert_eq!(sx.len(), 2);
        // group is g1: only the top-level one
        let sx = group(vec![
            sv("server1", "g1", "a/dom/region1/skydns/test"),
            sv("server2", "g2", "a/subdom/dom/region1/skydns/test"),
        ]);
        assert_eq!(sx.len(), 1);
        // groupless services are always included
        let sx = group(vec![
            sv("server1", "g1", "a/dom/region1/skydns/test"),
            sv("server2", "g2", "a/subdom/dom/region1/skydns/test"),
            sv("server2", "", "b/subdom/dom/region1/skydns/test"),
        ]);
        assert_eq!(sx.len(), 2);
        // empty group on the highest level: include that one too
        let sx = group(vec![
            sv("server1", "g1", "a/dom/region1/skydns/test"),
            sv("server1", "", "b/dom/region1/skydns/test"),
            sv("server2", "g2", "a/subdom/dom/region1/skydns/test"),
        ]);
        assert_eq!(sx.len(), 2);
        // ... and the rest of the group
        let sx = group(vec![
            sv("server1", "g5", "a/dom/region1/skydns/test"),
            sv("server1", "", "b/dom/region1/skydns/test"),
            sv("server2", "g5", "a/subdom/dom/region1/skydns/test"),
        ]);
        assert_eq!(sx.len(), 3);
        assert_eq!(group(vec![sv("server1", "g6", "a/dom/region1/skydns/test")]).len(), 1);
        assert_eq!(group(vec![sv("server1", "", "a/dom/region1/skydns/test")]).len(), 1);
    }

    // msg/type_test.go
    #[test]
    fn test_type() {
        let t = |host: &str, mail: bool, text: &str| {
            Service {
                host: host.into(),
                mail,
                text: text.into(),
                ..Default::default()
            }
            .host_type()
        };
        assert_eq!(t("example.org", false, ""), HostType::Cname);
        assert!(matches!(t("127.0.0.1", false, ""), HostType::A(_)));
        assert!(matches!(t("2000::3", false, ""), HostType::Aaaa(_)));
        assert_eq!(t("2000..3", false, ""), HostType::Cname);
        assert_eq!(t("127.0.0.257", false, ""), HostType::Cname);
        assert!(matches!(t("127.0.0.252", true, ""), HostType::A(_)));
        assert!(matches!(t("127.0.0.252", true, "a"), HostType::A(_)));
        assert!(matches!(t("127.0.0.254", false, "a"), HostType::A(_)));
    }

    #[test]
    fn json() {
        let s = decode_service(br#"{"host":"10.0.0.1","Port":8080,"PRIORITY":5,"weight":null,"x":[1,{}],"ttl":60,"mail":true,"targetstrip":1,"group":"g","text":"t"}"#).unwrap();
        assert_eq!(s.host, "10.0.0.1");
        assert_eq!((s.port, s.priority, s.weight, s.ttl), (8080, 5, 0, 60));
        assert!(s.mail);
        assert_eq!((s.target_strip, s.group.as_str(), s.text.as_str()), (1, "g", "t"));
        assert_eq!(decode_service(b"null").unwrap(), Service::default());
        // last one wins, like Go
        assert_eq!(decode_service(br#"{"host":"a","HOST":"b"}"#).unwrap().host, "b");
        for bad in [
            &br#"{"port":"80"}"#[..],
            br#"{"port":80.5}"#,
            br#"{"ttl":-1}"#,
            br#"{"ttl":4294967296}"#,
            br#"{"host":1}"#,
            br#"{"mail":"yes"}"#,
            br#""x""#,
            b"[]",
            b"{",
            br#"{} x"#,
        ] {
            assert!(decode_service(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
