//! `chaos`: answers CH-class TXT queries for the server's version, authors
//! and hostname. Port of `plugin/chaos`.
//!
//! The version is `KernDNS-<version>`: KernDNS reports its own name, not
//! CoreDNS's. CoreDNS builds it from `caddy.AppName` and `caddy.AppVersion`,
//! which the program embedding CoreDNS sets; KernDNS takes a replacement
//! from `$KERNDNS_CHAOS_VERSION` (the compatibility tests set it to their
//! own `caddy.AppName-caddy.AppVersion`).

use std::sync::Arc;

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::rdata::TXT;
use kerndns_core::proto::rr::{DNSClass, RData, Record, RecordType};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure,
};
use rand::seq::SliceRandom;

/// Default answer for `authors.bind.`.
pub const OWNERS: &[&str] = &["The KernDNS authors"];

pub fn default_version() -> String {
    version_or_default(std::env::var("KERNDNS_CHAOS_VERSION").ok())
}

fn version_or_default(env: Option<String>) -> String {
    env.filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("KernDNS-{}", kerndns_core::VERSION))
}

/// TXT strings are limited to 255 bytes.
fn trim(s: &str) -> String {
    let mut end = s.len().min(255);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "chaos"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut version = String::new();
        let mut authors: Vec<String> = OWNERS.iter().map(|s| s.to_string()).collect();
        if c.next() {
            let args = c.remaining_args();
            match args.len() {
                0 => version = trim(&default_version()),
                1 => version = trim(&args[0]),
                _ => {
                    version = args[0].clone();
                    let mut list: Vec<String> = args[1..].iter().map(|a| trim(a)).collect();
                    list.sort();
                    list.dedup();
                    authors = list;
                }
            }
            if c.next_block() {
                let msg = format!("unknown property '{}'", c.val());
                return Err(c.errf(msg));
            }
        }
        let (version, authors) = (Arc::new(version), Arc::new(authors));
        c.add_plugin(move |next| {
            Arc::new(Chaos {
                next,
                version: version.clone(),
                authors: authors.clone(),
            })
        });
        Ok(())
    }
}

pub struct Chaos {
    next: Next,
    version: Arc<String>,
    authors: Arc<Vec<String>>,
}

#[async_trait]
impl Handler for Chaos {
    fn name(&self) -> &'static str {
        "chaos"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        if req.qclass() != DNSClass::CH || req.qtype() != RecordType::TXT {
            return next_or_failure("chaos", &self.next, ctx, w, req).await;
        }
        let txt = |s: &str| {
            let mut r = Record::from_rdata(
                req.qname().clone(),
                0,
                RData::TXT(TXT::try_new(std::iter::once(s.as_bytes().to_vec())).expect("trimmed to 255 bytes")),
            );
            r.dns_class = DNSClass::CH;
            r
        };
        let mut m = req.reply();
        match req.name().as_str() {
            "authors.bind." => {
                let mut order: Vec<usize> = (0..self.authors.len()).collect();
                // CoreDNS: rnd.Perm(len(c.Authors))
                order.shuffle(&mut rand::rng());
                m.answers = order.into_iter().map(|i| txt(&self.authors[i])).collect();
            }
            // an untrimmed VERSION (given with authors) over 255 bytes can't be
            // packed: CoreDNS's write fails and the client gets no answer
            "version.bind." | "version.server." if self.version.len() > 255 => return Ok(ResponseCode::NoError),
            "version.bind." | "version.server." => m.answers = vec![txt(&self.version)],
            "hostname.bind." | "id.server." => m.answers = vec![txt(&trim(&hostname()))],
            _ => return next_or_failure("chaos", &self.next, ctx, w, req).await,
        }
        w.write_msg(m)
            .await
            .map_err(|e| PluginError::servfail("chaos", e.to_string()))?;
        Ok(ResponseCode::NoError)
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "localhost".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "chaos"));
        assert!(setup_ok(&Setup, "chaos v1 alice bob"));
        assert!(setup_err(&Setup, "chaos {\n foo\n}").contains("unknown property 'foo'"));
    }

    #[test]
    fn version_override() {
        let own = format!("KernDNS-{}", kerndns_core::VERSION);
        assert_eq!(version_or_default(None), own);
        assert_eq!(version_or_default(Some(String::new())), own);
        assert_eq!(version_or_default(Some("CoreDNS-1.15.0".into())), "CoreDNS-1.15.0");
    }

    #[tokio::test]
    async fn version() {
        let h = Chaos {
            next: None,
            version: Arc::new("v1".into()),
            authors: Arc::new(vec!["a".into(), "b".into()]),
        };
        let mut req = query("version.bind.", RecordType::TXT, "10.0.0.1:1");
        req.msg.queries[0].set_query_class(DNSClass::CH);
        let (rc, w) = serve(&h, &req).await;
        assert_eq!(rc.unwrap(), ResponseCode::NoError);
        assert_eq!(w.msg().unwrap().answers[0].to_string(), "version.bind. 0 CH TXT v1");
        req.msg.queries[0] = kerndns_core::proto::op::Query::query(
            kerndns_core::proto::rr::Name::from_ascii("authors.bind.").unwrap(),
            RecordType::TXT,
        );
        req.msg.queries[0].set_query_class(DNSClass::CH);
        let (_, w) = serve(&h, &req).await;
        assert_eq!(w.msg().unwrap().answers.len(), 2);
        // other classes go to the next plugin (none here)
        let req = query("version.bind.", RecordType::TXT, "10.0.0.1:1");
        assert!(serve(&h, &req).await.0.is_err());

        // a VERSION over 255 bytes (not trimmed when authors are given)
        // can't be packed: no answer, like CoreDNS, instead of a panic
        let h = Chaos {
            next: None,
            version: Arc::new("v".repeat(300)),
            authors: Arc::new(vec!["a".into()]),
        };
        let mut req = query("version.bind.", RecordType::TXT, "10.0.0.1:1");
        req.msg.queries[0].set_query_class(DNSClass::CH);
        let (rc, w) = serve(&h, &req).await;
        assert_eq!(rc.unwrap(), ResponseCode::NoError);
        assert!(w.msg().is_none());
    }
}
