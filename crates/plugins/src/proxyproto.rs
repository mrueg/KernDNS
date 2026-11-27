//! `proxyproto`: PROXY protocol v1/v2 on the block's listeners. Port of
//! `plugin/proxyproto`.
//!
//! ```text
//! proxyproto {
//!     allow <CIDR...>
//!     default <use|ignore|reject|skip>
//!     udp_session_tracking <duration> [max_sessions]
//!     tlv_metadata
//! }
//! ```
//!
//! The listeners do the work (`kerndns_server::proxyproto`): on `dns://`
//! (UDP v2 headers, TCP v1/v2), `tls://`, `https://` and `grpc://`, the
//! client address plugins see is the header's source. With `tlv_metadata`
//! the PPv2 TLVs of `dns://` and `tls://` requests are published as the
//! `proxyproto/tlv` metadata label (hex). `quic://` and `https3://` don't
//! support PROXY headers in KernDNS yet.

use std::sync::Arc;

use kerndns_core::plugin::{Metadata, MetadataProvider};
use kerndns_core::proxyproto::{Policy, ProxyProtoConfig};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};

use crate::dns64::parse_cidr;

const NAME: &str = "proxyproto";

/// The pass-through handler added with `tlv_metadata`; it provides the
/// `proxyproto/tlv` label.
pub struct ProxyProto {
    next: Next,
}

#[async_trait]
impl Handler for ProxyProto {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        next_or_failure(NAME, &self.next, ctx, w, req).await
    }
}

struct Provider;

impl MetadataProvider for Provider {
    fn metadata(&self, ctx: &mut Context, req: &Request) {
        if let Some(tlvs) = &req.conn.proxy_tlvs
            && !tlvs.is_empty()
        {
            ctx.metadata
                .insert("proxyproto/tlv".into(), data_encoding::HEXLOWER.encode(tlvs));
        }
    }
}

fn parse(c: &mut Controller<'_>) -> Result<ProxyProtoConfig, SetupError> {
    let mut cfg = ProxyProtoConfig::default();
    while c.next() {
        if !c.remaining_args().is_empty() {
            return Err(c.arg_err());
        }
        while c.next_block() {
            match c.val() {
                "allow" => {
                    for v in c.remaining_args() {
                        let (net, len, _) = parse_cidr(&v).map_err(|e| SetupError::new(NAME, format!("{v}: {e}")))?;
                        cfg.allow.push((net, len));
                    }
                }
                "default" => {
                    cfg.default_set = true;
                    let v = c.remaining_args();
                    if v.len() != 1 {
                        return Err(c.arg_err());
                    }
                    cfg.default = match v[0].to_lowercase().as_str() {
                        "use" => Policy::Use,
                        "ignore" => Policy::Ignore,
                        "reject" => Policy::Reject,
                        "skip" => Policy::Skip,
                        _ => return Err(c.arg_err()),
                    };
                }
                "udp_session_tracking" => {
                    let v = c.remaining_args();
                    if v.is_empty() || v.len() > 2 {
                        return Err(c.arg_err());
                    }
                    // Go accepts negative durations, which disable tracking
                    let (neg, d) = match v[0].strip_prefix('-') {
                        Some(rest) => (true, rest),
                        None => (false, v[0].as_str()),
                    };
                    let d = kerndns_core::duration::parse_duration(d).map_err(|e| {
                        let e = e.replace(&format!("{d:?}"), &format!("{:?}", v[0]));
                        SetupError::new(NAME, format!("udp_session_tracking: invalid duration {:?}: {e}", v[0]))
                    })?;
                    cfg.udp_session_ttl = (!neg && !d.is_zero()).then_some(d);
                    if v.len() == 2 {
                        match v[1].parse::<i64>() {
                            Ok(n) if n > 0 => cfg.udp_max_sessions = n as usize,
                            _ => {
                                return Err(SetupError::new(
                                    NAME,
                                    format!(
                                        "udp_session_tracking: invalid max sessions {:?}: must be a positive integer",
                                        v[1]
                                    ),
                                ));
                            }
                        }
                    }
                }
                "tlv_metadata" => {
                    if !c.remaining_args().is_empty() {
                        return Err(c.arg_err());
                    }
                    cfg.tlv_metadata = true;
                }
                other => {
                    // not wrapped in plugin.Error in CoreDNS
                    let e = c.errf(format!("unknown option '{other}'"));
                    return Err(SetupError::new("", e.msg));
                }
            }
        }
    }
    Ok(cfg)
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let cfg = parse(c)?;
        let tlv = cfg.tlv_metadata;
        c.config.proxy_proto = Some(Arc::new(cfg));
        if tlv {
            Metadata::of(c.config).add_provider(Arc::new(Provider));
            c.add_plugin(|next| Arc::new(ProxyProto { next }));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::rr::RecordType;
    use std::net::IpAddr;
    use std::time::Duration;

    fn policy(cfg: &ProxyProtoConfig, ip: &str) -> Policy {
        cfg.policy(ip.parse::<IpAddr>().unwrap())
    }

    fn config(input: &str) -> Result<Option<Arc<ProxyProtoConfig>>, String> {
        let (r, cfg) = run_setup(&Setup, input);
        r.map(|_| cfg.proxy_proto.clone())
    }

    // setup_test.go: TestSetup
    #[test]
    fn setup() {
        let ok = [
            ("proxyproto", None, 0),
            ("proxyproto {\nallow 127.0.0.1/8 ::1/128\n}", None, 0),
            ("proxyproto {\nallow 127.0.0.1/8 ::1/128\ndefault ignore\n}", None, 0),
            ("proxyproto {\nallow\n}", None, 0),
            ("proxyproto {\nudp_session_tracking 28s\n}", Some(28), 0),
            (
                "proxyproto {\nallow 10.0.0.0/8\nudp_session_tracking 1m\n}",
                Some(60),
                0,
            ),
            ("proxyproto {\nudp_session_tracking 28s 20000\n}", Some(28), 20000),
            (
                "proxyproto {\nallow 10.0.0.0/8\nudp_session_tracking 1m 500\n}",
                Some(60),
                500,
            ),
        ];
        for (input, ttl, max) in ok {
            let cfg = config(input)
                .unwrap_or_else(|e| panic!("{input}: {e}"))
                .expect("configured");
            assert_eq!(cfg.udp_session_ttl, ttl.map(Duration::from_secs), "{input}");
            assert_eq!(cfg.udp_max_sessions, max, "{input}");
        }
        let bad = [
            ("proxyproto {\nunknown\n}", "unknown option"),
            ("proxyproto extra_arg", "Wrong argument"),
            ("proxyproto {\nallow invalid_ip\n}", "invalid CIDR address"),
            (
                "proxyproto {\nallow 127.0.0.1/8\ndefault invalid_policy\n}",
                "Wrong argument",
            ),
            ("proxyproto {\nudp_session_tracking\n}", "Wrong argument"),
            ("proxyproto {\nudp_session_tracking 28s 100 extra\n}", "Wrong argument"),
            ("proxyproto {\nudp_session_tracking notaduration\n}", "invalid duration"),
            (
                "proxyproto {\nudp_session_tracking 28s notanumber\n}",
                "invalid max sessions",
            ),
            ("proxyproto {\nudp_session_tracking 28s 0\n}", "invalid max sessions"),
            ("proxyproto {\nudp_session_tracking 28s -1\n}", "invalid max sessions"),
        ];
        for (input, want) in bad {
            let (r, cfg) = run_setup(&Setup, input);
            let e = r.expect_err(input);
            assert!(e.contains(want), "{input}: {e}");
            assert!(cfg.proxy_proto.is_none(), "{input}");
        }
    }

    #[test]
    fn error_messages() {
        assert_eq!(
            setup_err(&Setup, "proxyproto {\nunknown\n}"),
            "Corefile:3 - Error during parsing: unknown option 'unknown'"
        );
        assert_eq!(
            setup_err(&Setup, "proxyproto {\nallow invalid_ip\n}"),
            "plugin/proxyproto: invalid_ip: invalid CIDR address: invalid_ip"
        );
        assert_eq!(
            setup_err(&Setup, "proxyproto {\nudp_session_tracking 5x\n}"),
            "plugin/proxyproto: udp_session_tracking: invalid duration \"5x\": time: unknown unit \"x\" in duration \"5x\""
        );
        assert_eq!(
            setup_err(&Setup, "proxyproto {\nudp_session_tracking 28s 0\n}"),
            "plugin/proxyproto: udp_session_tracking: invalid max sessions \"0\": must be a positive integer"
        );
        // negative durations parse, and disable tracking
        let cfg = config("proxyproto {\nudp_session_tracking -5s\n}").unwrap().unwrap();
        assert_eq!(cfg.udp_session_ttl, None);
    }

    // setup_test.go: TestTLVMetadataFlag
    #[test]
    fn tlv_metadata_flag() {
        for (input, want) in [
            ("proxyproto {\ntlv_metadata\n}", true),
            ("proxyproto {\nallow 10.0.0.0/8\ntlv_metadata\n}", true),
            ("proxyproto {\nallow 10.0.0.0/8\n}", false),
        ] {
            let (r, cfg) = run_setup(&Setup, input);
            r.unwrap();
            assert_eq!(cfg.proxy_proto.unwrap().tlv_metadata, want, "{input}");
            // the metadata handler is only in the chain with tlv_metadata
            assert_eq!(cfg.plugins.len(), usize::from(want), "{input}");
        }
        assert!(setup_err(&Setup, "proxyproto {\ntlv_metadata on\n}").contains("Wrong argument"));
    }

    // setup_test.go: TestDefaultPolicyWithoutAllow
    #[test]
    fn default_policy_without_allow() {
        let cfg = config("proxyproto {\ndefault reject\n}").unwrap().unwrap();
        assert_eq!(policy(&cfg, "192.0.2.1"), Policy::Reject);
        let cfg = config("proxyproto").unwrap().unwrap();
        assert_eq!(policy(&cfg, "192.0.2.1"), Policy::Use);
        let cfg = config("proxyproto {\nallow 192.168.1.1/32\n}").unwrap().unwrap();
        assert_eq!(policy(&cfg, "192.168.1.1"), Policy::Use);
        assert_eq!(policy(&cfg, "192.168.1.2"), Policy::Ignore);
    }

    // metadata_test.go
    #[test]
    fn tlv_label() {
        let mut ctx = Context::new(".", "dns://:53");
        let mut req = query("example.org.", RecordType::A, "192.0.2.1:53");
        Provider.metadata(&mut ctx, &req);
        assert!(ctx.metadata.is_empty(), "no TLVs, no label");
        req.conn.proxy_tlvs = Some(Arc::from(&[0xe0u8, 0x00, 0x02, 0xab, 0xcd][..]));
        Provider.metadata(&mut ctx, &req);
        assert_eq!(
            ctx.metadata.get("proxyproto/tlv").map(String::as_str),
            Some("e00002abcd")
        );
    }
}
