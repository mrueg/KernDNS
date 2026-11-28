//! `log`: logs queries in CoreDNS's common log format. Port of `plugin/log`.
//!
//! ```text
//! log [NAMES...] [FORMAT] {
//!     class CLASSES...
//! }
//! ```

use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;

use kerndns_core::proto::op::{Message, ResponseCode};
use kerndns_core::typify::{ResponseClass, ResponseType, typify};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Recorder, Request, ResponseWriter, SetupError,
    async_trait, client_write, next_or_failure, result_rcode,
};

/// Written for values that aren't available.
pub const EMPTY_VALUE: &str = "-";
pub const COMMON_LOG_FORMAT: &str = r#"{remote}:{port} - {>id} "{type} {class} {name} {proto} {size} {>do} {>bufsize}" {rcode} {>rflags} {rsize} {duration}"#;
pub const COMBINED_LOG_FORMAT: &str = concat!(
    r#"{remote}:{port} - {>id} "{type} {class} {name} {proto} {size} {>do} {>bufsize}" {rcode} {>rflags} {rsize} {duration}"#,
    r#" "{>opcode}""#
);
pub const DEFAULT_LOG_FORMAT: &str = COMMON_LOG_FORMAT;

/// Response classes that `class` can select, like `response.Class`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    All,
    Success,
    Denial,
    Error,
}

impl Class {
    fn parse(s: &str) -> Option<Class> {
        match s {
            "all" => Some(Class::All),
            "success" => Some(Class::Success),
            "denial" => Some(Class::Denial),
            "error" => Some(Class::Error),
            _ => None,
        }
    }
}

impl From<ResponseClass> for Class {
    fn from(c: ResponseClass) -> Class {
        match c {
            ResponseClass::All => Class::All,
            ResponseClass::Success => Class::Success,
            ResponseClass::Denial => Class::Denial,
            ResponseClass::Error => Class::Error,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name_scope: String,
    pub format: String,
    pub class: HashSet<Class>,
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "log"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut rules: Vec<Rule> = Vec::new();
        while c.next() {
            let length = rules.len();
            let mut args = c.remaining_args();
            let mut format = DEFAULT_LOG_FORMAT.to_string();
            if args.len() > 1 && args.last().is_some_and(|a| a.contains('{')) {
                format = args
                    .pop()
                    .unwrap()
                    .replace("{common}", COMMON_LOG_FORMAT)
                    .replace("{combined}", COMBINED_LOG_FORMAT);
            }
            if args.is_empty() {
                args.push(".".into());
            }
            for a in args {
                rules.push(Rule {
                    name_scope: fqdn(&a),
                    format: format.clone(),
                    class: HashSet::new(),
                });
            }

            let mut classes = HashSet::new();
            while c.next_block() {
                match c.val() {
                    "class" => {
                        let cls = c.remaining_args();
                        if cls.is_empty() {
                            return Err(c.arg_err());
                        }
                        for s in cls {
                            let Some(k) = Class::parse(&s) else {
                                return Err(c.errf(format!("invalid class: {s}")));
                            };
                            classes.insert(k);
                        }
                    }
                    other => {
                        let msg = format!("unknown property '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
            if classes.is_empty() {
                classes.insert(Class::All);
            }
            for r in &mut rules[length..] {
                r.class = classes.clone();
            }
        }
        let rules = Arc::new(rules);
        let meta = kerndns_core::plugin::Metadata::of(c.config);
        c.add_plugin(move |next| {
            Arc::new(Logger {
                next,
                rules: rules.clone(),
                meta: meta.clone(),
                meta_enabled: std::sync::OnceLock::new(),
            })
        });
        Ok(())
    }
}

fn fqdn(s: &str) -> String {
    let mut s = s.to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

/// True if `name` is `zone` or below it (both lowercase FQDNs).
pub fn name_matches(zone: &str, name: &str) -> bool {
    zone == "." || name == zone || name.ends_with(&format!(".{zone}"))
}

pub struct Logger {
    next: Next,
    rules: Arc<Vec<Rule>>,
    /// The block's metadata registry, for `log/type` and `log/class`.
    meta: kerndns_core::plugin::Metadata,
    /// Whether the `metadata` plugin is on (known once setup is done).
    meta_enabled: std::sync::OnceLock<bool>,
}

#[async_trait]
impl Handler for Logger {
    fn name(&self) -> &'static str {
        "log"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let name = req.name();
        let Some(rule) = self.rules.iter().find(|r| name_matches(&r.name_scope, &name)) else {
            return next_or_failure("log", &self.next, ctx, w, req).await;
        };
        let mut rec = Recorder::new(w);
        let res = next_or_failure("log", &self.next, ctx, &mut rec, req).await;
        let rc = result_rcode(&res);

        let meta = *self.meta_enabled.get_or_init(|| self.meta.enabled());
        let wanted = if !meta && rule.class.contains(&Class::All) {
            true
        } else {
            // classify what the client gets: a response the server still
            // writes (SERVFAIL etc.) is a message with just the rcode
            let synth;
            let msg = match &rec.msg {
                Some(m) => Some(m),
                None if !client_write(rc) => {
                    synth = req.error_reply(rc);
                    Some(&synth)
                }
                None => None,
            };
            let tpe = msg.map_or(ResponseType::OtherError, |m| typify(m, SystemTime::now()));
            let class = tpe.class();
            if meta {
                ctx.metadata.insert("log/type".into(), tpe.as_str().into());
                ctx.metadata.insert("log/class".into(), class.as_str().into());
            }
            rule.class.contains(&Class::All) || rule.class.contains(&Class::from(class))
        };
        if wanted {
            let line = replace(&rule.format, ctx, req, &rec, rc);
            kerndns_core::info!("{line}");
        }
        res
    }
}

/// Expand the placeholders of `format`, like `replacer.Replace`.
pub fn replace(format: &str, ctx: &Context, req: &Request, rec: &Recorder<'_>, rc: ResponseCode) -> String {
    let mut out = String::with_capacity(format.len() + 64);
    let mut rest = format;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) => {
                let key = &after[..end];
                match value(key, ctx, req, rec, rc) {
                    Some(v) => out.push_str(&v),
                    None => {
                        out.push('{');
                        out.push_str(key);
                        out.push('}');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn value(key: &str, ctx: &Context, req: &Request, rec: &Recorder<'_>, rc: ResponseCode) -> Option<String> {
    // `{/label}`: a metadata value (e.g. `{/kubernetes/namespace}`)
    if let Some(label) = key.strip_prefix('/') {
        return Some(
            ctx.metadata
                .get(label)
                .cloned()
                .unwrap_or_else(|| EMPTY_VALUE.to_string()),
        );
    }
    let v = match key {
        "type" => req.qtype().to_string(),
        "name" => req.name(),
        "class" => req.qclass().to_string(),
        "proto" => req.proto().to_string(),
        "remote" => match req.ip() {
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            ip => ip.to_string(),
        },
        "port" => req.port().to_string(),
        "local" => match req.local.ip().to_canonical() {
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            ip => ip.to_string(),
        },
        "size" => req.msg.to_vec().map(|v| v.len()).unwrap_or(0).to_string(),
        "rcode" => match (&rec.msg, rec.rcode) {
            (Some(_), Some(code)) => rcode_string(code),
            _ if !client_write(rc) => rcode_string(rc),
            _ => EMPTY_VALUE.to_string(),
        },
        "rsize" => {
            if rec.msg.is_some() {
                rec.len.to_string()
            } else {
                EMPTY_VALUE.to_string()
            }
        }
        "duration" => format!("{}s", ctx.start.elapsed().as_secs_f64()),
        ">id" => req.id().to_string(),
        ">opcode" => u8::from(req.msg.metadata.op_code).to_string(),
        ">do" => req.do_bit().to_string(),
        ">bufsize" => req.size().to_string(),
        ">rflags" => match &rec.msg {
            Some(m) => flags(m),
            None => EMPTY_VALUE.to_string(),
        },
        _ => return None,
    };
    Some(v)
}

/// Response code names as miekg/dns `RcodeToString` prints them.
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

/// Header flags as CoreDNS logs them: `qr,aa,tc,rd,ra,z,ad,cd` (set ones only).
pub fn flags(m: &Message) -> String {
    let h = &m.metadata;
    let mut f = Vec::new();
    if h.message_type == kerndns_core::proto::op::MessageType::Response {
        f.push("qr");
    }
    if h.authoritative {
        f.push("aa");
    }
    if h.truncation {
        f.push("tc");
    }
    if h.recursion_desired {
        f.push("rd");
    }
    if h.recursion_available {
        f.push("ra");
    }
    if h.authentic_data {
        f.push("ad");
    }
    if h.checking_disabled {
        f.push("cd");
    }
    if f.is_empty() {
        EMPTY_VALUE.to_string()
    } else {
        f.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::whoami::Whoami;
    use kerndns_core::CaptureWriter;
    use kerndns_core::proto::rr::RecordType;

    #[test]
    fn setup_variants() {
        assert!(setup_ok(&Setup, "log"));
        assert!(setup_ok(&Setup, "log example.org"));
        assert!(setup_ok(&Setup, "log example.org example.net {common}"));
        assert!(setup_ok(&Setup, "log {\n class denial error\n}"));
        assert!(setup_err(&Setup, "log {\n class\n}").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "log {\n class foo\n}").contains("invalid class: foo"));
        assert!(setup_err(&Setup, "log {\n foo\n}").contains("unknown property 'foo'"));
    }

    #[tokio::test]
    async fn common_format() {
        let req = query("example.org.", RecordType::A, "10.0.0.1:4242");
        let mut inner = CaptureWriter::new();
        let mut rec = Recorder::new(&mut inner);
        let mut ctx = Context::new(".", "dns://:53");
        Whoami.serve_dns(&mut ctx, &mut rec, &req).await.unwrap();
        let line = replace(COMMON_LOG_FORMAT, &ctx, &req, &rec, ResponseCode::NoError);
        let expected = r#"10.0.0.1:4242 - 1 "A IN example.org. udp 29 false 512" NOERROR qr,aa,rd "#;
        assert!(line.starts_with(expected), "{line}");
        assert!(line.ends_with('s'));
    }

    /// replacer_test.go TestMetadataReplace: `{/label}` is a metadata value,
    /// `-` when it isn't set.
    #[test]
    fn metadata_labels() {
        let req = query("example.org.", RecordType::A, "10.0.0.1:4242");
        let mut inner = CaptureWriter::new();
        let rec = Recorder::new(&mut inner);
        let mut ctx = Context::new(".", "dns://:53");
        ctx.metadata.insert("kubernetes/namespace".into(), "ns".into());
        let line = replace(
            "{/kubernetes/namespace} {/kubernetes/kind} {name}",
            &ctx,
            &req,
            &rec,
            ResponseCode::NoError,
        );
        assert_eq!(line, "ns - example.org.");
    }

    /// `class` filters with `response.Typify`/`Classify`, and the
    /// `log/type` and `log/class` metadata with the `metadata` plugin on.
    #[tokio::test]
    async fn classes_and_metadata() {
        use kerndns_core::proto::rr::rdata::A;
        use kerndns_core::proto::rr::{Name, RData, Record};
        let run = |rcode: ResponseCode, answer: bool, meta: bool| async move {
            let m = kerndns_core::plugin::Metadata::default();
            if meta {
                m.enable(vec![".".into()]);
            }
            let next = reply(move |r: &Request| {
                let mut m = r.reply();
                m.metadata.response_code = rcode;
                if answer {
                    let name = Name::from_ascii("example.org.").unwrap();
                    m.answers
                        .push(Record::from_rdata(name, 60, RData::A(A::new(1, 2, 3, 4))));
                }
                m
            });
            let l = Logger {
                next,
                rules: Arc::new(vec![Rule {
                    name_scope: ".".into(),
                    format: COMMON_LOG_FORMAT.into(),
                    class: [Class::Denial].into_iter().collect(),
                }]),
                meta: m,
                meta_enabled: std::sync::OnceLock::new(),
            };
            let req = query("example.org.", RecordType::A, "10.0.0.1:4242");
            let mut ctx = Context::new(".", "dns://:53");
            let mut w = CaptureWriter::new();
            l.serve_dns(&mut ctx, &mut w, &req).await.unwrap();
            (
                ctx.metadata.get("log/type").cloned(),
                ctx.metadata.get("log/class").cloned(),
            )
        };
        let s = |a: &str, b: &str| (Some(a.to_string()), Some(b.to_string()));
        // NOERROR without answers, SOA or NS is NOERROR/success in CoreDNS
        assert_eq!(run(ResponseCode::NoError, false, true).await, s("NOERROR", "success"));
        assert_eq!(run(ResponseCode::NXDomain, false, true).await, s("NXDOMAIN", "denial"));
        // NXDOMAIN with an answer is an error
        assert_eq!(run(ResponseCode::NXDomain, true, true).await, s("OTHERERROR", "error"));
        assert_eq!(
            run(ResponseCode::ServFail, false, true).await,
            s("SERVERERROR", "error")
        );
        assert_eq!(run(ResponseCode::NoError, true, false).await, (None, None));
    }

    #[test]
    fn matching() {
        assert!(name_matches(".", "a.b."));
        assert!(name_matches("example.org.", "www.example.org."));
        assert!(name_matches("example.org.", "example.org."));
        assert!(!name_matches("example.org.", "badexample.org."));
    }
}
