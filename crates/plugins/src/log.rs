//! `log`: logs queries in CoreDNS's common log format. Port of `plugin/log`.
//!
//! ```text
//! log [NAMES...] [FORMAT] {
//!     class CLASSES...
//! }
//! ```

use std::collections::HashSet;
use std::sync::Arc;

use kerndns_core::proto::op::{Message, ResponseCode};
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

    /// Classify a response like `response.Typify` + `response.Classify`.
    pub fn of(msg: Option<&Message>) -> Class {
        let Some(m) = msg else { return Class::Error };
        match m.metadata.response_code {
            ResponseCode::NXDomain => Class::Denial,
            ResponseCode::NoError if m.answers.is_empty() && !is_delegation(m) => Class::Denial,
            ResponseCode::NoError => Class::Success,
            _ => Class::Error,
        }
    }
}

fn is_delegation(m: &Message) -> bool {
    use kerndns_core::proto::rr::RecordType;
    m.authorities.iter().any(|r| r.record_type() == RecordType::NS)
        && !m.authorities.iter().any(|r| r.record_type() == RecordType::SOA)
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
                    _ => return Err(c.arg_err()),
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
        c.add_plugin(move |next| {
            Arc::new(Logger {
                next,
                rules: rules.clone(),
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

        let wanted = rule.class.contains(&Class::All) || {
            // A response the server will still write (SERVFAIL etc.) is an error.
            let class = if rec.msg.is_none() && !client_write(rc) {
                Class::Error
            } else {
                Class::of(rec.msg.as_ref())
            };
            rule.class.contains(&class)
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
        ">opcode" => format!("{:?}", req.msg.metadata.op_code).to_uppercase(),
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
        assert!(setup_err(&Setup, "log {\n foo\n}").contains("Wrong argument count"));
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

    #[test]
    fn matching() {
        assert!(name_matches(".", "a.b."));
        assert!(name_matches("example.org.", "www.example.org."));
        assert!(name_matches("example.org.", "example.org."));
        assert!(!name_matches("example.org.", "badexample.org."));
    }
}
