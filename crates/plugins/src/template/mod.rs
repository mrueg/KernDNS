//! `template`: answers queries from Go-style templates. Port of
//! `plugin/template`.
//!
//! ```text
//! template CLASS TYPE [ZONE...] {
//!     match REGEX...
//!     var NAME EXPRESSION
//!     expr EXPRESSION
//!     answer RR
//!     additional RR
//!     authority RR
//!     rcode CODE
//!     ederror EXTENDED_ERROR_CODE [EXTRA_REASON]
//!     fallthrough [FALLTHROUGH-ZONE...]
//!     upstream
//! }
//! ```
//!
//! The records are rendered with [`gotmpl`], a subset of Go's
//! `text/template`; anything outside that subset is rejected at setup.
//! `var` and `expr` are compiled and type checked at setup by
//! [`crate::expr`], KernDNS's evaluator of the expr language subset
//! listed there; expressions outside it are rejected at setup.

pub mod gotmpl;

use std::str::FromStr;
use std::sync::Arc;

use kerndns_core::proto::op::{Edns, ResponseCode};
use kerndns_core::proto::rr::rdata::opt::EdnsOption;
use kerndns_core::proto::rr::{DNSClass, RData, Record, RecordType};
use kerndns_core::zones::{self, Fall};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure, upstream,
};
use regex::Regex;

use crate::expr::{self, Program, Scope};
use crate::file::zonefile::new_rr;
use crate::pluginmetrics as pm;
use gotmpl::{Data, Question, Template};

/// A hard limit on the length of a regex pattern.
const MAX_REGEXP_LEN: usize = 10000;

/// EDNS0 option code of an Extended DNS Error (RFC 8914).
const EDNS0_EDE: u16 = 15;

/// One `template` block.
#[derive(Debug)]
pub struct Tmpl {
    zones: Vec<String>,
    rcode: ResponseCode,
    regex: Vec<Regex>,
    answer: Vec<Template>,
    additional: Vec<Template>,
    authority: Vec<Template>,
    qclass: DNSClass,
    qtype: RecordType,
    ederror: Option<(u16, String)>,
    fall: Fall,
    /// `var NAME EXPRESSION`, in order.
    vars: Vec<(String, Program)>,
    /// `expr EXPRESSION`: all must be true for a match.
    exprs: Vec<Program>,
}

/// A valid `var` name (`varNameRegexp`).
fn valid_var_name(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_alphabetic() || c == b'_') && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// `dns.StringToClass`.
fn parse_class(s: &str) -> Option<DNSClass> {
    Some(match s {
        "IN" => DNSClass::IN,
        "CS" => DNSClass::from(2),
        "CH" => DNSClass::CH,
        "HS" => DNSClass::HS,
        "NONE" => DNSClass::NONE,
        "ANY" => DNSClass::ANY,
        _ => return None,
    })
}

/// `dns.StringToType`: upper-case mnemonics only.
fn parse_type(s: &str) -> Option<RecordType> {
    if s != s.to_ascii_uppercase() {
        return None;
    }
    match RecordType::from_str(s) {
        Ok(RecordType::Unknown(_)) | Err(_) => None,
        Ok(t) => Some(t),
    }
}

/// `dns.StringToRcode`.
fn parse_rcode(s: &str) -> Option<ResponseCode> {
    let n: u16 = match s {
        "NOERROR" => 0,
        "FORMERR" => 1,
        "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "NOTIMP" => 4,
        "REFUSED" => 5,
        "YXDOMAIN" => 6,
        "YXRRSET" => 7,
        "NXRRSET" => 8,
        "NOTAUTH" => 9,
        "NOTZONE" => 10,
        "DSOTYPENI" => 11,
        "BADSIG" => 16,
        "BADKEY" => 17,
        "BADTIME" => 18,
        "BADMODE" => 19,
        "BADNAME" => 20,
        "BADALG" => 21,
        "BADTRUNC" => 22,
        "BADCOOKIE" => 23,
        _ => return None,
    };
    Some(n.into())
}

fn new_template(name: &str, text: &str) -> Result<Template, String> {
    Template::parse(name, text)
}

/// The default `match`, compiled once.
static MATCH_ALL: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(".*").expect("valid regex"));

/// Parse all `template` directives of a server block, like `templateParse`.
/// Returns the handler's zones and the templates.
pub fn template_parse(c: &mut Controller<'_>) -> Result<(Vec<String>, Vec<Tmpl>), SetupError> {
    let mut all_zones = Vec::new();
    let mut templates = Vec::new();
    let server_keys = c.server_block_keys();
    while c.next() {
        if !c.next_arg() {
            return Err(c.arg_err());
        }
        let Some(qclass) = parse_class(c.val()) else {
            let msg = format!("invalid query class {}", c.val());
            return Err(c.errf(msg));
        };
        if !c.next_arg() {
            return Err(c.arg_err());
        }
        let Some(qtype) = parse_type(c.val()) else {
            let msg = format!("invalid RR class {}", c.val());
            return Err(c.errf(msg));
        };
        let args = c.remaining_args();
        let zones = zones::origins_from_args_or_server_block(&args, &server_keys);
        all_zones.extend(zones.iter().cloned());
        let mut t = Tmpl {
            zones,
            rcode: ResponseCode::NoError,
            regex: Vec::new(),
            answer: Vec::new(),
            additional: Vec::new(),
            authority: Vec::new(),
            qclass,
            qtype,
            ederror: None,
            fall: Fall::default(),
            vars: Vec::new(),
            exprs: Vec::new(),
        };
        let mut scope = Scope {
            vars: Vec::new(),
            group: true,
        };

        while c.next_block() {
            let opt = c.val().to_string();
            match opt.as_str() {
                "match" => {
                    let args = c.remaining_args();
                    if args.is_empty() {
                        return Err(c.arg_err());
                    }
                    for re in args {
                        if re.len() > MAX_REGEXP_LEN {
                            let msg = format!("regex pattern too long: {} > {MAX_REGEXP_LEN}", re.len());
                            return Err(c.errf(msg));
                        }
                        match Regex::new(&re) {
                            Ok(r) => t.regex.push(r),
                            Err(e) => {
                                let msg = format!("could not parse regex: {re}, {e}");
                                return Err(c.errf(msg));
                            }
                        }
                    }
                }
                "answer" | "additional" | "authority" => {
                    let args = c.remaining_args();
                    if args.is_empty() {
                        return Err(c.arg_err());
                    }
                    for text in &args {
                        let tmpl = match new_template(&opt, text) {
                            Ok(t) => t,
                            Err(e) => {
                                let msg = format!("could not compile template: {}, {e}", c.val());
                                return Err(c.errf(msg));
                            }
                        };
                        match opt.as_str() {
                            "answer" => t.answer.push(tmpl),
                            "additional" => t.additional.push(tmpl),
                            _ => t.authority.push(tmpl),
                        }
                    }
                }
                "var" => {
                    let args = c.remaining_args();
                    if args.len() < 2 {
                        return Err(c.arg_err());
                    }
                    let name = &args[0];
                    if !valid_var_name(name) {
                        return Err(c.errf(format!("invalid variable name {name:?}")));
                    }
                    if scope.reserved(name) {
                        return Err(c.errf(format!("variable name {name:?} is reserved")));
                    }
                    let prog = Program::compile_in(&args[1..].join(" "), &scope)
                        .map_err(|e| c.errf(format!("could not compile expression: {name}, {e}")))?;
                    scope.vars.push((name.clone(), prog.result_type()));
                    t.vars.push((name.clone(), prog));
                }
                "expr" => {
                    let args = c.remaining_args();
                    if args.is_empty() {
                        return Err(c.arg_err());
                    }
                    let prog = Program::compile_in(&args.join(" "), &scope)
                        .map_err(|e| c.errf(format!("could not compile expression: {e}")))?;
                    t.exprs.push(prog);
                }
                "rcode" => {
                    if !c.next_arg() {
                        return Err(c.arg_err());
                    }
                    let Some(rc) = parse_rcode(c.val()) else {
                        let msg = format!("unknown rcode {}", c.val());
                        return Err(c.errf(msg));
                    };
                    t.rcode = rc;
                }
                "ederror" => {
                    let args = c.remaining_args();
                    if args.len() != 1 && args.len() != 2 {
                        return Err(c.arg_err());
                    }
                    let digits = !args[0].is_empty() && args[0].bytes().all(|b| b.is_ascii_digit());
                    let code = match args[0].parse::<u16>() {
                        Ok(v) if digits => v,
                        _ => {
                            let why = if digits { "value out of range" } else { "invalid syntax" };
                            let msg = format!(
                                "error parsing extended DNS error code {}, strconv.ParseUint: parsing {:?}: {why}",
                                c.val(),
                                args[0],
                            );
                            return Err(c.errf(msg));
                        }
                    };
                    t.ederror = Some((code, args.get(1).cloned().unwrap_or_default()));
                }
                "fallthrough" => {
                    let a = c.remaining_args();
                    t.fall.set_zones_from_args(&a);
                }
                "upstream" => {
                    // A no-op kept for compatibility: CNAME targets are
                    // always resolved.
                    c.remaining_args();
                }
                _ => return Err(c.arg_err()),
            }
        }
        if t.regex.is_empty() {
            t.regex.push(MATCH_ALL.clone());
        }
        templates.push(t);
    }
    Ok((all_zones, templates))
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "template"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let (zones, templates) = template_parse(c)?;
        let zones = Arc::new(zones);
        let templates = Arc::new(templates);
        c.add_plugin(move |next| {
            Arc::new(TemplateHandler {
                zones: zones.clone(),
                templates: templates.clone(),
                next,
            })
        });
        Ok(())
    }
}

pub struct TemplateHandler {
    zones: Arc<Vec<String>>,
    templates: Arc<Vec<Tmpl>>,
    next: Next,
}

enum Match<'a> {
    Yes(Box<Data<'a>>),
    No { fallthrough: bool },
}

impl Tmpl {
    /// Like `template.match`.
    fn matches<'a>(&self, ctx: &'a Context, req: &'a Request, qname: &str) -> Match<'a> {
        let Some(zone) = zones::matches(&self.zones, qname) else {
            return Match::No { fallthrough: true };
        };
        let (qclass, qtype) = (req.qclass(), req.qtype());
        if self.qclass != DNSClass::ANY && qclass != DNSClass::ANY && qclass != self.qclass {
            return Match::No { fallthrough: true };
        }
        if self.qtype != RecordType::ANY && qtype != RecordType::ANY && qtype != self.qtype {
            return Match::No { fallthrough: true };
        }
        for re in &self.regex {
            let Some(caps) = re.captures(qname) else {
                continue;
            };
            let matches: Vec<String> = caps
                .iter()
                .map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default())
                .collect();
            let mut group: std::collections::HashMap<String, String> = matches
                .iter()
                .enumerate()
                .map(|(i, m)| (i.to_string(), m.clone()))
                .collect();
            for (i, name) in re.capture_names().enumerate() {
                if let Some(name) = name
                    && !name.is_empty()
                {
                    group.insert(name.to_string(), matches[i].clone());
                }
            }
            let mut qn = req.qname().to_ascii();
            if !qn.ends_with('.') {
                qn.push('.');
            }
            let class = if qclass != DNSClass::ANY { qclass } else { self.qclass };
            let typ = if qtype != RecordType::ANY { qtype } else { self.qtype };
            let mut vars = Vec::new();
            if !self.vars.is_empty() || !self.exprs.is_empty() {
                // evaluation errors are SERVFAIL, even with fallthrough
                let mut values = Vec::with_capacity(self.vars.len());
                for (_, prog) in &self.vars {
                    let env = expr::Env {
                        vars: &values,
                        groups: Some(&group),
                    };
                    match prog.run_in(ctx, req, &env) {
                        Ok(v) => values.push(v),
                        Err(_) => return Match::No { fallthrough: false },
                    }
                }
                for prog in &self.exprs {
                    let env = expr::Env {
                        vars: &values,
                        groups: Some(&group),
                    };
                    match prog.run_in(ctx, req, &env) {
                        Ok(expr::Value::Bool(true)) => {}
                        Ok(_) => {
                            return Match::No {
                                fallthrough: self.fall.through(qname),
                            };
                        }
                        Err(_) => return Match::No { fallthrough: false },
                    }
                }
                vars = self.vars.iter().map(|(n, _)| n.clone()).zip(values).collect();
            }
            return Match::Yes(Box::new(Data {
                zone: zone.to_string(),
                name: qname.to_string(),
                regex: re.as_str().to_string(),
                matches,
                group,
                class: gotmpl::class_name(class),
                typ: gotmpl::type_name(typ),
                message: Some(&req.msg),
                question: Some(Question {
                    name: qn,
                    qtype: qtype.into(),
                    qclass: qclass.into(),
                }),
                remote: req.ip().to_string(),
                meta: Some(&ctx.metadata),
                vars,
            }));
        }
        Match::No {
            fallthrough: self.fall.through(qname),
        }
    }
}

/// Render one record, like `executeRRTemplate`.
fn execute_rr(ctx: &Context, section: &str, t: &Template, data: &Data<'_>) -> Result<Record, String> {
    let view = ctx.view.as_deref().unwrap_or("");
    let labels = |tmpl: &str| -> [String; 7] {
        [
            ctx.server.to_string(),
            data.zone.clone(),
            view.to_string(),
            data.class.clone(),
            data.typ.clone(),
            section.to_string(),
            tmpl.to_string(),
        ]
    };
    let text = match t.execute(data) {
        Ok(s) => s,
        Err(e) => {
            let l = labels(&t.to_string());
            pm::TEMPLATE_FAILURES
                .with_label_values(&l.each_ref().map(String::as_str))
                .inc();
            return Err(e);
        }
    };
    match new_rr(&text) {
        Ok(Some(rr)) => Ok(rr),
        res => {
            let l = labels(&t.to_string());
            pm::TEMPLATE_RR_FAILURES
                .with_label_values(&l.each_ref().map(String::as_str))
                .inc();
            Err(match res {
                Err(e) => e.to_string(),
                _ => format!("dns: no resource record in {text:?}"),
            })
        }
    }
}

#[async_trait]
impl Handler for TemplateHandler {
    fn name(&self) -> &'static str {
        "template"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let qname = req.name();
        if zones::matches(&self.zones, &qname).is_none() {
            return next_or_failure("template", &self.next, ctx, w, req).await;
        }

        for t in self.templates.iter() {
            let data = match t.matches(ctx, req, &qname) {
                Match::Yes(d) => *d,
                Match::No { fallthrough: false } => return Ok(ResponseCode::ServFail),
                Match::No { fallthrough: true } => continue,
            };
            let view = ctx.view.as_deref().unwrap_or("");
            pm::TEMPLATE_MATCHES
                .with_label_values(&[&*ctx.server, &data.zone, view, &data.class, &data.typ])
                .inc();

            if t.rcode == ResponseCode::ServFail {
                return Ok(t.rcode);
            }

            let mut m = req.reply();
            m.metadata.authoritative = true;
            m.metadata.response_code = t.rcode;

            let qtype = req.qtype();
            for a in &t.answer {
                let rr =
                    execute_rr(ctx, "answer", a, &data).map_err(|e| PluginError::raw(ResponseCode::ServFail, e))?;
                let target = match &rr.data {
                    RData::CNAME(c) if matches!(qtype, RecordType::A | RecordType::AAAA) => Some(c.0.clone()),
                    _ => None,
                };
                m.answers.push(rr);
                if let Some(target) = target
                    && let Ok(Some(up)) = upstream::lookup(ctx, req, &target, qtype).await
                {
                    m.metadata.truncation = up.metadata.truncation;
                    m.answers.extend(up.answers);
                }
            }
            for a in &t.additional {
                let rr =
                    execute_rr(ctx, "additional", a, &data).map_err(|e| PluginError::raw(ResponseCode::ServFail, e))?;
                m.additionals.push(rr);
            }
            for a in &t.authority {
                let rr =
                    execute_rr(ctx, "authority", a, &data).map_err(|e| PluginError::raw(ResponseCode::ServFail, e))?;
                m.authorities.push(rr);
            }

            if let Some((code, reason)) = &t.ederror {
                let opt = m.edns.get_or_insert_with(Edns::new);
                opt.set_max_payload(4096);
                opt.set_dnssec_ok(true);
                let mut data = code.to_be_bytes().to_vec();
                data.extend_from_slice(reason.as_bytes());
                opt.options_mut().insert(EdnsOption::Unknown(EDNS0_EDE, data));
            }

            drop(data);
            w.write_msg(m)
                .await
                .map_err(|e| PluginError::servfail("template", e.to_string()))?;
            return Ok(t.rcode);
        }

        next_or_failure("template", &self.next, ctx, w, req).await
    }
}

#[cfg(test)]
mod tests;
