//! `rewrite`: rewrites the question of requests (name, type, class, EDNS0
//! options) and, in reverse, names, values, TTLs, RCODEs and CNAME targets
//! in responses. Port of `plugin/rewrite`.
//!
//! ```text
//! rewrite [continue|stop] FIELD [TYPE] [(FROM TO)|TTL] [OPTIONS]
//! ```
//!
//! FIELD is `name`, `type`, `class`, `edns0`, `ttl`, `cname` or `rcode`.
//!
//! Differences from CoreDNS: plugins only ever see a rewritten copy of the
//! request, so the server always echoes the client's original EDNS options;
//! `edns0 ... revert` is therefore accepted but changes nothing. EDNS0
//! options that hickory decodes into another type (subnet, NSID) are
//! matched by code.

use std::net::IpAddr;
use std::sync::Arc;

use kerndns_core::proto::op::{Edns, Message, ResponseCode};
use kerndns_core::proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption, NSIDPayload};
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, client_write, next_or_failure, result_rcode,
};
use regex::Regex;

const MAX_REGEXP_LEN: usize = 10000;
const MAX_CNAME_REWRITE_DEPTH: u8 = 8;

// ------------------------------------------------------- string rewriting

/// Replace `{N}` with capture group N, like the Go loop over groups.
fn expand(template: &str, caps: &regex::Captures<'_>) -> String {
    let mut s = template.to_string();
    for (i, g) in caps.iter().enumerate() {
        s = s.replace(&format!("{{{i}}}"), g.map_or("", |m| m.as_str()));
    }
    s
}

#[derive(Debug, Clone)]
enum StrRewriter {
    Regex(Regex, String),
    /// `remapStringRewriter`: the name, or a name ending in `.` + it.
    Remap(String, String),
    Suffix(String, String),
}

impl StrRewriter {
    fn apply(&self, src: &str) -> String {
        match self {
            StrRewriter::Regex(re, repl) => match re.captures(src) {
                Some(c) => expand(repl, &c),
                None => src.to_string(),
            },
            StrRewriter::Remap(orig, repl) => {
                if src == orig {
                    return repl.clone();
                }
                if src.len() > orig.len() {
                    let i = src.len() - orig.len();
                    if src.as_bytes()[i - 1] == b'.' && &src[i..] == orig {
                        return format!("{}{repl}", &src[..i]);
                    }
                }
                src.to_string()
            }
            StrRewriter::Suffix(suffix, repl) => match src.strip_suffix(suffix.as_str()) {
                Some(before) => format!("{before}{repl}"),
                None => src.to_string(),
            },
        }
    }
}

/// A name as CoreDNS's string form: presentation format, fully qualified.
fn name_str(n: &Name) -> String {
    let mut s = n.to_ascii();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

fn rewrite_name(n: &mut Name, rw: &StrRewriter) {
    let old = name_str(n);
    let new = rw.apply(&old);
    if new != old
        && let Ok(v) = Name::from_ascii(&new)
    {
        *n = v;
    }
}

/// `getRecordValueForRewrite`/`setRewrittenRecordValue`: the name a record
/// points at.
fn value_mut(r: &mut Record) -> Option<&mut Name> {
    match &mut r.data {
        RData::SRV(s) => Some(&mut s.target),
        RData::MX(m) => Some(&mut m.exchange),
        RData::CNAME(c) => Some(&mut c.0),
        RData::NS(n) => Some(&mut n.0),
        RData::NAPTR(n) => Some(&mut n.replacement),
        RData::SOA(s) => Some(&mut s.mname),
        RData::PTR(p) => Some(&mut p.0),
        _ => None,
    }
}

// -------------------------------------------------------- response rules

/// What a matched rule does to the response.
#[derive(Clone)]
enum RespRule {
    Name(StrRewriter),
    Value(StrRewriter),
    Ttl(u32, u32),
    Rcode(ResponseCode, ResponseCode),
    Cname(Arc<CnameRule>, Box<Request>),
    /// `edns0 ... revert`: the server never sees the rewritten request.
    None,
}

impl RespRule {
    fn apply_rr(&self, m: &mut Message, rr: &mut Record) {
        match self {
            RespRule::Name(rw) => rewrite_name(&mut rr.name, rw),
            RespRule::Value(rw) => {
                if let Some(v) = value_mut(rr) {
                    rewrite_name(v, rw);
                }
            }
            RespRule::Ttl(min, max) => {
                if rr.ttl < *min {
                    rr.ttl = *min;
                } else if rr.ttl > *max {
                    rr.ttl = *max;
                }
            }
            RespRule::Rcode(old, new) => {
                if m.metadata.response_code == *old {
                    m.metadata.response_code = *new;
                }
            }
            RespRule::Cname(..) | RespRule::None => {}
        }
    }
}

// ----------------------------------------------------------------- rules

/// The request as the rules see and change it.
struct State {
    req: Request,
}

impl State {
    fn name(&self) -> String {
        self.req.name()
    }

    fn set_name(&mut self, s: &str) -> Result<(), String> {
        let n = Name::from_ascii(s).map_err(|_| format!("invalid name after rewrite: {s}"))?;
        self.req.msg.queries[0].set_name(n);
        Ok(())
    }
}

trait Rule: Send + Sync {
    /// `Some` with the response rules if the rule applied.
    fn rewrite(&self, ctx: &Context, st: &mut State) -> Result<Option<Vec<RespRule>>, String>;
    fn stop(&self) -> bool;
}

#[derive(Clone, Copy, PartialEq)]
enum Match {
    Exact,
    Prefix,
    Suffix,
    Substring,
    Regex,
}

fn parse_match(s: &str) -> Option<Match> {
    Some(match s.to_ascii_lowercase().as_str() {
        "exact" => Match::Exact,
        "prefix" => Match::Prefix,
        "suffix" => Match::Suffix,
        "substring" => Match::Substring,
        "regex" => Match::Regex,
        _ => return None,
    })
}

/// `plugin.Name(s).Normalize()`: lowercase and fully qualified.
fn normalize(s: &str) -> String {
    let mut s = s.to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

fn subexp_usage(s: &str) -> usize {
    (0..=100).filter(|i| s.contains(&format!("{{{i}}}"))).count()
}

/// `isValidRegexPattern`.
fn valid_regex(from: &str, to: &str) -> Result<Regex, String> {
    if from.len() > MAX_REGEXP_LEN {
        return Err(format!("regex pattern too long: {} > {MAX_REGEXP_LEN}", from.len()));
    }
    let re = Regex::new(from).map_err(|_| format!("invalid regex matching pattern: {from}"))?;
    if subexp_usage(to) > re.captures_len() - 1 {
        return Err(format!(
            "the rewrite regex pattern ({to}) uses more subexpressions than its corresponding matching regex pattern ({from})"
        ));
    }
    Ok(re)
}

/// Matches a request name (`ttl`, `rcode` rules).
enum NameMatcher {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Substring(String),
    Regex(Regex),
}

impl NameMatcher {
    fn parse(kind: &str, arg: &str, rule: &str) -> Result<NameMatcher, String> {
        Ok(match parse_match(kind) {
            Some(Match::Exact) => NameMatcher::Exact(normalize(arg)),
            Some(Match::Prefix) => NameMatcher::Prefix(normalize(arg)),
            Some(Match::Suffix) => NameMatcher::Suffix(normalize(arg)),
            Some(Match::Substring) => NameMatcher::Substring(normalize(arg)),
            Some(Match::Regex) => {
                if arg.len() > MAX_REGEXP_LEN {
                    return Err(format!(
                        "regex pattern too long in a {rule} rule: {} > {MAX_REGEXP_LEN}",
                        arg.len()
                    ));
                }
                NameMatcher::Regex(
                    Regex::new(arg).map_err(|_| format!("invalid regex pattern in a {rule} rule: {arg}"))?,
                )
            }
            None => {
                return Err(format!(
                    "{rule} rule supports only exact, prefix, suffix, substring, and regex name matching"
                ));
            }
        })
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            NameMatcher::Exact(s) => name == s,
            NameMatcher::Prefix(s) => name.starts_with(s.as_str()),
            NameMatcher::Suffix(s) => name.ends_with(s.as_str()),
            NameMatcher::Substring(s) => name.contains(s.as_str()),
            NameMatcher::Regex(re) => re.is_match(name),
        }
    }
}

// ------------------------------------------------------------- name rule

enum NameKind {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Substring(String),
    Regex(Regex),
    /// Regex with `{group}` and `{metadata/label}` parts.
    Metadata(Regex, Vec<Part>),
}

enum Part {
    Literal(String),
    Group(usize),
    Label(String),
}

struct NameRule {
    stop: bool,
    kind: NameKind,
    replacement: String,
    auto: bool,
    statics: Vec<RespRule>,
}

impl Rule for NameRule {
    fn rewrite(&self, ctx: &Context, st: &mut State) -> Result<Option<Vec<RespRule>>, String> {
        let before = st.name();
        let new = match &self.kind {
            NameKind::Exact(from) => (from == &before).then(|| self.replacement.clone()),
            NameKind::Prefix(p) => before
                .strip_prefix(p.as_str())
                .map(|a| format!("{}{a}", self.replacement)),
            NameKind::Suffix(s) => before
                .strip_suffix(s.as_str())
                .map(|b| format!("{b}{}", self.replacement)),
            NameKind::Substring(s) => before
                .contains(s.as_str())
                .then(|| before.replace(s.as_str(), &self.replacement)),
            NameKind::Regex(re) => re.captures(&before).map(|c| expand(&self.replacement, &c)),
            NameKind::Metadata(re, parts) => {
                let Some(c) = re.captures(&before) else { return Ok(None) };
                let mut out = String::new();
                for p in parts {
                    match p {
                        Part::Literal(l) => out.push_str(l),
                        Part::Group(g) => out.push_str(c.get(*g).map_or("", |m| m.as_str())),
                        Part::Label(l) => match ctx.metadata.get(l) {
                            Some(v) if !v.is_empty() => out.push_str(&v.to_ascii_lowercase()),
                            _ => return Ok(None),
                        },
                    }
                }
                Some(out)
            }
        };
        let Some(new) = new else { return Ok(None) };
        let written = new.clone();
        st.set_name(&new)?;
        if !self.auto {
            return Ok(Some(self.statics.clone()));
        }
        // `answer auto`: map the new name back to the one asked for
        let rw = StrRewriter::Remap(written, before);
        let mut rules = vec![RespRule::Name(rw.clone()), RespRule::Value(rw)];
        rules.extend(self.statics.iter().cloned());
        Ok(Some(rules))
    }

    fn stop(&self) -> bool {
        self.stop
    }
}

/// `parseAnswerRules`.
fn parse_answer_rules(name: &str, args: &[String]) -> Result<(bool, Vec<RespRule>), String> {
    if args.len() < 2 {
        return Err(format!("invalid arguments for {name} rule"));
    }
    let (mut auto, mut rules, mut name_rules) = (false, Vec::new(), 0);
    let mut arg = 0;
    let mut last = String::new();
    while arg < args.len() {
        if last.is_empty() && args[arg] != "answer" {
            return Err(format!(
                "exceeded the number of arguments for a non-answer rule argument for {name} rule"
            ));
        }
        if args[arg] == "answer" {
            arg += 1;
        }
        if arg == args.len() {
            return Err(format!("type missing for answer rule for {name} rule"));
        }
        last = args[arg].clone();
        arg += 1;
        match last.as_str() {
            "auto" => auto = true,
            "name" | "value" => {
                if args.len() - arg < 2 {
                    return Err(format!("{last} answer rule for {name} rule: 2 arguments required"));
                }
                let re = valid_regex(&args[arg], &args[arg + 1])
                    .map_err(|e| format!("{last} answer rule for {name} rule: {e}"))?;
                let rw = StrRewriter::Regex(re, normalize(&args[arg + 1]));
                if last == "name" {
                    rules.push(RespRule::Name(rw));
                    name_rules += 1;
                } else {
                    rules.push(RespRule::Value(rw));
                }
                arg += 2;
            }
            other => return Err(format!("invalid type {other:?} for answer rule for {name} rule")),
        }
    }
    if auto && name_rules > 0 {
        return Err("auto name answer rule cannot be combined with explicit name anwer rules".into());
    }
    Ok((auto, rules))
}

/// `parseNameReplacement`.
fn parse_replacement(mut s: &str, groups: usize) -> Result<Vec<Part>, String> {
    let mut parts = Vec::new();
    while !s.is_empty() {
        let (before, rest) = match s.split_once('{') {
            Some((b, r)) => (b, Some(r)),
            None => (s, None),
        };
        if before.contains('}') {
            return Err("unmatched closing brace in metadata name replacement".into());
        }
        if !before.is_empty() {
            parts.push(Part::Literal(before.to_ascii_lowercase()));
        }
        let Some(rest) = rest else { break };
        let Some((label, after)) = rest.split_once('}') else {
            return Err("unclosed placeholder in metadata name replacement".into());
        };
        if let Ok(g) = label.parse::<usize>() {
            if g > groups {
                return Err(format!("capture group {label} does not exist in name matching pattern"));
            }
            parts.push(Part::Group(g));
        } else {
            // `metadata.IsLabel`: plugin/name
            let ok = label
                .split_once('/')
                .is_some_and(|(p, n)| !p.is_empty() && !n.is_empty() && !label.contains('{'));
            if !ok {
                return Err(format!("invalid metadata label {label:?} in name replacement"));
            }
            parts.push(Part::Label(label.to_string()));
        }
        s = after;
    }
    Ok(parts)
}

fn new_name_rule(stop: bool, args: &[String]) -> Result<Box<dyn Rule>, String> {
    if args.len() < 2 {
        return Err("too few arguments for a name rule".into());
    }
    let (kind, mut from, mut to) = if args.len() == 2 {
        (Match::Exact, normalize(&args[0]), normalize(&args[1]))
    } else {
        let Some(k) = parse_match(&args[0]) else {
            return Err(format!(
                "name rule supports only exact, prefix, suffix, substring, and regex name matching, received: {}",
                args[0].to_ascii_lowercase()
            ));
        };
        if k == Match::Regex {
            (k, args[1].clone(), args[2].clone())
        } else {
            (k, normalize(&args[1]), normalize(&args[2]))
        }
    };
    if matches!(kind, Match::Exact | Match::Suffix) {
        if !from.ends_with('.') {
            from.push('.');
        }
        if !to.ends_with('.') {
            to.push('.');
        }
    }
    let mut answer_start = 3;
    let with_metadata = args.len() > 3 && args[3] == "metadata";
    if with_metadata {
        if kind != Match::Regex {
            return Err("metadata is only supported for regex name rules".into());
        }
        answer_start += 1;
    }
    let (auto, answers) = if args.len() > answer_start {
        parse_answer_rules(&args[0].to_ascii_lowercase(), &args[answer_start..])?
    } else {
        (false, Vec::new())
    };
    let rule = match kind {
        Match::Exact => {
            valid_regex(&to, &from)?;
            NameRule {
                stop,
                kind: NameKind::Exact(from),
                replacement: to,
                auto: true,
                statics: answers,
            }
        }
        Match::Prefix => NameRule {
            stop,
            kind: NameKind::Prefix(from),
            replacement: to,
            auto,
            statics: answers,
        },
        Match::Suffix => {
            let mut statics = Vec::new();
            if auto {
                let rw = StrRewriter::Suffix(to.clone(), from.clone());
                statics.push(RespRule::Name(rw.clone()));
                statics.push(RespRule::Value(rw));
            }
            statics.extend(answers);
            NameRule {
                stop,
                kind: NameKind::Suffix(from),
                replacement: to,
                auto: false,
                statics,
            }
        }
        Match::Substring => NameRule {
            stop,
            kind: NameKind::Substring(from),
            replacement: to,
            auto,
            statics: answers,
        },
        Match::Regex if with_metadata => {
            let re = valid_regex(&from, "")?;
            let mut t = to.clone();
            if !t.ends_with('.') {
                t.push('.');
            }
            let parts = parse_replacement(&t, re.captures_len() - 1)?;
            NameRule {
                stop,
                kind: NameKind::Metadata(re, parts),
                replacement: String::new(),
                auto,
                statics: answers,
            }
        }
        Match::Regex => {
            let re = valid_regex(&from, &to)?;
            NameRule {
                stop,
                kind: NameKind::Regex(re),
                replacement: normalize(&args[2]),
                auto,
                statics: answers,
            }
        }
    };
    Ok(Box::new(rule))
}

// ------------------------------------------------------ type/class rules

struct TypeRule {
    stop: bool,
    from: RecordType,
    to: RecordType,
}

impl Rule for TypeRule {
    fn rewrite(&self, _: &Context, st: &mut State) -> Result<Option<Vec<RespRule>>, String> {
        let q = &mut st.req.msg.queries[0];
        if q.query_type() != self.from {
            return Ok(None);
        }
        q.set_query_type(self.to);
        Ok(Some(Vec::new()))
    }

    fn stop(&self) -> bool {
        self.stop
    }
}

struct ClassRule {
    stop: bool,
    from: DNSClass,
    to: DNSClass,
}

impl Rule for ClassRule {
    fn rewrite(&self, _: &Context, st: &mut State) -> Result<Option<Vec<RespRule>>, String> {
        let q = &mut st.req.msg.queries[0];
        if q.query_class() != self.from {
            return Ok(None);
        }
        q.set_query_class(self.to);
        Ok(Some(Vec::new()))
    }

    fn stop(&self) -> bool {
        self.stop
    }
}

fn parse_type(s: &str) -> Option<RecordType> {
    let up = s.to_ascii_uppercase();
    match up.as_str() {
        "IXFR" => Some(RecordType::IXFR),
        _ => up
            .parse::<RecordType>()
            .ok()
            .filter(|t| !matches!(t, RecordType::Unknown(_))),
    }
}

fn parse_class(s: &str) -> Option<DNSClass> {
    match s.to_ascii_uppercase().as_str() {
        "IN" => Some(DNSClass::IN),
        "CH" | "CHAOS" => Some(DNSClass::CH),
        "HS" => Some(DNSClass::HS),
        "NONE" => Some(DNSClass::NONE),
        "ANY" => Some(DNSClass::ANY),
        _ => None,
    }
}

// --------------------------------------------------------- ttl / rcode

struct MatchRule {
    stop: bool,
    matcher: NameMatcher,
    response: RespRule,
}

impl Rule for MatchRule {
    fn rewrite(&self, _: &Context, st: &mut State) -> Result<Option<Vec<RespRule>>, String> {
        Ok(self.matcher.matches(&st.name()).then(|| vec![self.response.clone()]))
    }

    fn stop(&self) -> bool {
        self.stop
    }
}

/// `isValidTTL`: `N`, `MIN-MAX`, `-MAX` or `MIN-`.
fn parse_ttl(v: &str) -> Option<(u32, u32)> {
    match v.split('-').collect::<Vec<_>>().as_slice() {
        [n] => n.parse().ok().map(|n| (n, n)),
        [min, max] => {
            let lo = if min.is_empty() { 0 } else { min.parse().ok()? };
            let hi = if max.is_empty() {
                if min.is_empty() {
                    return None;
                }
                2147483647
            } else {
                max.parse().ok()?
            };
            (lo <= hi).then_some((lo, hi))
        }
        _ => None,
    }
}

fn new_ttl_rule(stop: bool, args: &[String]) -> Result<Box<dyn Rule>, String> {
    if args.len() < 2 {
        return Err(format!("too few ({}) arguments for a ttl rule", args.len()));
    }
    if args.len() > 3 {
        return Err("many few arguments for a ttl rule".into());
    }
    let s = if args.len() == 2 { &args[1] } else { &args[2] };
    let Some((min, max)) = parse_ttl(s) else {
        return Err(format!("invalid TTL '{s}' for a ttl rule"));
    };
    let matcher = if args.len() == 3 {
        NameMatcher::parse(&args[0], &args[1], "ttl")?
    } else {
        NameMatcher::Exact(normalize(&args[0]))
    };
    Ok(Box::new(MatchRule {
        stop,
        matcher,
        response: RespRule::Ttl(min, max),
    }))
}

/// `isValidRCode`: a number up to 23 or a name.
fn parse_rcode(v: &str) -> Option<ResponseCode> {
    if let Ok(n) = v.parse::<u16>() {
        return (n <= 23).then(|| rcode_of(n));
    }
    let code: u16 = match v.to_ascii_uppercase().as_str() {
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
        "BADSIG" | "BADVERS" => 16,
        "BADKEY" => 17,
        "BADTIME" => 18,
        "BADMODE" => 19,
        "BADNAME" => 20,
        "BADALG" => 21,
        "BADTRUNC" => 22,
        "BADCOOKIE" => 23,
        _ => return None,
    };
    Some(rcode_of(code))
}

fn rcode_of(code: u16) -> ResponseCode {
    ResponseCode::from((code >> 4) as u8, (code & 0xF) as u8)
}

fn new_rcode_rule(stop: bool, args: &[String]) -> Result<Box<dyn Rule>, String> {
    if args.len() < 3 {
        return Err(format!("too few ({}) arguments for a rcode rule", args.len()));
    }
    if args.len() > 4 {
        return Err("many few arguments for a rcode rule".into());
    }
    let (old, new) = if args.len() == 3 {
        (&args[1], &args[2])
    } else {
        (&args[2], &args[3])
    };
    let Some(o) = parse_rcode(old) else {
        return Err(format!("invalid matching RCODE '{old}' for a rcode rule"));
    };
    let Some(n) = parse_rcode(new) else {
        return Err(format!("invalid replacement RCODE '{new}' for a rcode rule"));
    };
    let matcher = if args.len() == 4 {
        NameMatcher::parse(&args[0], &args[1], "rcode")?
    } else {
        NameMatcher::Exact(normalize(&args[0]))
    };
    Ok(Box::new(MatchRule {
        stop,
        matcher,
        response: RespRule::Rcode(o, n),
    }))
}

// ----------------------------------------------------------------- cname

struct CnameRule {
    stop: bool,
    kind: Match,
    from: String,
    to: String,
    pattern: Option<Regex>,
}

impl CnameRule {
    /// `getFromAndToTarget`.
    fn targets(&self, target: &str) -> Option<(String, String)> {
        match self.kind {
            Match::Exact => Some((self.from.clone(), self.to.clone())),
            Match::Prefix => target
                .strip_prefix(self.from.as_str())
                .map(|a| (target.to_string(), format!("{}{a}", self.to))),
            Match::Suffix => target
                .strip_suffix(self.from.as_str())
                .map(|b| (target.to_string(), format!("{b}{}", self.to))),
            Match::Substring => target
                .contains(self.from.as_str())
                .then(|| (target.to_string(), target.replace(self.from.as_str(), &self.to))),
            Match::Regex => self
                .pattern
                .as_ref()?
                .captures(target)
                .map(|c| (target.to_string(), expand(&self.to, &c))),
        }
    }
}

struct CnameRuleRef(Arc<CnameRule>);

impl Rule for CnameRuleRef {
    fn rewrite(&self, _: &Context, st: &mut State) -> Result<Option<Vec<RespRule>>, String> {
        Ok(Some(vec![RespRule::Cname(self.0.clone(), Box::new(st.req.clone()))]))
    }

    fn stop(&self) -> bool {
        self.0.stop
    }
}

fn new_cname_rule(stop: bool, args: &[String]) -> Result<Box<dyn Rule>, String> {
    let (kind, mut from, mut to) = match args.len() {
        3 => {
            let Some(k) = parse_match(&args[0]) else {
                return Err(format!("unknown cname rewrite type: {}", args[0].to_ascii_lowercase()));
            };
            (k, args[1].to_ascii_lowercase(), args[2].to_ascii_lowercase())
        }
        2 => (Match::Exact, args[0].to_ascii_lowercase(), args[1].to_ascii_lowercase()),
        n => return Err(format!("too few ({n}) arguments for a cname rule")),
    };
    if kind == Match::Exact {
        from = normalize(&from);
        to = normalize(&to);
    }
    let pattern = if kind == Match::Regex {
        if from.len() > MAX_REGEXP_LEN {
            return Err(format!(
                "regex pattern too long in a cname rule: {} > {MAX_REGEXP_LEN}",
                from.len()
            ));
        }
        Some(Regex::new(&from).map_err(|e| format!("invalid cname rewrite regex pattern: {e}"))?)
    } else {
        None
    };
    Ok(Box::new(CnameRuleRef(Arc::new(CnameRule {
        stop,
        kind,
        from,
        to,
        pattern,
    }))))
}

// ------------------------------------------------------------------ edns0

#[derive(Clone, Copy, PartialEq)]
enum Action {
    Append,
    Replace,
    Set,
    Unset,
}

enum EdnsKind {
    Local { code: u16, data: Vec<u8> },
    Variable { code: u16, var: String },
    Nsid,
    Subnet { v4: u8, v6: u8 },
}

struct EdnsRule {
    stop: bool,
    action: Action,
    kind: EdnsKind,
    /// `revert`: CoreDNS then serves through its response reverter.
    revert: bool,
}

fn code_of(k: &EdnsKind) -> u16 {
    match k {
        EdnsKind::Local { code, .. } | EdnsKind::Variable { code, .. } => *code,
        EdnsKind::Nsid => 3,
        EdnsKind::Subnet { .. } => 8,
    }
}

fn opt_code(o: &EdnsOption) -> u16 {
    u16::from(EdnsCode::from(o))
}

fn mask_ip(ip: IpAddr, bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let m = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(bits))
            };
            IpAddr::V4((u32::from(a) & m).into())
        }
        IpAddr::V6(a) => {
            let m = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(bits))
            };
            IpAddr::V6((u128::from(a) & m).into())
        }
    }
}

impl EdnsRule {
    /// `ruleData` for variable rules.
    fn variable(&self, ctx: &Context, req: &Request, var: &str) -> Option<Vec<u8>> {
        let ip = |ip: IpAddr| match ip {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        Some(match var {
            "{qname}" => name_str(req.qname()).into_bytes(),
            "{qtype}" => u16::from(req.qtype()).to_be_bytes().to_vec(),
            "{client_ip}" => ip(req.ip()),
            "{server_ip}" => ip(req.local.ip().to_canonical()),
            "{client_port}" => req.port().to_be_bytes().to_vec(),
            "{server_port}" => req.local.port().to_be_bytes().to_vec(),
            "{protocol}" => req.proto().as_bytes().to_vec(),
            _ => {
                let v = ctx.metadata.get(&var[1..var.len() - 1])?;
                if v.is_empty() {
                    return None;
                }
                v.clone().into_bytes()
            }
        })
    }

    fn option(&self, ctx: &Context, req: &Request) -> Option<EdnsOption> {
        Some(match &self.kind {
            EdnsKind::Local { code, data } => EdnsOption::Unknown(*code, data.clone()),
            EdnsKind::Variable { code, var } => EdnsOption::Unknown(*code, self.variable(ctx, req, var)?),
            EdnsKind::Nsid => EdnsOption::NSID(NSIDPayload::new(Vec::new()).ok()?),
            EdnsKind::Subnet { v4, v6 } => {
                let ip = req.ip();
                let bits = if ip.is_ipv4() { *v4 } else { *v6 };
                EdnsOption::Subnet(ClientSubnet::new(mask_ip(ip, bits), bits, 0))
            }
        })
    }
}

impl Rule for EdnsRule {
    fn rewrite(&self, ctx: &Context, st: &mut State) -> Result<Option<Vec<RespRule>>, String> {
        let code = code_of(&self.kind);
        // variable data is computed before the OPT is touched
        let new = if self.action == Action::Unset {
            None
        } else {
            match self.option(ctx, &st.req) {
                Some(o) => Some(o),
                None => return Ok(None),
            }
        };
        let opt = st.req.msg.edns.get_or_insert_with(|| {
            let mut e = Edns::new();
            e.set_max_payload(4096);
            e
        });
        let opts = &mut opt.options_mut().options;
        if self.action == Action::Unset {
            opts.retain(|(_, o)| opt_code(o) != code);
            return Ok(Some(vec![]));
        }
        let new = new.expect("set above");
        let done = if self.revert { vec![RespRule::None] } else { Vec::new() };
        if let Some((_, o)) = opts.iter_mut().find(|(_, o)| opt_code(o) == code) {
            if matches!(self.action, Action::Replace | Action::Set) {
                *o = new;
                return Ok(Some(done));
            }
            // like CoreDNS: an existing option isn't appended twice for
            // variable and subnet rules; local and nsid rules append anyway
            if matches!(self.kind, EdnsKind::Variable { .. } | EdnsKind::Subnet { .. }) {
                return Ok(None);
            }
        }
        if matches!(self.action, Action::Append | Action::Set) {
            opts.push(((&new).into(), new));
            return Ok(Some(done));
        }
        Ok(None)
    }

    fn stop(&self) -> bool {
        self.stop
    }
}

const VARIABLES: [&str; 7] = [
    "{qname}",
    "{qtype}",
    "{client_ip}",
    "{client_port}",
    "{protocol}",
    "{server_ip}",
    "{server_port}",
];

/// `strconv.ParseUint(s, 0, 16)`: decimal, `0x` hex or `0` octal.
fn parse_uint16(s: &str) -> Result<u16, String> {
    let r = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(h, 16)
    } else if let Some(o) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        u16::from_str_radix(o, 8)
    } else if s.len() > 1 && s.starts_with('0') {
        u16::from_str_radix(&s[1..], 8)
    } else {
        s.parse()
    };
    r.map_err(|_| format!("strconv.ParseUint: parsing {s:?}: invalid syntax"))
}

fn new_edns_rule(stop: bool, args: &[String]) -> Result<Box<dyn Rule>, String> {
    if args.len() < 2 {
        return Err("too few arguments for an EDNS0 rule".into());
    }
    let kind_s = args[0].to_ascii_lowercase();
    let action = match args[1].to_ascii_lowercase().as_str() {
        "append" => Action::Append,
        "replace" => Action::Replace,
        "set" => Action::Set,
        "unset" => Action::Unset,
        a => return Err(format!("invalid action: {a:?}")),
    };
    let revert = action != Action::Unset && args.last().is_some_and(|a| a == "revert");
    let rule = |kind| -> Result<Box<dyn Rule>, String> {
        Ok(Box::new(EdnsRule {
            stop,
            action,
            kind,
            revert,
        }))
    };
    if action == Action::Unset {
        return match kind_s.as_str() {
            "local" if args.len() == 3 => rule(EdnsKind::Local {
                code: parse_uint16(&args[2])?,
                data: Vec::new(),
            }),
            "local" => Err("local unset action requires exactly two arguments".into()),
            "nsid" if args.len() == 2 => rule(EdnsKind::Nsid),
            "nsid" => Err("nsid unset action requires exactly one argument".into()),
            "subnet" if args.len() == 2 => rule(EdnsKind::Subnet { v4: 0, v6: 0 }),
            "subnet" => Err("subnet unset action requires exactly one argument".into()),
            _ => Err(format!("invalid rule type {kind_s:?}")),
        };
    }
    let mut args = args.to_vec();
    if args.last().is_some_and(|a| a == "revert") {
        args.pop();
    }
    match kind_s.as_str() {
        "local" => {
            if args.len() != 4 {
                return Err("EDNS0 local rules require three or four args".into());
            }
            let code = parse_uint16(&args[2])?;
            let data = &args[3];
            if data.starts_with('{') && data.ends_with('}') {
                let label_ok = data[1..data.len() - 1]
                    .split_once('/')
                    .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty());
                if !VARIABLES.contains(&data.as_str()) && !label_ok {
                    return Err(format!("unsupported variable name {data:?}"));
                }
                return rule(EdnsKind::Variable {
                    code,
                    var: data.clone(),
                });
            }
            let bytes = match data.strip_prefix("0x") {
                Some(h) => data_encoding::HEXLOWER_PERMISSIVE
                    .decode(h.as_bytes())
                    .map_err(|_| format!("encoding/hex: invalid byte in {h:?}"))?,
                None => data.as_bytes().to_vec(),
            };
            rule(EdnsKind::Local { code, data: bytes })
        }
        "nsid" => {
            if args.len() != 2 {
                return Err("EDNS0 NSID rules can accept no more than one arg".into());
            }
            rule(EdnsKind::Nsid)
        }
        "subnet" => {
            if args.len() != 4 {
                return Err("EDNS0 subnet rules require three or four args".into());
            }
            let v4 = parse_uint16(&args[2])?;
            if v4 > 32 {
                return Err(format!("invalid IPv4 bit mask length {v4}"));
            }
            let v6 = parse_uint16(&args[3])?;
            if v6 > 128 {
                return Err(format!("invalid IPv6 bit mask length {v6}"));
            }
            rule(EdnsKind::Subnet {
                v4: v4 as u8,
                v6: v6 as u8,
            })
        }
        _ => Err(format!("invalid rule type {kind_s:?}")),
    }
}

/// `newRule`.
fn new_rule(args: &[String]) -> Result<Box<dyn Rule>, String> {
    if args.is_empty() {
        return Err("no rule type specified for rewrite".into());
    }
    let (stop, rest) = match args[0].to_ascii_lowercase().as_str() {
        "continue" => {
            if args.len() < 2 {
                return Err("continue rule must begin with a rule type".into());
            }
            (false, &args[1..])
        }
        "stop" => {
            if args.len() < 2 {
                return Err("stop rule must begin with a rule type".into());
            }
            (true, &args[1..])
        }
        _ => (true, args),
    };
    let ty = rest[0].to_ascii_lowercase();
    let params = &rest[1..];
    match ty.as_str() {
        "answer" => Err("response rewrites must begin with a name rule".into()),
        "name" => new_name_rule(stop, params),
        "class" | "type" => {
            if rest.len() != 3 {
                return Err(format!("{ty} rules must have exactly two arguments"));
            }
            if ty == "class" {
                let from = parse_class(&params[0])
                    .ok_or_else(|| format!("invalid class {:?}", params[0].to_ascii_uppercase()))?;
                let to = parse_class(&params[1])
                    .ok_or_else(|| format!("invalid class {:?}", params[1].to_ascii_uppercase()))?;
                Ok(Box::new(ClassRule { stop, from, to }))
            } else {
                let from = parse_type(&params[0])
                    .ok_or_else(|| format!("invalid type {:?}", params[0].to_ascii_uppercase()))?;
                let to = parse_type(&params[1])
                    .ok_or_else(|| format!("invalid type {:?}", params[1].to_ascii_uppercase()))?;
                Ok(Box::new(TypeRule { stop, from, to }))
            }
        }
        "edns0" => new_edns_rule(stop, params),
        "ttl" => new_ttl_rule(stop, params),
        "cname" => new_cname_rule(stop, params),
        "rcode" => new_rcode_rule(stop, params),
        _ => Err(format!("invalid rule type {:?}", args[0])),
    }
}

// ---------------------------------------------------------------- plugin

pub struct Rewrite {
    next: Next,
    rules: Arc<Vec<Box<dyn Rule>>>,
}

/// `ResponseReverter`: restores the question and applies the response
/// rules (in reverse order).
struct Reverter<'a> {
    inner: &'a mut dyn ResponseWriter,
    original: kerndns_core::proto::op::Query,
    rules: Vec<RespRule>,
    ctx: Context,
}

/// The response half of the reverter; borrows only what it needs, so it
/// can run across awaits (CNAME lookups) without the inner writer.
struct Reverse<'a> {
    original: &'a kerndns_core::proto::op::Query,
    rules: &'a [RespRule],
    ctx: &'a Context,
}

impl Reverse<'_> {
    async fn rewrite(&self, mut m: Message) -> Message {
        if m.queries.is_empty() {
            m.queries.push(self.original.clone());
        } else {
            m.queries[0] = self.original.clone();
        }
        if self.rules.is_empty() {
            return m;
        }
        let rules: Vec<&RespRule> = self.rules.iter().rev().collect();
        let mut sections = [
            std::mem::take(&mut m.authorities),
            std::mem::take(&mut m.answers),
            std::mem::take(&mut m.additionals),
        ];
        let any = sections.iter().any(|s| !s.is_empty());
        for s in sections.iter_mut() {
            for rr in s.iter_mut() {
                for r in &rules {
                    r.apply_rr(&mut m, rr);
                }
            }
        }
        let [ns, an, ex] = sections;
        (m.authorities, m.answers, m.additionals) = (ns, an, ex);
        if !any {
            for r in &rules {
                if let RespRule::Rcode(..) = r {
                    r.apply_rr(&mut m, &mut Record::update0(Name::root(), 0, RecordType::A));
                }
            }
        }
        for r in &rules {
            if let RespRule::Cname(rule, req) = r {
                self.cname(&mut m, rule, req).await;
            }
        }
        m
    }

    /// `cnameTargetRuleWithReqState.RewriteResponse` for each CNAME.
    async fn cname(&self, m: &mut Message, rule: &CnameRule, req: &Request) {
        let targets: Vec<String> = m
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::CNAME(c) => Some(name_str(&c.0)),
                _ => None,
            })
            .collect();
        for target in targets {
            let Some((from, to)) = rule.targets(&target) else {
                continue;
            };
            if target != from || self.ctx.loop_count > MAX_CNAME_REWRITE_DEPTH {
                continue;
            }
            let Ok(to_name) = Name::from_ascii(&to) else { continue };
            let mut ctx = self.ctx.clone();
            ctx.loop_count += 1;
            let up = match kerndns_core::upstream::lookup(&ctx, req, &to_name, req.qtype()).await {
                Ok(Some(u)) => u,
                Ok(None) => {
                    kerndns_core::error!(plugin = "rewrite", "upstream lookup returned nil");
                    continue;
                }
                Err(e) => {
                    kerndns_core::error!(plugin = "rewrite", "upstream lookup failed: {}", e.msg);
                    continue;
                }
            };
            let mut answers = Vec::new();
            for mut r in std::mem::take(&mut m.answers) {
                if let RData::CNAME(c) = &mut r.data {
                    let hit = name_str(&c.0) == from;
                    if hit {
                        c.0 = to_name.clone();
                    }
                    answers.push(r);
                    if hit {
                        break;
                    }
                }
            }
            answers.extend(up.answers);
            m.answers = answers;
            m.metadata.truncation = up.metadata.truncation;
        }
    }
}

#[async_trait]
impl ResponseWriter for Reverter<'_> {
    async fn write_msg(&mut self, m: Message) -> std::io::Result<()> {
        let m = Reverse {
            original: &self.original,
            rules: &self.rules,
            ctx: &self.ctx,
        }
        .rewrite(m)
        .await;
        self.inner.write_msg(m).await
    }
}

#[async_trait]
impl Handler for Rewrite {
    fn name(&self) -> &'static str {
        "rewrite"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        if req.msg.queries.is_empty() {
            return next_or_failure("rewrite", &self.next, ctx, w, req).await;
        }
        let mut st = State { req: req.clone() };
        let mut resp: Vec<RespRule> = Vec::new();
        let mut stopped = false;
        for rule in self.rules.iter() {
            let r = rule
                .rewrite(ctx, &mut st)
                .map_err(|e| PluginError::servfail("rewrite", e))?;
            if let Some(rs) = r {
                resp.extend(rs);
                if rule.stop() {
                    stopped = true;
                    break;
                }
            }
        }
        // like CoreDNS: without response rules (and no `stop` match) the
        // answer goes out as is, rewritten question included
        if !stopped && resp.is_empty() {
            return next_or_failure("rewrite", &self.next, ctx, w, &st.req).await;
        }
        let mut wr = Reverter {
            inner: w,
            original: req.msg.queries[0].clone(),
            rules: resp,
            ctx: ctx.clone(),
        };
        let res = next_or_failure("rewrite", &self.next, ctx, &mut wr, &st.req).await;
        let rcode = result_rcode(&res);
        if client_write(rcode) {
            return res;
        }
        // `serveWithResponseReverter`: answer the error ourselves so the
        // response rules (e.g. an rcode rewrite) apply to it too
        let mut m = st.req.error_reply(rcode);
        st.req.size_and_do(&mut m);
        let _ = wr.write_msg(m).await;
        match res {
            Err(mut e) => {
                e.rcode = ResponseCode::NoError;
                Err(e)
            }
            Ok(_) => Ok(ResponseCode::NoError),
        }
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "rewrite"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut rules: Vec<Box<dyn Rule>> = Vec::new();
        while c.next() {
            let mut args = c.remaining_args();
            if args.len() < 2 {
                while c.next_block() {
                    args.push(c.val().to_string());
                }
            }
            rules.push(new_rule(&args).map_err(|e| SetupError::new("rewrite", e))?);
        }
        let rules = Arc::new(rules);
        c.add_plugin(move |next| {
            Arc::new(Rewrite {
                next,
                rules: rules.clone(),
            })
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn rule(s: &str) -> Result<Box<dyn Rule>, String> {
        new_rule(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn parse_errors() {
        for (r, e) in [
            ("", "no rule type"),
            ("continue", "must begin with a rule type"),
            ("answer name a b", "must begin with a name rule"),
            ("type MX", "exactly two arguments"),
            ("type MX XX", "invalid type \"XX\""),
            ("class IN XX", "invalid class"),
            ("name foo", "too few arguments"),
            ("name blah a b", "only exact, prefix"),
            ("name regex (a) {1}{2}.", "more subexpressions"),
            ("name regex (.*) {1} answer auto answer name x y", "cannot be combined"),
            ("name prefix a b metadata", "only supported for regex"),
            ("ttl a.b", "too few"),
            ("ttl a.b x-1", "invalid TTL"),
            ("ttl blah a.b 1", "only exact, prefix"),
            ("rcode a.b SERVFAIL", "too few"),
            ("rcode a.b XX NXDOMAIN", "invalid matching RCODE"),
            ("edns0 local blah 1 2", "invalid action"),
            ("edns0 local set 0xffee", "three or four args"),
            ("edns0 local set 0xffee {nope}", "unsupported variable"),
            ("edns0 subnet set 33 56", "invalid IPv4 bit mask"),
            ("cname blah a b", "unknown cname rewrite type"),
            ("foo a b", "invalid rule type"),
        ] {
            match rule(r) {
                Ok(_) => panic!("{r:?} parsed"),
                Err(got) => assert!(got.contains(e), "{r:?}: {got}"),
            }
        }
        for r in [
            "name example.com example.org",
            "stop name suffix .a. .b. answer auto",
            "continue name regex (.*)\\.test\\.$ {1}. answer auto",
            "name regex (.*)\\.x\\.$ {1}.{kubernetes/ns}. metadata answer auto",
            "ttl regex .* 10-",
            "rcode suffix .example. SERVFAIL 3",
            "edns0 local set 0xffee hello-world revert",
            "edns0 local append 0xffee {client_ip}",
            "edns0 nsid set",
            "edns0 subnet set 24 56",
            "cname exact a. b.",
            "class CH IN",
        ] {
            assert!(rule(r).is_ok(), "{r}: {:?}", rule(r).err());
        }
    }

    #[test]
    fn ttls() {
        assert_eq!(parse_ttl("5"), Some((5, 5)));
        assert_eq!(parse_ttl("-10"), Some((0, 10)));
        assert_eq!(parse_ttl("10-"), Some((10, 2147483647)));
        assert_eq!(parse_ttl("-"), None);
        assert_eq!(parse_ttl("10-5"), None);
    }

    fn rewrite_of(rules: &[&str], next: Next) -> Rewrite {
        Rewrite {
            next,
            rules: Arc::new(rules.iter().map(|r| rule(r).unwrap()).collect()),
        }
    }

    fn a(name: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            300,
            RData::A(kerndns_core::proto::rr::rdata::A::new(192, 0, 2, 1)),
        )
    }

    #[tokio::test]
    async fn name_with_answer_auto_and_ttl() {
        // the backend sees the rewritten name; the client its own name back
        let seen = Arc::new(std::sync::Mutex::new(String::new()));
        let s2 = seen.clone();
        let h = rewrite_of(
            &[
                "continue name regex (.*)\\.test\\.$ {1}.example.org. answer auto",
                "ttl regex .* 10-60",
            ],
            reply(move |r| {
                *s2.lock().unwrap() = r.name();
                let mut m = r.reply();
                m.answers.push(a(&r.name()));
                m
            }),
        );
        let (res, w) = serve(&h, &query("www.test.", RecordType::A, "10.0.0.1:53")).await;
        assert!(res.is_ok());
        assert_eq!(*seen.lock().unwrap(), "www.example.org.");
        let m = &w.msgs[0];
        assert_eq!(name_str(m.queries[0].name()), "www.test.");
        assert_eq!(name_str(&m.answers[0].name), "www.test.");
        assert_eq!(m.answers[0].ttl, 60);
    }

    #[tokio::test]
    async fn type_and_rcode() {
        let h = rewrite_of(
            &["continue type MX A", "rcode exact x.example. NXDOMAIN NOERROR"],
            reply(|r| {
                assert_eq!(r.qtype(), RecordType::A);
                r.error_reply(ResponseCode::NXDomain)
            }),
        );
        let (_, w) = serve(&h, &query("x.example.", RecordType::MX, "10.0.0.1:53")).await;
        let m = &w.msgs[0];
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        assert_eq!(m.queries[0].query_type(), RecordType::MX, "question restored");
    }

    #[tokio::test]
    async fn failure_keeps_original_question() {
        // TestRewriteFailure: no next plugin, the SERVFAIL names the asked name
        let h = rewrite_of(&["name regex (.*)\\.test\\.$ {1}. answer auto"], None);
        let (res, w) = serve(&h, &query("example.test.", RecordType::MX, "10.0.0.1:53")).await;
        assert!(res.is_err());
        let m = &w.msgs[0];
        assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(name_str(m.queries[0].name()), "example.test.");
    }

    #[tokio::test]
    async fn edns0_local() {
        let got = Arc::new(std::sync::Mutex::new(None));
        let g2 = got.clone();
        let h = rewrite_of(
            &["edns0 local set 0xffee hello-world"],
            reply(move |r| {
                *g2.lock().unwrap() = r.edns().and_then(|e| e.option(EdnsCode::from(0xffee))).cloned();
                r.reply()
            }),
        );
        let _ = serve(&h, &query("x.example.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(
            *got.lock().unwrap(),
            Some(EdnsOption::Unknown(0xffee, b"hello-world".to_vec()))
        );
    }
}
