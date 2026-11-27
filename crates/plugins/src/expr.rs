//! A small evaluator for the expr-lang (github.com/expr-lang/expr) subset
//! that CoreDNS's `view` expressions use, over the environment of
//! `plugin/pkg/expression.DefaultEnv`.
//!
//! Supported: string (`'...'`, `"..."`), integer, float, `true`/`false`/
//! `nil` and list (`[a, b]`) literals; the environment functions `type()`,
//! `name()`, `class()`, `proto()`, `size()`, `client_ip()`, `port()`,
//! `id()`, `opcode()`, `do()`, `bufsize()`, `server_ip()`, `server_port()`,
//! `incidr(ip, cidr)` and `metadata(label)`; the builtins `len`, `lower`,
//! `upper`, `trim`, `hasPrefix`, `hasSuffix`, `int`, `string`; the
//! operators `or ||`, `and &&`, `not !`, `== != < <= > >=`, `in`, `not in`,
//! `matches`, `contains`, `startsWith`, `endsWith`, `+ - * / %`, unary
//! `-`, and parentheses. Anything else fails at setup.

use std::net::IpAddr;

use kerndns_core::{Context, Request};
use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Nil,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
}

#[derive(Debug, Clone)]
enum Tok {
    Str(String),
    Int(i64),
    Float(f64),
    Ident(String),
    Op(&'static str),
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    const OPS: [&str; 18] = [
        "==", "!=", "<=", ">=", "&&", "||", "<", ">", "!", "+", "-", "*", "/", "%", "(", ")", "[", "]",
    ];
    while i < b.len() {
        let c = b[i] as char;
        if c.is_whitespace() {
            i += 1;
        } else if c == '\'' || c == '"' {
            let q = b[i];
            let mut s = String::new();
            i += 1;
            loop {
                let Some(&ch) = b.get(i) else {
                    return Err("unterminated string".into());
                };
                if ch == q {
                    i += 1;
                    break;
                }
                if ch == b'\\' {
                    i += 1;
                    let e = *b.get(i).ok_or("unterminated string")?;
                    s.push(match e {
                        b'n' => '\n',
                        b't' => '\t',
                        b'r' => '\r',
                        other => other as char,
                    });
                    i += 1;
                    continue;
                }
                // keep UTF-8 intact
                let len = utf8_len(ch);
                s.push_str(std::str::from_utf8(&b[i..i + len]).map_err(|e| e.to_string())?);
                i += len;
            }
            out.push(Tok::Str(s));
        } else if c.is_ascii_digit() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.' || b[i] == b'_') {
                i += 1;
            }
            let t = src[start..i].replace('_', "");
            out.push(if t.contains('.') {
                Tok::Float(t.parse().map_err(|_| format!("invalid number {t}"))?)
            } else {
                Tok::Int(t.parse().map_err(|_| format!("invalid number {t}"))?)
            });
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push(Tok::Ident(src[start..i].to_string()));
        } else if c == ',' {
            out.push(Tok::Op(","));
            i += 1;
        } else if let Some(op) = OPS.iter().find(|op| src[i..].starts_with(**op)) {
            out.push(Tok::Op(op));
            i += op.len();
        } else {
            return Err(format!("unexpected character {c:?}"));
        }
    }
    Ok(out)
}

fn utf8_len(first: u8) -> usize {
    match first {
        0..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

#[derive(Debug)]
enum Expr {
    Lit(Value),
    List(Vec<Expr>),
    Call(String, Vec<Expr>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Bin(&'static str, Box<Expr>, Box<Expr>),
    /// `matches` with a literal pattern, compiled at setup.
    Matches(Box<Expr>, Regex),
}

/// The environment's functions and their argument counts.
const ENV: [(&str, usize); 15] = [
    ("type", 0),
    ("name", 0),
    ("class", 0),
    ("proto", 0),
    ("size", 0),
    ("client_ip", 0),
    ("port", 0),
    ("id", 0),
    ("opcode", 0),
    ("do", 0),
    ("bufsize", 0),
    ("server_ip", 0),
    ("server_port", 0),
    ("incidr", 2),
    ("metadata", 1),
];

const BUILTINS: [(&str, usize); 8] = [
    ("len", 1),
    ("lower", 1),
    ("upper", 1),
    ("trim", 1),
    ("hasPrefix", 2),
    ("hasSuffix", 2),
    ("int", 1),
    ("string", 1),
];

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn peek_word(&self) -> Option<&str> {
        match self.peek()? {
            Tok::Ident(s) => Some(s.as_str()),
            Tok::Op(o) => Some(o),
            _ => None,
        }
    }

    fn eat(&mut self, w: &str) -> bool {
        if self.peek_word() == Some(w) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, w: &str) -> Result<(), String> {
        if self.eat(w) {
            Ok(())
        } else {
            Err(format!("expected {w:?}"))
        }
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut l = self.and()?;
        while self.eat("or") || self.eat("||") {
            l = Expr::Bin("or", Box::new(l), Box::new(self.and()?));
        }
        Ok(l)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut l = self.cmp()?;
        while self.eat("and") || self.eat("&&") {
            l = Expr::Bin("and", Box::new(l), Box::new(self.cmp()?));
        }
        Ok(l)
    }

    fn cmp(&mut self) -> Result<Expr, String> {
        let mut l = self.add()?;
        loop {
            let op = match self.peek_word() {
                Some(o @ ("==" | "!=" | "<" | "<=" | ">" | ">=")) => match o {
                    "==" => "==",
                    "!=" => "!=",
                    "<" => "<",
                    "<=" => "<=",
                    ">" => ">",
                    _ => ">=",
                },
                Some("in") => "in",
                Some("contains") => "contains",
                Some("startsWith") => "startsWith",
                Some("endsWith") => "endsWith",
                Some("matches") => "matches",
                Some("not") if matches!(self.toks.get(self.pos + 1), Some(Tok::Ident(s)) if s == "in") => {
                    self.pos += 2;
                    let r = self.add()?;
                    l = Expr::Not(Box::new(Expr::Bin("in", Box::new(l), Box::new(r))));
                    continue;
                }
                _ => return Ok(l),
            };
            self.pos += 1;
            let r = self.add()?;
            l = match (op, r) {
                ("matches", Expr::Lit(Value::Str(p))) => Expr::Matches(
                    Box::new(l),
                    Regex::new(&p).map_err(|e| format!("invalid regex {p:?}: {e}"))?,
                ),
                ("matches", _) => return Err("matches needs a string literal pattern".into()),
                (op, r) => Expr::Bin(op, Box::new(l), Box::new(r)),
            };
        }
    }

    fn add(&mut self) -> Result<Expr, String> {
        let mut l = self.mul()?;
        loop {
            let op = if self.eat("+") {
                "+"
            } else if self.eat("-") {
                "-"
            } else {
                return Ok(l);
            };
            l = Expr::Bin(op, Box::new(l), Box::new(self.mul()?));
        }
    }

    fn mul(&mut self) -> Result<Expr, String> {
        let mut l = self.unary()?;
        loop {
            let op = if self.eat("*") {
                "*"
            } else if self.eat("/") {
                "/"
            } else if self.eat("%") {
                "%"
            } else {
                return Ok(l);
            };
            l = Expr::Bin(op, Box::new(l), Box::new(self.unary()?));
        }
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat("!") || self.eat("not") {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        if self.eat("-") {
            return Ok(Expr::Neg(Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        let Some(t) = self.toks.get(self.pos).cloned() else {
            return Err("unexpected end of expression".into());
        };
        self.pos += 1;
        match t {
            Tok::Str(s) => Ok(Expr::Lit(Value::Str(s))),
            Tok::Int(i) => Ok(Expr::Lit(Value::Int(i))),
            Tok::Float(f) => Ok(Expr::Lit(Value::Float(f))),
            Tok::Op("(") => {
                let e = self.or()?;
                self.expect(")")?;
                Ok(e)
            }
            Tok::Op("[") => {
                let mut items = Vec::new();
                if !self.eat("]") {
                    loop {
                        items.push(self.or()?);
                        if self.eat("]") {
                            break;
                        }
                        self.expect(",")?;
                    }
                }
                Ok(Expr::List(items))
            }
            Tok::Ident(id) => match id.as_str() {
                "true" => Ok(Expr::Lit(Value::Bool(true))),
                "false" => Ok(Expr::Lit(Value::Bool(false))),
                "nil" => Ok(Expr::Lit(Value::Nil)),
                _ => {
                    let Some(&(_, arity)) = ENV.iter().chain(BUILTINS.iter()).find(|(n, _)| *n == id) else {
                        return Err(format!("unknown name {id}"));
                    };
                    if !self.eat("(") {
                        return Err(format!("{id} must be called: {id}()"));
                    }
                    let mut args = Vec::new();
                    if !self.eat(")") {
                        loop {
                            args.push(self.or()?);
                            if self.eat(")") {
                                break;
                            }
                            self.expect(",")?;
                        }
                    }
                    if args.len() != arity {
                        return Err(format!("{id} takes {arity} arguments, got {}", args.len()));
                    }
                    Ok(Expr::Call(id, args))
                }
            },
            Tok::Op(o) => Err(format!("unexpected {o:?}")),
        }
    }
}

/// A compiled expression.
#[derive(Debug)]
pub struct Program(Expr);

impl Program {
    pub fn compile(src: &str) -> Result<Program, String> {
        let mut p = Parser {
            toks: lex(src)?,
            pos: 0,
        };
        let e = p.or()?;
        if p.pos != p.toks.len() {
            return Err(format!("unexpected token at position {} in {src:?}", p.pos));
        }
        Ok(Program(e))
    }

    /// Evaluate; errors (type mismatches) are `Err`.
    pub fn run(&self, ctx: &Context, req: &Request) -> Result<Value, String> {
        eval(&self.0, ctx, req)
    }
}

fn truthy(v: &Value) -> Result<bool, String> {
    match v {
        Value::Bool(b) => Ok(*b),
        other => Err(format!("expected bool, got {other:?}")),
    }
}

fn s(v: Value) -> Result<String, String> {
    match v {
        Value::Str(s) => Ok(s),
        other => Err(format!("expected string, got {other:?}")),
    }
}

fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Int(i) => Some(*i as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    }
}

fn equal(a: &Value, b: &Value) -> bool {
    match (num(a), num(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

fn env(name: &str, args: Vec<Value>, ctx: &Context, req: &Request) -> Result<Value, String> {
    let ip_s = |ip: IpAddr| ip.to_canonical().to_string();
    Ok(match name {
        "type" => Value::Str(req.qtype().to_string()),
        "name" => Value::Str(req.name()),
        "class" => Value::Str(req.qclass().to_string()),
        "proto" => Value::Str(req.proto().to_string()),
        "size" => Value::Int(req.wire.as_ref().map_or(0, |w| w.len()) as i64),
        "client_ip" => Value::Str(req.ip().to_string()),
        "port" => Value::Str(req.port().to_string()),
        "id" => Value::Int(i64::from(req.msg.metadata.id)),
        "opcode" => Value::Int(i64::from(u8::from(req.msg.metadata.op_code))),
        "do" => Value::Bool(req.do_bit()),
        "bufsize" => Value::Int(i64::from(req.size())),
        "server_ip" => Value::Str(ip_s(req.local.ip())),
        "server_port" => Value::Str(req.local.port().to_string()),
        "metadata" => {
            let l = s(args.into_iter().next().unwrap_or(Value::Nil))?;
            Value::Str(ctx.metadata.get(&l).cloned().unwrap_or_default())
        }
        "incidr" => {
            let mut it = args.into_iter();
            let ip: IpAddr = s(it.next().unwrap_or(Value::Nil))?
                .parse()
                .map_err(|_| "first argument is not an IP address".to_string())?;
            let cidr = s(it.next().unwrap_or(Value::Nil))?;
            let (net, bits) = cidr
                .split_once('/')
                .ok_or_else(|| format!("invalid CIDR address: {cidr}"))?;
            let net: IpAddr = net.parse().map_err(|_| format!("invalid CIDR address: {cidr}"))?;
            let bits: u32 = bits.parse().map_err(|_| format!("invalid CIDR address: {cidr}"))?;
            let ip = ip.to_canonical();
            Value::Bool(match (ip, net) {
                (IpAddr::V4(a), IpAddr::V4(n)) if bits <= 32 => {
                    let m = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                    u32::from(a) & m == u32::from(n) & m
                }
                (IpAddr::V6(a), IpAddr::V6(n)) if bits <= 128 => {
                    let m = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                    u128::from(a) & m == u128::from(n) & m
                }
                (_, _) if bits > 128 => return Err(format!("invalid CIDR address: {cidr}")),
                _ => false,
            })
        }
        "len" => match args.into_iter().next() {
            Some(Value::Str(x)) => Value::Int(x.chars().count() as i64),
            Some(Value::List(l)) => Value::Int(l.len() as i64),
            other => return Err(format!("invalid argument for len: {other:?}")),
        },
        "lower" => Value::Str(s(args.into_iter().next().unwrap_or(Value::Nil))?.to_lowercase()),
        "upper" => Value::Str(s(args.into_iter().next().unwrap_or(Value::Nil))?.to_uppercase()),
        "trim" => Value::Str(s(args.into_iter().next().unwrap_or(Value::Nil))?.trim().to_string()),
        "hasPrefix" | "hasSuffix" => {
            let mut it = args.into_iter();
            let (a, b) = (s(it.next().unwrap_or(Value::Nil))?, s(it.next().unwrap_or(Value::Nil))?);
            Value::Bool(if name == "hasPrefix" {
                a.starts_with(&b)
            } else {
                a.ends_with(&b)
            })
        }
        "int" => match args.into_iter().next() {
            Some(Value::Int(i)) => Value::Int(i),
            Some(Value::Float(f)) => Value::Int(f as i64),
            Some(Value::Str(x)) => Value::Int(x.trim().parse().map_err(|_| format!("invalid int {x:?}"))?),
            other => return Err(format!("invalid argument for int: {other:?}")),
        },
        "string" => Value::Str(match args.into_iter().next() {
            Some(Value::Str(x)) => x,
            Some(Value::Int(i)) => i.to_string(),
            Some(Value::Float(f)) => f.to_string(),
            Some(Value::Bool(b)) => b.to_string(),
            other => return Err(format!("invalid argument for string: {other:?}")),
        }),
        other => return Err(format!("unknown function {other}")),
    })
}

fn eval(e: &Expr, ctx: &Context, req: &Request) -> Result<Value, String> {
    Ok(match e {
        Expr::Lit(v) => v.clone(),
        Expr::List(items) => Value::List(items.iter().map(|i| eval(i, ctx, req)).collect::<Result<_, _>>()?),
        Expr::Call(name, args) => {
            let args = args.iter().map(|a| eval(a, ctx, req)).collect::<Result<Vec<_>, _>>()?;
            env(name, args, ctx, req)?
        }
        Expr::Not(x) => Value::Bool(!truthy(&eval(x, ctx, req)?)?),
        Expr::Neg(x) => match eval(x, ctx, req)? {
            Value::Int(i) => Value::Int(-i),
            Value::Float(f) => Value::Float(-f),
            other => return Err(format!("cannot negate {other:?}")),
        },
        Expr::Matches(x, re) => Value::Bool(re.is_match(&s(eval(x, ctx, req)?)?)),
        Expr::Bin(op, l, r) => {
            // short-circuit logic
            if *op == "or" {
                return Ok(Value::Bool(
                    truthy(&eval(l, ctx, req)?)? || truthy(&eval(r, ctx, req)?)?,
                ));
            }
            if *op == "and" {
                return Ok(Value::Bool(
                    truthy(&eval(l, ctx, req)?)? && truthy(&eval(r, ctx, req)?)?,
                ));
            }
            let (a, b) = (eval(l, ctx, req)?, eval(r, ctx, req)?);
            match *op {
                "==" => Value::Bool(equal(&a, &b)),
                "!=" => Value::Bool(!equal(&a, &b)),
                "in" => match b {
                    Value::List(items) => Value::Bool(items.iter().any(|i| equal(&a, i))),
                    other => return Err(format!("in needs a list, got {other:?}")),
                },
                "contains" => Value::Bool(s(a)?.contains(&s(b)?)),
                "startsWith" => Value::Bool(s(a)?.starts_with(&s(b)?)),
                "endsWith" => Value::Bool(s(a)?.ends_with(&s(b)?)),
                "<" | "<=" | ">" | ">=" => {
                    let ord = match (num(&a), num(&b), &a, &b) {
                        (Some(x), Some(y), _, _) => x.partial_cmp(&y),
                        (_, _, Value::Str(x), Value::Str(y)) => Some(x.cmp(y)),
                        _ => None,
                    }
                    .ok_or_else(|| format!("cannot compare {a:?} and {b:?}"))?;
                    Value::Bool(match *op {
                        "<" => ord.is_lt(),
                        "<=" => ord.is_le(),
                        ">" => ord.is_gt(),
                        _ => ord.is_ge(),
                    })
                }
                "+" => match (a, b) {
                    (Value::Str(x), Value::Str(y)) => Value::Str(x + &y),
                    (Value::Int(x), Value::Int(y)) => Value::Int(x.wrapping_add(y)),
                    (x, y) => Value::Float(num(&x).ok_or("bad operand")? + num(&y).ok_or("bad operand")?),
                },
                "-" | "*" | "/" | "%" => match (a, b) {
                    (Value::Int(x), Value::Int(y)) => match *op {
                        "-" => Value::Int(x.wrapping_sub(y)),
                        "*" => Value::Int(x.wrapping_mul(y)),
                        "/" if y != 0 => Value::Float(x as f64 / y as f64),
                        "%" if y != 0 => Value::Int(x % y),
                        _ => return Err("integer divide by zero".into()),
                    },
                    (x, y) => {
                        let (x, y) = (num(&x).ok_or("bad operand")?, num(&y).ok_or("bad operand")?);
                        Value::Float(match *op {
                            "-" => x - y,
                            "*" => x * y,
                            "/" => x / y,
                            _ => x % y,
                        })
                    }
                },
                other => return Err(format!("unknown operator {other}")),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::query;
    use kerndns_core::proto::rr::RecordType;

    fn run(src: &str) -> Result<Value, String> {
        let mut ctx = Context::new(".", "dns://:53");
        ctx.metadata.insert("view/name".into(), "v1".into());
        let req = query("one.example.split-name.", RecordType::AAAA, "10.0.0.7:4242");
        Program::compile(src)?.run(&ctx, &req)
    }

    #[test]
    fn evaluates_view_expressions() {
        let t = Value::Bool(true);
        let f = Value::Bool(false);
        assert_eq!(run("type() == 'AAAA'"), Ok(t.clone()));
        assert_eq!(run("type() in ['A', 'AAAA']"), Ok(t.clone()));
        assert_eq!(run("type() not in ['A', 'AAAA']"), Ok(f.clone()));
        assert_eq!(run(r"name() matches '^one\\..*\\.split-name\\.$'"), Ok(t.clone()));
        assert_eq!(run("incidr(client_ip(), '10.0.0.0/24')"), Ok(t.clone()));
        assert_eq!(run("incidr(client_ip(), '2001:db8::/32')"), Ok(f.clone()));
        assert_eq!(run("metadata('view/name') == 'v1' && !do()"), Ok(t.clone()));
        assert_eq!(run("port() == '4242' and bufsize() >= 512"), Ok(t.clone()));
        assert_eq!(run("name() endsWith 'split-name.' or 1 / 0 == 1"), Ok(t));
        assert!(run("type() == 1 + ").is_err());
    }

    #[test]
    fn rejects_at_compile_time() {
        for bad in [
            "invalid expression",
            "nope()",
            "name",
            "incidr('a')",
            "name() matches name()",
            "a ? b : c",
        ] {
            assert!(Program::compile(bad).is_err(), "{bad}");
        }
    }
}
