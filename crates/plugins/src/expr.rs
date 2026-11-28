//! An evaluator for the part of the expr language
//! (github.com/expr-lang/expr) that CoreDNS's `view` expressions and
//! `template`'s `var`/`expr` options use, over the environment of
//! `plugin/pkg/expression.DefaultEnv`.
//!
//! Supported:
//!
//! * literals: strings (`'...'`, `"..."` with escapes, `` `raw` ``),
//!   integers (decimal, `0x`, `0o`, `0b`, `_` separators), floats (`1.5`,
//!   `1e3`), `true`, `false`, `nil` and lists (`[a, b]`)
//! * the environment functions `type()`, `name()`, `class()`, `proto()`,
//!   `size()`, `client_ip()`, `port()`, `id()`, `opcode()`, `do()`,
//!   `bufsize()`, `server_ip()`, `server_port()`, `incidr(ip, cidr)` and
//!   `metadata(label)`, and with [`Scope`] the variables and `group()` of
//!   the `template` plugin
//! * the builtins `len`, `lower`, `upper`, `trim`, `trimPrefix`,
//!   `trimSuffix`, `hasPrefix`, `hasSuffix`, `replace`, `split`, `join`,
//!   `repeat`, `indexOf`, `lastIndexOf`, `int`, `float`, `string`, `abs`,
//!   `ceil`, `floor`, `round`, `max`, `min`, `first`, `last` and the
//!   predicates `all`, `any`, `none`, `one`, `filter`, `map`, `count` with
//!   `#` (`any(list, incidr(ip, #))`, also `{...}` closures)
//! * the operators `?:` (and `?:` without a middle part), `??`, `or ||`,
//!   `and &&`, `not !`, `== != < <= > >=`, `in`, `matches`, `contains`,
//!   `startsWith`, `endsWith` (each also as `not in`, `not matches`, ...),
//!   `+ - * / % **`, unary `-` and `+`, indexing (`x[0]`, `x[-1]`) and
//!   parentheses, with expr-lang's precedences
//!
//! Like expr-lang, programs are type checked when they are compiled
//! (`'x' + 1`, unknown names and wrong argument counts are compile errors)
//! and runtime errors (`incidr('notanip', ...)`) are `Err` from `run`.
//! Other builtins, maps, member access, slices, ranges, pipes, `let` and
//! `if` are compile errors.

use std::collections::HashMap;
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

/// The static type of an expression; `Any` when only known at run time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Any,
    Nil,
    Bool,
    Int,
    Float,
    Str,
    List,
}

impl Type {
    fn name(self) -> &'static str {
        match self {
            Type::Any => "interface {}",
            Type::Nil => "nil",
            Type::Bool => "bool",
            Type::Int => "int",
            Type::Float => "float64",
            Type::Str => "string",
            Type::List => "[]interface {}",
        }
    }

    fn of(v: &Value) -> Type {
        match v {
            Value::Nil => Type::Nil,
            Value::Bool(_) => Type::Bool,
            Value::Int(_) => Type::Int,
            Value::Float(_) => Type::Float,
            Value::Str(_) => Type::Str,
            Value::List(_) => Type::List,
        }
    }

    fn is(self, want: Type) -> bool {
        self == want || self == Type::Any
    }

    fn numeric(self) -> bool {
        matches!(self, Type::Int | Type::Float | Type::Any)
    }
}

// --------------------------------------------------------------------- lexer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Str(String),
    Int(i64),
    Float(f64),
    Ident(String),
    Op(&'static str),
}

const OPS: [&str; 28] = [
    "**", "??", "^", "==", "!=", "<=", ">=", "&&", "||", "..", "<", ">", "!", "+", "-", "*", "/", "%", "(", ")", "[",
    "]", "{", "}", "?", ":", "#", ",",
];

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as char;
        if c.is_whitespace() {
            i += 1;
        } else if c == '`' {
            let end = src[i + 1..].find('`').ok_or("literal not terminated")?;
            out.push(Tok::Str(src[i + 1..i + 1 + end].to_string()));
            i += end + 2;
        } else if c == '\'' || c == '"' {
            let q = b[i];
            let mut s = String::new();
            i += 1;
            loop {
                let Some(&ch) = b.get(i) else {
                    return Err("literal not terminated".into());
                };
                if ch == q {
                    i += 1;
                    break;
                }
                if ch == b'\\' {
                    i += 1;
                    let e = *b.get(i).ok_or("literal not terminated")?;
                    i += 1;
                    match e {
                        b'n' => s.push('\n'),
                        b't' => s.push('\t'),
                        b'r' => s.push('\r'),
                        b'a' => s.push('\x07'),
                        b'b' => s.push('\x08'),
                        b'f' => s.push('\x0c'),
                        b'v' => s.push('\x0b'),
                        b'\\' | b'\'' | b'"' => s.push(e as char),
                        b'x' | b'u' | b'U' => {
                            let n = match e {
                                b'x' => 2,
                                b'u' => 4,
                                _ => 8,
                            };
                            let hex = src.get(i..i + n).ok_or("invalid char escape")?;
                            let cp = u32::from_str_radix(hex, 16).map_err(|_| "invalid char escape")?;
                            s.push(char::from_u32(cp).ok_or("invalid char escape")?);
                            i += n;
                        }
                        _ => return Err("invalid char escape".into()),
                    }
                    continue;
                }
                let len = utf8_len(ch);
                s.push_str(std::str::from_utf8(&b[i..i + len]).map_err(|e| e.to_string())?);
                i += len;
            }
            out.push(Tok::Str(s));
        } else if c.is_ascii_digit() || (c == '.' && b.get(i + 1).is_some_and(|d| d.is_ascii_digit())) {
            let start = i;
            let radix = match (c, b.get(i + 1).map(|x| x.to_ascii_lowercase())) {
                ('0', Some(b'x')) => 16,
                ('0', Some(b'o')) => 8,
                ('0', Some(b'b')) => 2,
                _ => 10,
            };
            if radix != 10 {
                i += 2;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                let t = src[start + 2..i].replace('_', "");
                out.push(Tok::Int(
                    i64::from_str_radix(&t, radix).map_err(|_| format!("invalid number {}", &src[start..i]))?,
                ));
                continue;
            }
            let mut float = false;
            while i < b.len() {
                match b[i] {
                    b'0'..=b'9' | b'_' => i += 1,
                    // `1..3` is a range, not a float
                    b'.' if !float && b.get(i + 1) != Some(&b'.') => {
                        float = true;
                        i += 1;
                    }
                    b'e' | b'E' => {
                        float = true;
                        i += 1;
                        if matches!(b.get(i), Some(b'+' | b'-')) {
                            i += 1;
                        }
                    }
                    _ => break,
                }
            }
            let t = src[start..i].replace('_', "");
            out.push(if float {
                Tok::Float(t.parse().map_err(|_| format!("invalid float literal: {t}"))?)
            } else {
                Tok::Int(t.parse().map_err(|_| format!("invalid integer literal: {t}"))?)
            });
        } else if c.is_ascii_alphabetic() || c == '_' || c == '$' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$') {
                i += 1;
            }
            out.push(Tok::Ident(src[start..i].to_string()));
        } else if let Some(op) = OPS.iter().find(|op| src[i..].starts_with(**op)) {
            out.push(Tok::Op(op));
            i += op.len();
        } else if c == '.' || c == '|' {
            return Err(format!("{c:?} is not supported by KernDNS's expression evaluator"));
        } else {
            return Err(format!("unrecognized character: U+{:04X} '{c}'", c as u32));
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

// -------------------------------------------------------------------- parser

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pred {
    All,
    Any,
    None,
    One,
    Filter,
    Map,
    Count,
}

#[derive(Debug)]
enum Expr {
    Lit(Value),
    List(Vec<Expr>),
    /// A `template` variable, by its slot in the scope.
    Var(usize),
    /// `#`, the current element in a predicate.
    Pointer,
    Call(&'static str, Vec<Expr>),
    Pred(Pred, Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Bin(&'static str, Box<Expr>, Box<Expr>),
    /// `matches` with a literal pattern, compiled at setup.
    Matches(Box<Expr>, Regex),
    Cond(Box<Expr>, Box<Expr>, Box<Expr>),
    Index(Box<Expr>, Box<Expr>),
}

/// Environment functions: name, argument count.
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

/// Implemented builtins: name, minimum and maximum argument count.
const BUILTINS: [(&str, usize, usize); 24] = [
    ("len", 1, 1),
    ("lower", 1, 1),
    ("upper", 1, 1),
    ("trim", 1, 2),
    ("trimPrefix", 1, 2),
    ("trimSuffix", 1, 2),
    ("hasPrefix", 2, 2),
    ("hasSuffix", 2, 2),
    ("replace", 3, 3),
    ("split", 2, 3),
    ("join", 1, 2),
    ("repeat", 2, 2),
    ("indexOf", 2, 2),
    ("lastIndexOf", 2, 2),
    ("int", 1, 1),
    ("float", 1, 1),
    ("string", 1, 1),
    ("abs", 1, 1),
    ("ceil", 1, 1),
    ("floor", 1, 1),
    ("round", 1, 1),
    ("max", 1, usize::MAX),
    ("min", 1, usize::MAX),
    ("first", 1, 1),
];

/// Every builtin of expr-lang (`builtin.Index`), implemented or not, and
/// its keywords: not usable as `template` variable names.
const RESERVED: &[&str] = &[
    "all",
    "none",
    "any",
    "one",
    "filter",
    "map",
    "find",
    "findIndex",
    "findLast",
    "findLastIndex",
    "count",
    "sum",
    "groupBy",
    "sortBy",
    "reduce",
    "len",
    "type",
    "abs",
    "ceil",
    "floor",
    "round",
    "int",
    "float",
    "string",
    "trim",
    "trimPrefix",
    "trimSuffix",
    "upper",
    "lower",
    "split",
    "splitAfter",
    "replace",
    "repeat",
    "join",
    "indexOf",
    "lastIndexOf",
    "hasPrefix",
    "hasSuffix",
    "max",
    "min",
    "mean",
    "median",
    "toJSON",
    "fromJSON",
    "toBase64",
    "fromBase64",
    "now",
    "duration",
    "date",
    "timezone",
    "first",
    "last",
    "get",
    "keys",
    "values",
    "toPairs",
    "fromPairs",
    "take",
    "sort",
    "bitand",
    "bitor",
    "bitxor",
    "bitnand",
    "bitnot",
    "bitshl",
    "bitshr",
    "bitushr",
    "uniq",
    "concat",
    "flatten",
    "true",
    "false",
    "nil",
    "let",
    "in",
    "not",
    "and",
    "or",
    "matches",
    "contains",
    "startsWith",
    "endsWith",
    "if",
    "else",
];

fn pred_of(name: &str) -> Option<Pred> {
    Some(match name {
        "all" => Pred::All,
        "any" => Pred::Any,
        "none" => Pred::None,
        "one" => Pred::One,
        "filter" => Pred::Filter,
        "map" => Pred::Map,
        "count" => Pred::Count,
        _ => return None,
    })
}

/// Binary operators: precedence, right associative.
fn binary(op: &str) -> Option<(u16, bool)> {
    Some(match op {
        "or" | "||" => (10, false),
        "and" | "&&" => (15, false),
        "==" | "!=" | "<" | ">" | "<=" | ">=" | "in" | "matches" | "contains" | "startsWith" | "endsWith" => {
            (20, false)
        }
        ".." => (25, false),
        "+" | "-" => (30, false),
        "*" | "/" | "%" => (60, false),
        "**" | "^" => (100, true),
        "??" => (500, false),
        _ => return None,
    })
}

const NEGATABLE: [&str; 5] = ["in", "matches", "contains", "startsWith", "endsWith"];

fn canon(op: &str) -> &'static str {
    match op {
        "or" | "||" => "or",
        "and" | "&&" => "and",
        "==" => "==",
        "!=" => "!=",
        "<" => "<",
        ">" => ">",
        "<=" => "<=",
        ">=" => ">=",
        "in" => "in",
        "matches" => "matches",
        "contains" => "contains",
        "startsWith" => "startsWith",
        "endsWith" => "endsWith",
        ".." => "..",
        "+" => "+",
        "-" => "-",
        "*" => "*",
        "/" => "/",
        "%" => "%",
        "**" | "^" => "**",
        _ => "??",
    }
}

/// Names a program may use besides the environment: `template`'s
/// variables (in declaration order) and its `group()` function.
#[derive(Debug, Default, Clone)]
pub struct Scope {
    pub vars: Vec<(String, Type)>,
    pub group: bool,
}

impl Scope {
    /// Whether `name` can't be a variable: an environment function, a
    /// builtin, a keyword, `group`, or a variable already declared.
    pub fn reserved(&self, name: &str) -> bool {
        ENV.iter().any(|(n, _)| *n == name)
            || RESERVED.contains(&name)
            || (self.group && name == "group")
            || self.vars.iter().any(|(n, _)| n == name)
    }
}

struct Parser<'s> {
    toks: Vec<Tok>,
    pos: usize,
    scope: &'s Scope,
    /// Nesting depth of predicate closures (where `#` is valid).
    closures: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn peek_word(&self) -> Option<&str> {
        self.word_at(self.pos)
    }

    fn word_at(&self, i: usize) -> Option<&str> {
        match self.toks.get(i)? {
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
            Err(match self.peek() {
                Some(t) => format!("unexpected token {t:?}, expected {w:?}"),
                None => format!("unexpected end of expression, expected {w:?}"),
            })
        }
    }

    /// `parseExpression`: precedence climbing, then `?:` at the top level.
    fn expression(&mut self, prec: u16) -> Result<Expr, String> {
        let mut left = self.unary()?;
        while let Some(w) = self.peek_word() {
            let (op, negate) = if w == "not" {
                match self.word_at(self.pos + 1) {
                    Some(n) if NEGATABLE.contains(&n) => (n, true),
                    _ => break,
                }
            } else {
                (w, false)
            };
            let Some((p, right_assoc)) = binary(op) else { break };
            if p < prec {
                break;
            }
            let op = canon(op);
            self.pos += if negate { 2 } else { 1 };
            if op == ".." {
                return Err("ranges (..) are not supported by KernDNS's expression evaluator".into());
            }
            let right = self.expression(if right_assoc { p } else { p + 1 })?;
            left = match (op, right) {
                ("matches", Expr::Lit(Value::Str(pat))) => {
                    Expr::Matches(Box::new(left), Regex::new(&pat).map_err(|e| regexp_error(&e))?)
                }
                (op, right) => Expr::Bin(op, Box::new(left), Box::new(right)),
            };
            if negate {
                left = Expr::Not(Box::new(left));
            }
        }
        if prec == 0 {
            while self.eat("?") {
                let (a, b) = if self.eat(":") {
                    (None, self.expression(0)?)
                } else {
                    let a = self.expression(0)?;
                    self.expect(":")?;
                    (Some(a), self.expression(0)?)
                };
                left = match a {
                    Some(a) => Expr::Cond(Box::new(left), Box::new(a), Box::new(b)),
                    // `a ?: b` is `a ? a : b`
                    None => Expr::Bin("?:", Box::new(left), Box::new(b)),
                };
            }
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat("!") || self.eat("not") {
            let e = self.expression(50)?;
            return self.postfix(Expr::Not(Box::new(e)));
        }
        if self.eat("-") {
            let e = self.expression(90)?;
            return self.postfix(Expr::Neg(Box::new(e)));
        }
        if self.eat("+") {
            let e = self.expression(90)?;
            return self.postfix(Expr::Bin("+", Box::new(Expr::Lit(Value::Int(0))), Box::new(e)));
        }
        if self.eat("(") {
            let e = self.expression(0)?;
            self.expect(")")?;
            return self.postfix(e);
        }
        let e = self.primary()?;
        self.postfix(e)
    }

    fn postfix(&mut self, mut e: Expr) -> Result<Expr, String> {
        while self.eat("[") {
            if self.peek_word() == Some(":") {
                return Err("slices are not supported by KernDNS's expression evaluator".into());
            }
            let i = self.expression(0)?;
            if self.peek_word() == Some(":") {
                return Err("slices are not supported by KernDNS's expression evaluator".into());
            }
            self.expect("]")?;
            e = Expr::Index(Box::new(e), Box::new(i));
        }
        Ok(e)
    }

    fn args(&mut self) -> Result<Vec<Expr>, String> {
        let mut args = Vec::new();
        if !self.eat(")") {
            loop {
                args.push(self.expression(0)?);
                if self.eat(")") {
                    break;
                }
                self.expect(",")?;
            }
        }
        Ok(args)
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
            Tok::Op("#") => {
                if self.closures == 0 {
                    return Err("cannot use pointer accessor outside predicate".into());
                }
                if matches!(self.peek(), Some(Tok::Ident(_))) {
                    return Err("#index and #acc are not supported by KernDNS's expression evaluator".into());
                }
                Ok(Expr::Pointer)
            }
            Tok::Op("[") => {
                let mut items = Vec::new();
                if !self.eat("]") {
                    loop {
                        items.push(self.expression(0)?);
                        if self.eat("]") {
                            break;
                        }
                        self.expect(",")?;
                        // trailing comma
                        if self.eat("]") {
                            break;
                        }
                    }
                }
                Ok(Expr::List(items))
            }
            Tok::Op("{") => Err("maps are not supported by KernDNS's expression evaluator".into()),
            Tok::Ident(id) => self.ident(id),
            Tok::Op(o) => Err(format!("unexpected token Operator({o:?})")),
        }
    }

    fn ident(&mut self, id: String) -> Result<Expr, String> {
        match id.as_str() {
            "true" => return Ok(Expr::Lit(Value::Bool(true))),
            "false" => return Ok(Expr::Lit(Value::Bool(false))),
            "nil" => return Ok(Expr::Lit(Value::Nil)),
            "let" | "if" => return Err(format!("{id} is not supported by KernDNS's expression evaluator")),
            _ => {}
        }
        if let Some(slot) = self.scope.vars.iter().position(|(n, _)| *n == id) {
            if self.peek_word() == Some("(") {
                return Err(format!("{id} is not callable"));
            }
            return Ok(Expr::Var(slot));
        }
        let is_group = self.scope.group && id == "group";
        let env = ENV.iter().find(|(n, _)| *n == id);
        let builtin = BUILTINS.iter().find(|(n, _, _)| *n == id);
        let pred = pred_of(&id);
        if env.is_none() && builtin.is_none() && pred.is_none() && !is_group && id != "last" {
            if RESERVED.contains(&id.as_str()) {
                return Err(format!(
                    "builtin {id} is not supported by KernDNS's expression evaluator"
                ));
            }
            return Err(format!("unknown name {id}"));
        }
        if !self.eat("(") {
            return Err(format!("{id} must be called: {id}()"));
        }
        if let Some(p) = pred {
            let list = self.expression(0)?;
            self.expect(",")?;
            self.closures += 1;
            let body = if self.eat("{") {
                let b = self.expression(0)?;
                self.expect("}")?;
                b
            } else {
                self.expression(0)?
            };
            self.closures -= 1;
            self.expect(")")?;
            return Ok(Expr::Pred(p, Box::new(list), Box::new(body)));
        }
        let args = self.args()?;
        let (name, min, max): (&'static str, usize, usize) = if is_group {
            ("group", 1, 1)
        } else if let Some(&(n, a)) = env {
            (n, a, a)
        } else if let Some(&(n, lo, hi)) = builtin {
            (n, lo, hi)
        } else {
            ("last", 1, 1)
        };
        if args.len() < min {
            return Err(format!("not enough arguments to call {name}"));
        }
        if args.len() > max {
            return Err(format!("too many arguments to call {name}"));
        }
        Ok(Expr::Call(name, args))
    }
}

/// Go's regexp error text (`error parsing regexp: ...`).
fn regexp_error(e: &regex::Error) -> String {
    let s = e.to_string();
    let detail = s
        .lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix("error: "))
        .unwrap_or(s.trim());
    format!("error parsing regexp: {detail}")
}

// ------------------------------------------------------------- type checking

fn mismatch(op: &str, a: Type, b: Type) -> String {
    format!(
        "invalid operation: {op} (mismatched types {} and {})",
        a.name(),
        b.name()
    )
}

fn check(e: &Expr, scope: &Scope) -> Result<Type, String> {
    Ok(match e {
        Expr::Lit(v) => Type::of(v),
        Expr::List(items) => {
            for i in items {
                check(i, scope)?;
            }
            Type::List
        }
        Expr::Var(slot) => scope.vars[*slot].1,
        Expr::Pointer => Type::Any,
        Expr::Not(x) => {
            let t = check(x, scope)?;
            if !t.is(Type::Bool) {
                return Err(format!("invalid operation: ! (mismatched type {})", t.name()));
            }
            Type::Bool
        }
        Expr::Neg(x) => {
            let t = check(x, scope)?;
            if !t.numeric() {
                return Err(format!("invalid operation: - (mismatched type {})", t.name()));
            }
            t
        }
        Expr::Matches(x, _) => {
            let t = check(x, scope)?;
            if !t.is(Type::Str) {
                return Err(mismatch("matches", t, Type::Str));
            }
            Type::Bool
        }
        Expr::Cond(c, a, b) => {
            let t = check(c, scope)?;
            if !t.is(Type::Bool) {
                return Err(format!("non-bool expression (type {}) used as condition", t.name()));
            }
            let (a, b) = (check(a, scope)?, check(b, scope)?);
            if a == b { a } else { Type::Any }
        }
        Expr::Index(x, i) => {
            let (t, it) = (check(x, scope)?, check(i, scope)?);
            match t {
                Type::List | Type::Any => {
                    if !it.is(Type::Int) {
                        return Err(format!(
                            "array elements can only be selected using an integer (got {})",
                            it.name()
                        ));
                    }
                    Type::Any
                }
                Type::Str => return Err("indexing strings is not supported by KernDNS's expression evaluator".into()),
                t => return Err(format!("type {} does not support indexing", t.name())),
            }
        }
        Expr::Pred(p, list, body) => {
            let lt = check(list, scope)?;
            if !lt.is(Type::List) {
                return Err(format!(
                    "builtin {} takes only array (got {})",
                    pred_name(*p),
                    lt.name()
                ));
            }
            let bt = check(body, scope)?;
            match p {
                Pred::Map => Type::List,
                Pred::Filter => {
                    if !bt.is(Type::Bool) {
                        return Err(format!("predicate should return boolean (got {})", bt.name()));
                    }
                    Type::List
                }
                Pred::Count => {
                    if !bt.is(Type::Bool) {
                        return Err(format!("predicate should return boolean (got {})", bt.name()));
                    }
                    Type::Int
                }
                _ => {
                    if !bt.is(Type::Bool) {
                        return Err(format!("predicate should return boolean (got {})", bt.name()));
                    }
                    Type::Bool
                }
            }
        }
        Expr::Call(name, args) => {
            let ts = args.iter().map(|a| check(a, scope)).collect::<Result<Vec<_>, _>>()?;
            check_call(name, &ts)?
        }
        Expr::Bin(op, l, r) => {
            let (a, b) = (check(l, scope)?, check(r, scope)?);
            let any = a == Type::Any || b == Type::Any;
            match *op {
                "or" | "and" => {
                    if !a.is(Type::Bool) || !b.is(Type::Bool) {
                        return Err(mismatch(if *op == "or" { "||" } else { "&&" }, a, b));
                    }
                    Type::Bool
                }
                "==" | "!=" => {
                    let ok = any || a == b || a == Type::Nil || b == Type::Nil || (a.numeric() && b.numeric());
                    if !ok {
                        return Err(mismatch(op, a, b));
                    }
                    Type::Bool
                }
                "<" | "<=" | ">" | ">=" => {
                    let ok = (a.numeric() && b.numeric()) || (a.is(Type::Str) && b.is(Type::Str));
                    if !ok {
                        return Err(mismatch(op, a, b));
                    }
                    Type::Bool
                }
                "in" => {
                    if !b.is(Type::List) {
                        return Err(mismatch("in", a, b));
                    }
                    Type::Bool
                }
                "contains" | "startsWith" | "endsWith" | "matches" => {
                    if !a.is(Type::Str) || !b.is(Type::Str) {
                        return Err(mismatch(op, a, b));
                    }
                    Type::Bool
                }
                "+" => match (a, b) {
                    (Type::Int, Type::Int) => Type::Int,
                    (Type::Str, Type::Str) => Type::Str,
                    (Type::Int | Type::Float, Type::Int | Type::Float) => Type::Float,
                    (Type::Any, Type::Any | Type::Int | Type::Float | Type::Str)
                    | (Type::Int | Type::Float | Type::Str, Type::Any) => Type::Any,
                    _ => return Err(mismatch("+", a, b)),
                },
                "-" | "*" | "%" => {
                    if !a.numeric() || !b.numeric() || (*op == "%" && (a == Type::Float || b == Type::Float)) {
                        return Err(mismatch(op, a, b));
                    }
                    match (a, b) {
                        (Type::Int, Type::Int) => Type::Int,
                        _ if any => Type::Any,
                        _ => Type::Float,
                    }
                }
                "/" | "**" => {
                    if !a.numeric() || !b.numeric() {
                        return Err(mismatch(op, a, b));
                    }
                    Type::Float
                }
                "?:" => {
                    if !a.is(Type::Bool) {
                        return Err(format!("non-bool expression (type {}) used as condition", a.name()));
                    }
                    if a == b { a } else { Type::Any }
                }
                // `??`
                _ => {
                    if a == b {
                        a
                    } else {
                        Type::Any
                    }
                }
            }
        }
    })
}

fn pred_name(p: Pred) -> &'static str {
    match p {
        Pred::All => "all",
        Pred::Any => "any",
        Pred::None => "none",
        Pred::One => "one",
        Pred::Filter => "filter",
        Pred::Map => "map",
        Pred::Count => "count",
    }
}

fn check_call(name: &str, ts: &[Type]) -> Result<Type, String> {
    let want = |i: usize, t: Type| -> Result<(), String> {
        if ts[i].is(t) {
            Ok(())
        } else {
            Err(format!(
                "cannot use {} as argument (type {}) to call {name}",
                ts[i].name(),
                t.name()
            ))
        }
    };
    let strs = |n: usize| -> Result<(), String> { (0..n.min(ts.len())).try_for_each(|i| want(i, Type::Str)) };
    Ok(match name {
        "type" | "name" | "class" | "proto" | "client_ip" | "port" | "server_ip" | "server_port" => Type::Str,
        "size" | "id" | "opcode" | "bufsize" => Type::Int,
        "do" => Type::Bool,
        "incidr" => {
            strs(2)?;
            Type::Bool
        }
        "metadata" => {
            strs(1)?;
            Type::Str
        }
        "group" => Type::Str,
        "len" => {
            if !matches!(ts[0], Type::Str | Type::List | Type::Any) {
                return Err(format!("invalid argument for len (type {})", ts[0].name()));
            }
            Type::Int
        }
        "lower" | "upper" | "trim" | "trimPrefix" | "trimSuffix" | "replace" => {
            strs(ts.len())?;
            Type::Str
        }
        "repeat" => {
            want(0, Type::Str)?;
            want(1, Type::Int)?;
            Type::Str
        }
        "hasPrefix" | "hasSuffix" => {
            strs(2)?;
            Type::Bool
        }
        "indexOf" | "lastIndexOf" => {
            strs(2)?;
            Type::Int
        }
        "split" => {
            strs(2)?;
            if ts.len() == 3 {
                want(2, Type::Int)?;
            }
            Type::List
        }
        "join" => {
            want(0, Type::List)?;
            if ts.len() == 2 {
                want(1, Type::Str)?;
            }
            Type::Str
        }
        "int" | "float" => {
            if !matches!(ts[0], Type::Int | Type::Float | Type::Str | Type::Any) {
                return Err(format!("invalid argument for {name} (type {})", ts[0].name()));
            }
            if name == "int" { Type::Int } else { Type::Float }
        }
        "string" => Type::Str,
        "abs" => {
            if !ts[0].numeric() {
                return Err(format!("invalid argument for abs (type {})", ts[0].name()));
            }
            ts[0]
        }
        "ceil" | "floor" | "round" => {
            if !ts[0].numeric() {
                return Err(format!("invalid argument for {name} (type {})", ts[0].name()));
            }
            Type::Float
        }
        "max" | "min" => Type::Any,
        "first" | "last" => {
            want(0, Type::List)?;
            Type::Any
        }
        _ => Type::Any,
    })
}

// ----------------------------------------------------------------- programs

/// A compiled expression.
#[derive(Debug)]
pub struct Program {
    expr: Expr,
    ty: Type,
}

/// Values for a program's [`Scope`] at run time.
#[derive(Default)]
pub struct Env<'a> {
    /// Variable values, in the scope's order (later ones may be missing
    /// while they are computed).
    pub vars: &'a [Value],
    /// The capture groups for `group()`, by index (`"0"`, `"1"`, ...) and name.
    pub groups: Option<&'a HashMap<String, String>>,
}

impl Program {
    /// Compile with the environment functions only (`view`).
    pub fn compile(src: &str) -> Result<Program, String> {
        Program::compile_in(src, &Scope::default())
    }

    /// Compile with the variables and functions of `scope` (`template`).
    pub fn compile_in(src: &str, scope: &Scope) -> Result<Program, String> {
        let mut p = Parser {
            toks: lex(src)?,
            pos: 0,
            scope,
            closures: 0,
        };
        let expr = p.expression(0)?;
        if let Some(t) = p.peek() {
            return Err(format!("unexpected token {t:?}"));
        }
        let ty = check(&expr, scope)?;
        Ok(Program { expr, ty })
    }

    /// The static type of the result.
    pub fn result_type(&self) -> Type {
        self.ty
    }

    /// Evaluate; runtime errors are `Err`.
    pub fn run(&self, ctx: &Context, req: &Request) -> Result<Value, String> {
        self.run_in(ctx, req, &Env::default())
    }

    /// Evaluate with the values of the program's scope.
    pub fn run_in(&self, ctx: &Context, req: &Request, env: &Env<'_>) -> Result<Value, String> {
        let rt = Rt {
            ctx,
            req,
            env,
            ptr: None,
        };
        rt.eval(&self.expr)
    }
}

struct Rt<'a> {
    ctx: &'a Context,
    req: &'a Request,
    env: &'a Env<'a>,
    ptr: Option<&'a Value>,
}

fn truthy(v: &Value) -> Result<bool, String> {
    match v {
        Value::Bool(b) => Ok(*b),
        other => Err(format!("expected bool, got {}", Type::of(other).name())),
    }
}

fn s(v: Value) -> Result<String, String> {
    match v {
        Value::Str(s) => Ok(s),
        other => Err(format!("expected string, got {}", Type::of(&other).name())),
    }
}

fn int(v: &Value) -> Result<i64, String> {
    match v {
        Value::Int(i) => Ok(*i),
        other => Err(format!("expected int, got {}", Type::of(other).name())),
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
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x == y,
        _ => match (num(a), num(b)) {
            (Some(x), Some(y)) => x == y,
            _ => a == b,
        },
    }
}

/// Go's `%v` of an expression value (`string()`, `join`).
pub fn format_value(v: &Value) -> String {
    match v {
        Value::Nil => "<nil>".into(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => format_float(*f),
        Value::Str(s) => s.clone(),
        Value::List(l) => format!("[{}]", l.iter().map(format_value).collect::<Vec<_>>().join(" ")),
    }
}

/// Go's `strconv.FormatFloat(f, 'g', -1, 64)`, as `%v` prints a float64.
pub fn format_float(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "+Inf" } else { "-Inf" }.into();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0" } else { "0" }.into();
    }
    // shortest representation, then Go's choice of %e for exponents < -4 or >= 21
    let e = format!("{f:e}");
    let (mant, exp) = e.split_once('e').expect("exponent");
    let exp: i32 = exp.parse().expect("exponent");
    if !(-4..21).contains(&exp) {
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{mant}e{sign}{:02}", exp.abs())
    } else {
        format!("{f}")
    }
}

impl Rt<'_> {
    fn eval(&self, e: &Expr) -> Result<Value, String> {
        Ok(match e {
            Expr::Lit(v) => v.clone(),
            Expr::List(items) => Value::List(items.iter().map(|i| self.eval(i)).collect::<Result<_, _>>()?),
            Expr::Var(slot) => self.env.vars.get(*slot).cloned().unwrap_or(Value::Nil),
            Expr::Pointer => self.ptr.cloned().unwrap_or(Value::Nil),
            Expr::Call(name, args) => {
                let args = args.iter().map(|a| self.eval(a)).collect::<Result<Vec<_>, _>>()?;
                self.call(name, args)?
            }
            Expr::Pred(p, list, body) => {
                let items = match self.eval(list)? {
                    Value::List(l) => l,
                    Value::Nil => Vec::new(),
                    other => return Err(format!("cannot iterate over {}", Type::of(&other).name())),
                };
                let mut out = Vec::new();
                let mut n = 0i64;
                for item in &items {
                    let rt = Rt {
                        ctx: self.ctx,
                        req: self.req,
                        env: self.env,
                        ptr: Some(item),
                    };
                    let v = rt.eval(body)?;
                    if *p == Pred::Map {
                        out.push(v);
                        continue;
                    }
                    let b = truthy(&v)?;
                    match (p, b) {
                        (Pred::All, false) => return Ok(Value::Bool(false)),
                        (Pred::Any, true) => return Ok(Value::Bool(true)),
                        (Pred::None, true) => return Ok(Value::Bool(false)),
                        (Pred::Filter, true) => out.push(item.clone()),
                        (Pred::One | Pred::Count, true) => n += 1,
                        _ => {}
                    }
                }
                match p {
                    Pred::All | Pred::None => Value::Bool(true),
                    Pred::Any => Value::Bool(false),
                    Pred::One => Value::Bool(n == 1),
                    Pred::Count => Value::Int(n),
                    Pred::Filter | Pred::Map => Value::List(out),
                }
            }
            Expr::Not(x) => Value::Bool(!truthy(&self.eval(x)?)?),
            Expr::Neg(x) => match self.eval(x)? {
                Value::Int(i) => Value::Int(i.wrapping_neg()),
                Value::Float(f) => Value::Float(-f),
                other => return Err(format!("invalid operation: - {}", Type::of(&other).name())),
            },
            Expr::Matches(x, re) => Value::Bool(re.is_match(&s(self.eval(x)?)?)),
            Expr::Cond(c, a, b) => {
                if truthy(&self.eval(c)?)? {
                    self.eval(a)?
                } else {
                    self.eval(b)?
                }
            }
            Expr::Index(x, i) => {
                let base = self.eval(x)?;
                let i = int(&self.eval(i)?)?;
                let at = |len: usize| -> Result<usize, String> {
                    let j = if i < 0 { i + len as i64 } else { i };
                    if j < 0 || j >= len as i64 {
                        Err(format!("index out of range: {i} (array length is {len})"))
                    } else {
                        Ok(j as usize)
                    }
                };
                match base {
                    Value::List(l) => l[at(l.len())?].clone(),
                    other => return Err(format!("cannot index {}", Type::of(&other).name())),
                }
            }
            Expr::Bin(op, l, r) => {
                match *op {
                    "or" => return Ok(Value::Bool(truthy(&self.eval(l)?)? || truthy(&self.eval(r)?)?)),
                    "and" => return Ok(Value::Bool(truthy(&self.eval(l)?)? && truthy(&self.eval(r)?)?)),
                    "??" => {
                        return match self.eval(l)? {
                            Value::Nil => self.eval(r),
                            v => Ok(v),
                        };
                    }
                    "?:" => {
                        let v = self.eval(l)?;
                        return if truthy(&v)? { Ok(v) } else { self.eval(r) };
                    }
                    _ => {}
                }
                let (a, b) = (self.eval(l)?, self.eval(r)?);
                binop(op, a, b)?
            }
        })
    }

    fn call(&self, name: &str, args: Vec<Value>) -> Result<Value, String> {
        let req = self.req;
        let ip_s = |ip: IpAddr| ip.to_canonical().to_string();
        let mut it = args.into_iter();
        let mut arg = || it.next().unwrap_or(Value::Nil);
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
                let l = s(arg())?;
                Value::Str(self.ctx.metadata.get(&l).cloned().unwrap_or_default())
            }
            "group" => {
                let key = match arg() {
                    Value::Int(i) => i.to_string(),
                    Value::Str(x) => x,
                    _ => return Ok(Value::Str(String::new())),
                };
                Value::Str(self.env.groups.and_then(|g| g.get(&key)).cloned().unwrap_or_default())
            }
            "incidr" => {
                let (ip, cidr) = (s(arg())?, s(arg())?);
                Value::Bool(incidr(&ip, &cidr)?)
            }
            "len" => match arg() {
                Value::Str(x) => Value::Int(x.len() as i64),
                Value::List(l) => Value::Int(l.len() as i64),
                other => return Err(format!("invalid argument for len (type {})", Type::of(&other).name())),
            },
            "lower" => Value::Str(s(arg())?.to_lowercase()),
            "upper" => Value::Str(s(arg())?.to_uppercase()),
            "trim" | "trimPrefix" | "trimSuffix" => {
                let x = s(arg())?;
                let cut = match arg() {
                    Value::Nil => None,
                    v => Some(s(v)?),
                };
                Value::Str(match (name, cut) {
                    ("trim", None) => x.trim().to_string(),
                    ("trim", Some(c)) => x.trim_matches(|ch| c.contains(ch)).to_string(),
                    ("trimPrefix", c) => {
                        let c = c.unwrap_or_else(|| " ".into());
                        x.strip_prefix(c.as_str()).unwrap_or(&x).to_string()
                    }
                    (_, c) => {
                        let c = c.unwrap_or_else(|| " ".into());
                        x.strip_suffix(c.as_str()).unwrap_or(&x).to_string()
                    }
                })
            }
            "hasPrefix" => {
                let (a, b) = (s(arg())?, s(arg())?);
                Value::Bool(a.starts_with(&b))
            }
            "hasSuffix" => {
                let (a, b) = (s(arg())?, s(arg())?);
                Value::Bool(a.ends_with(&b))
            }
            "replace" => {
                let (x, old, new) = (s(arg())?, s(arg())?, s(arg())?);
                Value::Str(go_replace_all(&x, &old, &new))
            }
            "repeat" => {
                let x = s(arg())?;
                let n = int(&arg())?;
                if n < 0 {
                    return Err("strings: negative Repeat count".into());
                }
                Value::Str(x.repeat(n as usize))
            }
            "indexOf" | "lastIndexOf" => {
                let (x, sub) = (s(arg())?, s(arg())?);
                let pos = if name == "indexOf" { x.find(&sub) } else { x.rfind(&sub) };
                // byte offsets, like strings.Index
                Value::Int(pos.map_or(-1, |p| p as i64))
            }
            "split" => {
                let (x, sep) = (s(arg())?, s(arg())?);
                let n = match arg() {
                    Value::Nil => -1,
                    v => int(&v)?,
                };
                Value::List(go_split(&x, &sep, n).into_iter().map(Value::Str).collect())
            }
            "join" => {
                let items = match arg() {
                    Value::List(l) => l,
                    other => return Err(format!("expected array, got {}", Type::of(&other).name())),
                };
                let sep = match arg() {
                    Value::Nil => String::new(),
                    v => s(v)?,
                };
                let strs = items.into_iter().map(s).collect::<Result<Vec<_>, _>>()?;
                Value::Str(strs.join(&sep))
            }
            "int" => match arg() {
                Value::Int(i) => Value::Int(i),
                Value::Float(f) => Value::Int(f as i64),
                Value::Str(x) => Value::Int(
                    x.parse()
                        .map_err(|_| format!("strconv.Atoi: parsing {x:?}: invalid syntax"))?,
                ),
                other => return Err(format!("invalid operation: int({})", Type::of(&other).name())),
            },
            "float" => match arg() {
                Value::Int(i) => Value::Float(i as f64),
                Value::Float(f) => Value::Float(f),
                Value::Str(x) => Value::Float(
                    x.parse()
                        .map_err(|_| format!("strconv.ParseFloat: parsing {x:?}: invalid syntax"))?,
                ),
                other => return Err(format!("invalid operation: float({})", Type::of(&other).name())),
            },
            "string" => Value::Str(format_value(&arg())),
            "abs" => match arg() {
                Value::Int(i) => Value::Int(i.wrapping_abs()),
                Value::Float(f) => Value::Float(f.abs()),
                other => return Err(format!("invalid argument for abs (type {})", Type::of(&other).name())),
            },
            "ceil" | "floor" | "round" => {
                let v = arg();
                let f = num(&v).ok_or_else(|| format!("invalid argument for {name} (type {})", Type::of(&v).name()))?;
                Value::Float(match name {
                    "ceil" => f.ceil(),
                    "floor" => f.floor(),
                    _ => f.round(),
                })
            }
            "max" | "min" => {
                let mut vals: Vec<Value> = it.by_ref().collect();
                // a single list argument is spread
                if let [Value::List(l)] = vals.as_slice() {
                    vals = l.clone();
                }
                let mut best: Option<Value> = None;
                for v in vals {
                    let x =
                        num(&v).ok_or_else(|| format!("invalid argument for {name} (type {})", Type::of(&v).name()))?;
                    let replace = match &best {
                        None => true,
                        Some(b) => {
                            let y = num(b).expect("numeric");
                            if name == "max" { x > y } else { x < y }
                        }
                    };
                    if replace {
                        best = Some(v);
                    }
                }
                best.unwrap_or(Value::Nil)
            }
            "first" | "last" => match arg() {
                Value::List(l) => {
                    let v = if name == "first" { l.first() } else { l.last() };
                    v.cloned().unwrap_or(Value::Nil)
                }
                _ => Value::Nil,
            },
            other => return Err(format!("unknown function {other}")),
        })
    }
}

fn binop(op: &str, a: Value, b: Value) -> Result<Value, String> {
    Ok(match op {
        "==" => Value::Bool(equal(&a, &b)),
        "!=" => Value::Bool(!equal(&a, &b)),
        "in" => match b {
            Value::List(items) => Value::Bool(items.iter().any(|i| equal(&a, i))),
            Value::Nil => Value::Bool(false),
            other => return Err(format!("operator \"in\" not defined on {}", Type::of(&other).name())),
        },
        "contains" => Value::Bool(s(a)?.contains(&s(b)?)),
        "startsWith" => Value::Bool(s(a)?.starts_with(&s(b)?)),
        "endsWith" => Value::Bool(s(a)?.ends_with(&s(b)?)),
        "matches" => {
            let pat = s(b)?;
            let re = Regex::new(&pat).map_err(|e| regexp_error(&e))?;
            Value::Bool(re.is_match(&s(a)?))
        }
        "<" | "<=" | ">" | ">=" => {
            let ord = match (&a, &b) {
                (Value::Int(x), Value::Int(y)) => Some(x.cmp(y)),
                (Value::Str(x), Value::Str(y)) => Some(x.cmp(y)),
                _ => match (num(&a), num(&b)) {
                    (Some(x), Some(y)) => x.partial_cmp(&y),
                    _ => {
                        return Err(format!(
                            "invalid operation: {} {op} {}",
                            Type::of(&a).name(),
                            Type::of(&b).name()
                        ));
                    }
                },
            };
            let Some(ord) = ord else { return Ok(Value::Bool(false)) };
            Value::Bool(match op {
                "<" => ord.is_lt(),
                "<=" => ord.is_le(),
                ">" => ord.is_gt(),
                _ => ord.is_ge(),
            })
        }
        "+" => match (a, b) {
            (Value::Str(x), Value::Str(y)) => Value::Str(x + &y),
            (Value::Int(x), Value::Int(y)) => Value::Int(x.wrapping_add(y)),
            (x, y) => match (num(&x), num(&y)) {
                (Some(x), Some(y)) => Value::Float(x + y),
                _ => {
                    return Err(format!(
                        "invalid operation: {} + {}",
                        Type::of(&x).name(),
                        Type::of(&y).name()
                    ));
                }
            },
        },
        "-" | "*" | "%" => match (a, b) {
            (Value::Int(x), Value::Int(y)) => match op {
                "-" => Value::Int(x.wrapping_sub(y)),
                "*" => Value::Int(x.wrapping_mul(y)),
                _ if y == 0 => return Err("integer divide by zero".into()),
                _ => Value::Int(x.wrapping_rem(y)),
            },
            (x, y) => {
                let bad = || {
                    format!(
                        "invalid operation: {} {op} {}",
                        Type::of(&x).name(),
                        Type::of(&y).name()
                    )
                };
                let (p, q) = (num(&x).ok_or_else(bad)?, num(&y).ok_or_else(bad)?);
                if op == "%" {
                    return Err(bad());
                }
                Value::Float(if op == "-" { p - q } else { p * q })
            }
        },
        "/" | "**" => {
            let bad = || {
                format!(
                    "invalid operation: {} {op} {}",
                    Type::of(&a).name(),
                    Type::of(&b).name()
                )
            };
            let (p, q) = (num(&a).ok_or_else(bad)?, num(&b).ok_or_else(bad)?);
            Value::Float(if op == "/" { p / q } else { p.powf(q) })
        }
        other => return Err(format!("unknown operator {other}")),
    })
}

/// `incidr` of `DefaultEnv`: `net.ParseIP` and `net.ParseCIDR`.
fn incidr(ip: &str, cidr: &str) -> Result<bool, String> {
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| "first argument is not an IP address".to_string())?;
    Ok(kerndns_core::cidr::contains(&kerndns_core::cidr::parse_cidr(cidr)?, ip))
}

/// Go's `strings.ReplaceAll` (an empty `old` inserts `new` around every rune).
fn go_replace_all(x: &str, old: &str, new: &str) -> String {
    if old.is_empty() {
        let mut out = String::from(new);
        for c in x.chars() {
            out.push(c);
            out.push_str(new);
        }
        return out;
    }
    x.replace(old, new)
}

/// Go's `strings.SplitN` (`n < 0`: all).
fn go_split(x: &str, sep: &str, n: i64) -> Vec<String> {
    if n == 0 {
        return Vec::new();
    }
    if sep.is_empty() {
        let mut parts: Vec<String> = x.chars().map(String::from).collect();
        if n > 0 && parts.len() > n as usize {
            let rest: String = parts[n as usize - 1..].concat();
            parts.truncate(n as usize - 1);
            parts.push(rest);
        }
        return parts;
    }
    if n < 0 {
        x.split(sep).map(String::from).collect()
    } else {
        x.splitn(n as usize, sep).map(String::from).collect()
    }
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
        assert_eq!(run("name() endsWith 'split-name.' or 1 % 0 == 1"), Ok(t));
        assert!(run("type() == 1 + ").is_err());
    }

    #[test]
    fn rejects_at_compile_time() {
        for bad in [
            "invalid expression",
            "nope()",
            "name",
            "incidr('a')",
            "1 + 'x'",
            "name() == 1",
            "!1",
            "name() matches '('",
            "#",
            "1..3",
            "{a: 1}",
            "toJSON(1)",
            "len(1)",
            "incidr(1, 2)",
            "'' ?: 'y'",
            "'abc'[0]",
        ] {
            assert!(Program::compile(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn operators_and_builtins() {
        let cases: &[(&str, Value)] = &[
            ("1 + 2 * 3", Value::Int(7)),
            ("(1 + 2) * 3", Value::Int(9)),
            ("7 / 2", Value::Float(3.5)),
            ("1 / 0 > 1000", Value::Bool(true)),
            ("7 % 4", Value::Int(3)),
            ("2 ** 3 ** 2", Value::Float(512.0)),
            ("-2 ** 2", Value::Float(-4.0)),
            ("2 ^ 2", Value::Float(4.0)),
            ("0x1f + 0b11 + 1_000", Value::Int(1034)),
            ("1e3", Value::Float(1000.0)),
            ("true ? 'a' : 'b'", Value::Str("a".into())),
            ("false ? 'a' : 1 > 0 ? 'b' : 'c'", Value::Str("b".into())),
            ("nil ?? 'x'", Value::Str("x".into())),
            ("false ?: true", Value::Bool(true)),
            ("not true == false", Value::Bool(true)),
            ("'abc' contains 'b' and 'abc' not startsWith 'b'", Value::Bool(true)),
            ("[1, 2, 3][-1]", Value::Int(3)),
            ("replace('10-0-0-1', '-', '.')", Value::Str("10.0.0.1".into())),
            ("split('a.b.c', '.')[1]", Value::Str("b".into())),
            ("len(split('a.b.c', '.', 2))", Value::Int(2)),
            ("join(['a', 'b'], '-')", Value::Str("a-b".into())),
            (
                "trimPrefix('www.x', 'www.') + trimSuffix('x.', '.')",
                Value::Str("xx".into()),
            ),
            ("trim('..a..', '.')", Value::Str("a".into())),
            ("indexOf('héllo', 'l')", Value::Int(3)),
            ("len('é')", Value::Int(2)),
            ("int('42') + int(1.9)", Value::Int(43)),
            ("float(1) / 4", Value::Float(0.25)),
            ("string(12) + string(true)", Value::Str("12true".into())),
            ("max(1, 5, 3) + min([4, 2])", Value::Int(7)),
            ("abs(-3)", Value::Int(3)),
            ("all([1, 2], # > 0)", Value::Bool(true)),
            ("any([1, 2], {# > 1})", Value::Bool(true)),
            ("none([1, 2], # > 1)", Value::Bool(false)),
            ("one([1, 2], # > 1)", Value::Bool(true)),
            ("count([1, 2, 3], # >= 2)", Value::Int(2)),
            (
                "filter([1, 2, 3], # % 2 == 1)",
                Value::List(vec![Value::Int(1), Value::Int(3)]),
            ),
            ("map([1, 2], # * 10)", Value::List(vec![Value::Int(10), Value::Int(20)])),
            ("first([1, 2]) + last([1, 2])", Value::Int(3)),
            (
                "any(['10.0.0.0/8', '192.168.0.0/16'], incidr(client_ip(), #))",
                Value::Bool(true),
            ),
            ("1 == 1.0", Value::Bool(true)),
            ("[1, 'a'] == [1, 'a']", Value::Bool(true)),
            ("'b' > 'a'", Value::Bool(true)),
            ("`raw\\n`", Value::Str("raw\\n".into())),
            ("'\\x41\\u00e9'", Value::Str("Aé".into())),
        ];
        for (src, want) in cases {
            assert_eq!(run(src).as_ref(), Ok(want), "{src}");
        }
    }

    #[test]
    fn runtime_errors() {
        for bad in [
            "incidr('notanip', '10.0.0.0/8')",
            "incidr(client_ip(), '10.0.0.0/33')",
            "int('x')",
            "[1][5]",
            "1 % 0",
            "repeat('a', -1)",
        ] {
            assert!(run(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn scope_variables_and_groups() {
        let mut scope = Scope {
            vars: Vec::new(),
            group: true,
        };
        let a = Program::compile_in("1", &scope).unwrap();
        assert_eq!(a.result_type(), Type::Int);
        scope.vars.push(("a".into(), a.result_type()));
        let b = Program::compile_in("a + 1", &scope).unwrap();
        assert_eq!(b.result_type(), Type::Int);
        scope.vars.push(("b".into(), b.result_type()));
        assert!(Program::compile_in("'x' + b", &scope).is_err());
        assert!(Program::compile_in("undefined", &scope).is_err());
        let g = Program::compile_in("group('n') + group(0) + group(9)", &scope).unwrap();
        assert!(scope.reserved("a") && scope.reserved("group") && scope.reserved("len"));
        assert!(scope.reserved("name") && scope.reserved("true") && scope.reserved("let"));
        assert!(!scope.reserved("c"));

        let ctx = Context::new(".", "dns://:53");
        let req = query("2.example.", RecordType::A, "10.0.0.7:4242");
        let groups: HashMap<String, String> = [("0", "2.example."), ("1", "2"), ("n", "2")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let vals = [Value::Int(1)];
        let env = Env {
            vars: &vals,
            groups: Some(&groups),
        };
        assert_eq!(b.run_in(&ctx, &req, &env), Ok(Value::Int(2)));
        assert_eq!(g.run_in(&ctx, &req, &env), Ok(Value::Str("22.example.".into())));
    }

    #[test]
    fn go_float_format() {
        for (f, s) in [
            (1.0, "1"),
            (2.5, "2.5"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
        ] {
            assert_eq!(format_float(f), s);
        }
    }
}
