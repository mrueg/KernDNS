//! A subset of Go's `text/template`, enough for the `template` plugin.
//!
//! Supported:
//!
//! * text and `{{ pipeline }}` actions, `{{-` / `-}}` whitespace trimming
//!   and `{{/* comments */}}`
//! * `{{ if }}` / `{{ else if }}` / `{{ else }}` / `{{ end }}`
//! * the dot, field chains (`.Name`, `.Group.a`, `.Question.Name`), the
//!   `.Meta "key"` method, fields on parenthesized pipelines
//!   (`(index .Message.Question 0).Name`)
//! * string (interpreted and raw), integer, float, boolean and `nil` literals
//! * pipelines (`x | f`) and parenthesized calls
//! * the functions `and`, `or`, `not`, `eq`, `ne`, `lt`, `le`, `gt`, `ge`,
//!   `index`, `len`, `print`, `printf`, `println` and `parseInt`
//!
//! Everything else (`range`, `with`, `define`, `template`, `block`,
//! variables, character constants, other functions, fields of `.Message`
//! and `.Question` that are not listed in [`MESSAGE_FIELDS`] and
//! [`QUESTION_FIELDS`]) is rejected when the template is parsed. Errors at
//! execution time use Go's wording, e.g. `template: answer:1:26: executing
//! "answer" at <index .Match 2>: error calling index: index out of range: 2`.

use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Write as _};

use kerndns_core::proto::op::Message;
use kerndns_core::proto::rr::{DNSClass, RecordType};

/// Fields of `.Message` (a `*dns.Msg`) a template may use.
pub const MESSAGE_FIELDS: &[&str] = &[
    "Id",
    "Response",
    "Opcode",
    "Authoritative",
    "Truncated",
    "RecursionDesired",
    "RecursionAvailable",
    "Zero",
    "AuthenticatedData",
    "CheckingDisabled",
    "Rcode",
    "Question",
];

/// Fields of `.Question` (a `*dns.Question`) a template may use.
pub const QUESTION_FIELDS: &[&str] = &["Name", "Qtype", "Qclass"];

const DATA_FIELDS: &[&str] = &[
    "Zone", "Name", "Regex", "Match", "Group", "Class", "Type", "Message", "Question", "Remote", "Var", "Meta",
];

const FUNCS: &[&str] = &[
    "and", "or", "not", "eq", "ne", "lt", "le", "gt", "ge", "index", "len", "print", "printf", "println", "parseInt",
];

/// Go builtins that are not implemented.
const UNSUPPORTED_FUNCS: &[&str] = &["call", "html", "js", "urlquery", "slice"];

/// A parsed template.
#[derive(Debug, Clone)]
pub struct Template {
    name: String,
    text: String,
    root: Vec<Node>,
}

/// The question in the template data, like `dns.Question`.
#[derive(Debug, Clone)]
pub struct Question {
    /// The name as sent, fully qualified.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl fmt::Display for Question {
    /// `dns.Question.String()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ";{}\t{}\t {}",
            self.name,
            class_to_string(self.qclass),
            type_to_string(self.qtype)
        )
    }
}

fn class_to_string(c: u16) -> String {
    match c {
        1 => "IN".into(),
        2 => "CS".into(),
        3 => "CH".into(),
        4 => "HS".into(),
        254 => "NONE".into(),
        255 => "ANY".into(),
        n => format!("CLASS{n}"),
    }
}

fn type_to_string(t: u16) -> String {
    match RecordType::from(t) {
        RecordType::Unknown(n) => format!("TYPE{n}"),
        rt => rt.to_string(),
    }
}

/// The data a template is executed with, like `templateData`.
pub struct Data<'a> {
    pub zone: String,
    pub name: String,
    pub regex: String,
    pub matches: Vec<String>,
    pub group: HashMap<String, String>,
    pub class: String,
    pub typ: String,
    pub message: Option<&'a Message>,
    pub question: Option<Question>,
    pub remote: String,
    pub meta: Option<&'a HashMap<String, String>>,
}

// ---------------------------------------------------------------- parse tree

#[derive(Debug, Clone)]
enum Node {
    Text(String),
    Action(Pipe),
    If {
        pipe: Pipe,
        then: Vec<Node>,
        els: Option<Vec<Node>>,
    },
}

#[derive(Debug, Clone)]
struct Pipe {
    pos: usize,
    cmds: Vec<Cmd>,
}

#[derive(Debug, Clone)]
struct Cmd {
    pos: usize,
    args: Vec<Arg>,
}

#[derive(Debug, Clone)]
enum Arg {
    Dot(usize),
    Field(usize, Vec<String>),
    Func(usize, String),
    Str(usize, String, String),
    Num(usize, Num, String),
    Bool(usize, bool),
    Nil(usize),
    Pipe(Box<Pipe>),
    Chain(usize, Box<Arg>, Vec<String>),
}

#[derive(Debug, Clone, Copy)]
enum Num {
    Int(i64),
    Float(f64),
}

impl Arg {
    fn pos(&self) -> usize {
        match self {
            Arg::Dot(p)
            | Arg::Field(p, _)
            | Arg::Func(p, _)
            | Arg::Str(p, ..)
            | Arg::Num(p, ..)
            | Arg::Bool(p, _)
            | Arg::Nil(p)
            | Arg::Chain(p, ..) => *p,
            Arg::Pipe(p) => p.pos,
        }
    }
}

impl fmt::Display for Arg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Arg::Dot(_) => f.write_str("."),
            Arg::Field(_, names) => {
                for n in names {
                    write!(f, ".{n}")?;
                }
                Ok(())
            }
            Arg::Func(_, n) => f.write_str(n),
            Arg::Str(_, _, raw) | Arg::Num(_, _, raw) => f.write_str(raw),
            Arg::Bool(_, b) => write!(f, "{b}"),
            Arg::Nil(_) => f.write_str("nil"),
            Arg::Pipe(p) => write!(f, "({p})"),
            Arg::Chain(_, base, names) => {
                write!(f, "{base}")?;
                for n in names {
                    write!(f, ".{n}")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, a) in self.args.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{a}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Pipe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.cmds.iter().enumerate() {
            if i > 0 {
                f.write_str(" | ")?;
            }
            write!(f, "{c}")?;
        }
        Ok(())
    }
}

fn write_list(f: &mut fmt::Formatter<'_>, nodes: &[Node]) -> fmt::Result {
    for n in nodes {
        match n {
            Node::Text(t) => f.write_str(t)?,
            Node::Action(p) => write!(f, "{{{{{p}}}}}")?,
            Node::If { pipe, then, els } => {
                write!(f, "{{{{if {pipe}}}}}")?;
                write_list(f, then)?;
                if let Some(e) = els {
                    f.write_str("{{else}}")?;
                    write_list(f, e)?;
                }
                f.write_str("{{end}}")?;
            }
        }
    }
    Ok(())
}

impl fmt::Display for Template {
    /// The template as Go's `Tree.Root.String()` prints it: actions
    /// normalized, trim markers and comments dropped.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_list(f, &self.root)
    }
}

// --------------------------------------------------------------------- lexer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Dot,
    /// The names and the position Go reports for the field.
    Field(Vec<String>, usize),
    Ident(String),
    Str(String, String),
    Num(Num, String),
    Pipe,
    LParen,
    RParen,
}

impl PartialEq for Num {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Num::Int(a), Num::Int(b)) => a == b,
            (Num::Float(a), Num::Float(b)) => a.to_bits() == b.to_bits(),
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    pos: usize,
    /// Whitespace came right before this token.
    space_before: bool,
}

#[derive(Debug)]
enum Item {
    Text(String),
    Action { pos: usize, toks: Vec<Token> },
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

struct Lexer<'a> {
    src: &'a str,
    name: &'a str,
}

impl Lexer<'_> {
    fn err(&self, pos: usize, msg: impl fmt::Display) -> String {
        let line = 1 + self.src[..pos.min(self.src.len())].matches('\n').count();
        format!("template: {}:{line}: {msg}", self.name)
    }

    fn items(&self) -> Result<Vec<Item>, String> {
        let s = self.src;
        let b = s.as_bytes();
        let mut items = Vec::new();
        let mut i = 0;
        let mut trim_next = false;
        loop {
            let start = i;
            let open = s[i..].find("{{").map(|o| i + o);
            let end = open.unwrap_or(s.len());
            let mut text = &s[start..end];
            if trim_next {
                text = text.trim_start_matches([' ', '\t', '\r', '\n']);
                trim_next = false;
            }
            let Some(open) = open else {
                if !text.is_empty() {
                    items.push(Item::Text(text.to_string()));
                }
                return Ok(items);
            };
            let mut j = open + 2;
            // left trim marker: "-" followed by a space
            if b.get(j) == Some(&b'-') && b.get(j + 1).is_some_and(|c| is_space(*c)) {
                text = text.trim_end_matches([' ', '\t', '\r', '\n']);
                j += 2;
            }
            if !text.is_empty() {
                items.push(Item::Text(text.to_string()));
            }
            // a comment must follow the delimiter (and trim marker) directly
            if s[j..].starts_with("/*") {
                let Some(close) = s[j + 2..].find("*/") else {
                    return Err(self.err(open, "unclosed comment"));
                };
                let mut m = j + 2 + close + 2;
                if s[m..].starts_with(" -}}")
                    || (b.get(m).is_some_and(|c| is_space(*c)) && s[m + 1..].starts_with("-}}"))
                {
                    trim_next = true;
                    m += 4;
                } else if s[m..].starts_with("}}") {
                    m += 2;
                } else {
                    return Err(self.err(open, "comment ends before closing delimiter"));
                }
                i = m;
                continue;
            }
            let (toks, next, trim) = self.action(j)?;
            if toks.is_empty() {
                return Err(self.err(open, "missing value for command"));
            }
            items.push(Item::Action { pos: open, toks });
            trim_next = trim;
            i = next;
        }
    }

    /// Lex the inside of an action starting at `i`. Returns the tokens, the
    /// position after `}}` and whether a right trim marker was present.
    fn action(&self, mut i: usize) -> Result<(Vec<Token>, usize, bool), String> {
        let s = self.src;
        let b = s.as_bytes();
        let mut toks = Vec::new();
        let mut space_before = true;
        loop {
            if i >= b.len() {
                return Err(self.err(i, "unclosed action"));
            }
            let c = b[i];
            if is_space(c) {
                if s[i + 1..].starts_with("-}}") {
                    return Ok((toks, i + 4, true));
                }
                i += 1;
                space_before = true;
                continue;
            }
            if s[i..].starts_with("}}") {
                return Ok((toks, i + 2, false));
            }
            let pos = i;
            let tok = match c {
                b'|' => {
                    i += 1;
                    Tok::Pipe
                }
                b'(' => {
                    i += 1;
                    Tok::LParen
                }
                b')' => {
                    i += 1;
                    Tok::RParen
                }
                b'"' => {
                    let (val, end) = self.quoted(i)?;
                    let raw = s[i..end].to_string();
                    i = end;
                    Tok::Str(val, raw)
                }
                b'`' => {
                    let Some(close) = s[i + 1..].find('`') else {
                        return Err(self.err(i, "unterminated raw quoted string"));
                    };
                    let end = i + 1 + close + 1;
                    let tok = Tok::Str(s[i + 1..end - 1].to_string(), s[i..end].to_string());
                    i = end;
                    tok
                }
                b'\'' => {
                    return Err(self.err(i, "character constants are not supported"));
                }
                b'$' => {
                    return Err(self.err(i, "template variables ($) are not supported"));
                }
                b'.' if b.get(i + 1).is_some_and(|c| c.is_ascii_digit()) => self.number(&mut i)?,
                b'.' => {
                    let mut names = Vec::new();
                    // Go positions a multi-part field at its second part.
                    let mut npos = i;
                    while b.get(i) == Some(&b'.') && b.get(i + 1).is_some_and(|c| is_ident_byte(*c)) {
                        if names.len() == 1 {
                            npos = i;
                        }
                        let st = i + 1;
                        i = st;
                        while i < b.len() && is_ident_byte(b[i]) {
                            i += 1;
                        }
                        names.push(s[st..i].to_string());
                    }
                    if names.is_empty() {
                        i += 1;
                        Tok::Dot
                    } else {
                        Tok::Field(names, npos)
                    }
                }
                b'+' | b'-' if b.get(i + 1).is_some_and(|c| c.is_ascii_digit() || *c == b'.') => self.number(&mut i)?,
                c if c.is_ascii_digit() => self.number(&mut i)?,
                c if c.is_ascii_alphabetic() || c == b'_' || c >= 0x80 => {
                    let st = i;
                    while i < b.len() && (is_ident_byte(b[i]) || b[i] >= 0x80) {
                        i += 1;
                    }
                    Tok::Ident(s[st..i].to_string())
                }
                b':' | b'=' => return Err(self.err(i, "template variables (:=, =) are not supported")),
                _ => {
                    let ch = s[i..].chars().next().unwrap_or('?');
                    return Err(self.err(i, format!("unexpected {ch:?} in command")));
                }
            };
            // a field directly after an operand: chain, e.g. (x).Name
            toks.push(Token { tok, pos, space_before });
            space_before = false;
        }
    }

    fn number(&self, i: &mut usize) -> Result<Tok, String> {
        let s = self.src;
        let b = s.as_bytes();
        let st = *i;
        let mut j = st;
        if matches!(b[j], b'+' | b'-') {
            j += 1;
        }
        let hex = s[j..].starts_with("0x") || s[j..].starts_with("0X");
        while j < b.len() {
            let c = b[j];
            let exponent_sign = matches!(c, b'+' | b'-') && !hex && matches!(b[j - 1], b'e' | b'E');
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || exponent_sign {
                j += 1;
            } else {
                break;
            }
        }
        *i = j;
        let raw = &s[st..j];
        let n = parse_number(raw).ok_or_else(|| self.err(st, format!("bad number syntax: {raw:?}")))?;
        Ok(Tok::Num(n, raw.to_string()))
    }

    /// An interpreted string literal at `i` (the opening quote). Returns the
    /// value and the position after the closing quote.
    fn quoted(&self, i: usize) -> Result<(String, usize), String> {
        let s = self.src;
        let mut out = String::new();
        let mut chars = s[i + 1..].char_indices();
        let unterminated = || self.err(i, "unterminated quoted string");
        while let Some((o, c)) = chars.next() {
            match c {
                '"' => return Ok((out, i + 1 + o + 1)),
                '\n' => return Err(unterminated()),
                '\\' => {
                    let (_, e) = chars.next().ok_or_else(unterminated)?;
                    let mut hex = |n: usize| -> Result<u32, String> {
                        let mut v = 0u32;
                        for _ in 0..n {
                            let (_, h) = chars.next().ok_or_else(unterminated)?;
                            v = v * 16 + h.to_digit(16).ok_or_else(|| self.err(i, "invalid syntax"))?;
                        }
                        Ok(v)
                    };
                    match e {
                        'a' => out.push('\x07'),
                        'b' => out.push('\x08'),
                        'f' => out.push('\x0c'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'v' => out.push('\x0b'),
                        '\\' => out.push('\\'),
                        '"' => out.push('"'),
                        'x' => {
                            let v = hex(2)?;
                            if v >= 0x80 {
                                return Err(self.err(i, "non-ASCII \\x escapes are not supported"));
                            }
                            out.push(char::from(v as u8));
                        }
                        'u' | 'U' => {
                            let v = hex(if e == 'u' { 4 } else { 8 })?;
                            out.push(char::from_u32(v).ok_or_else(|| self.err(i, "invalid syntax"))?);
                        }
                        '0'..='7' => {
                            let mut v = e.to_digit(8).unwrap_or(0);
                            for _ in 0..2 {
                                let (_, d) = chars.next().ok_or_else(unterminated)?;
                                v = v * 8 + d.to_digit(8).ok_or_else(|| self.err(i, "invalid syntax"))?;
                            }
                            if v >= 0x80 {
                                return Err(self.err(i, "non-ASCII octal escapes are not supported"));
                            }
                            out.push(char::from(v as u8));
                        }
                        _ => return Err(self.err(i, "invalid syntax")),
                    }
                }
                c => out.push(c),
            }
        }
        Err(unterminated())
    }
}

/// A Go number literal as text/template types it: an `int` if it is an
/// integer that fits, a `float64` if it has a fraction or exponent.
fn parse_number(raw: &str) -> Option<Num> {
    let (neg, body) = match raw.as_bytes().first()? {
        b'-' => (true, &raw[1..]),
        b'+' => (false, &raw[1..]),
        _ => (false, raw),
    };
    let clean: String = body.chars().filter(|c| *c != '_').collect();
    let lower = clean.to_ascii_lowercase();
    let (radix, digits) = if let Some(d) = lower.strip_prefix("0x") {
        (16, d)
    } else if let Some(d) = lower.strip_prefix("0o") {
        (8, d)
    } else if let Some(d) = lower.strip_prefix("0b") {
        (2, d)
    } else if lower.contains(['.', 'e']) {
        let f: f64 = lower.parse().ok()?;
        return Some(Num::Float(if neg { -f } else { f }));
    } else if lower.len() > 1 && lower.starts_with('0') {
        (8, &lower[1..])
    } else {
        (10, lower.as_str())
    };
    if digits.is_empty() {
        return None;
    }
    let v = i128::from_str_radix(digits, radix).ok()?;
    let v = if neg { -v } else { v };
    i64::try_from(v).ok().map(Num::Int)
}

// -------------------------------------------------------------------- parser

struct Parser<'a> {
    lx: &'a Lexer<'a>,
    toks: Vec<Token>,
    i: usize,
    end: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.i)
    }

    fn pipe(&mut self, pos: usize, inner: bool) -> Result<Pipe, String> {
        let mut cmds = Vec::new();
        loop {
            let cmd = self.cmd()?;
            if cmd.args.is_empty() {
                return Err(self.lx.err(pos, "missing value for command"));
            }
            if !cmds.is_empty() {
                // Go rejects literals as later pipeline stages.
                if !matches!(
                    cmd.args[0],
                    Arg::Func(..) | Arg::Field(..) | Arg::Chain(..) | Arg::Pipe(_)
                ) {
                    return Err(self.lx.err(
                        pos,
                        format!("non executable command in pipeline stage {}", cmds.len() + 1),
                    ));
                }
            }
            if matches!(cmd.args[0], Arg::Nil(_)) {
                return Err(self.lx.err(pos, "nil is not a command"));
            }
            cmds.push(cmd);
            match self.peek().map(|t| &t.tok) {
                Some(Tok::Pipe) => {
                    self.i += 1;
                }
                Some(Tok::RParen) if inner => break,
                None if !inner => break,
                None => return Err(self.lx.err(self.end, "unclosed left paren")),
                Some(t) => return Err(self.lx.err(pos, format!("unexpected {t:?} in operand"))),
            }
        }
        Ok(Pipe { pos, cmds })
    }

    fn cmd(&mut self) -> Result<Cmd, String> {
        let pos = self.peek().map(|t| t.pos).unwrap_or(self.end);
        let mut args = Vec::new();
        while let Some(t) = self.peek() {
            if matches!(t.tok, Tok::Pipe | Tok::RParen) {
                break;
            }
            if !args.is_empty() && !t.space_before {
                return Err(self.lx.err(t.pos, "missing space between operands"));
            }
            args.push(self.operand()?);
        }
        Ok(Cmd { pos, args })
    }

    fn operand(&mut self) -> Result<Arg, String> {
        let t = self.toks[self.i].clone();
        self.i += 1;
        let pos = t.pos;
        let term = match t.tok {
            Tok::Dot => Arg::Dot(pos),
            Tok::Field(names, fpos) => Arg::Field(fpos, names),
            Tok::Str(v, raw) => Arg::Str(pos, v, raw),
            Tok::Num(n, raw) => Arg::Num(pos, n, raw),
            Tok::Ident(id) => match id.as_str() {
                "true" => Arg::Bool(pos, true),
                "false" => Arg::Bool(pos, false),
                "nil" => Arg::Nil(pos),
                "if" | "else" | "end" | "range" | "with" | "define" | "template" | "block" | "break" | "continue" => {
                    return Err(self.lx.err(pos, format!("unexpected <{id}> in command")));
                }
                f if FUNCS.contains(&f) => Arg::Func(pos, id),
                f if UNSUPPORTED_FUNCS.contains(&f) => {
                    return Err(self.lx.err(pos, format!("function {f:?} is not supported")));
                }
                f => return Err(self.lx.err(pos, format!("function {f:?} not defined"))),
            },
            Tok::LParen => {
                let p = self.pipe(pos, true)?;
                match self.peek() {
                    Some(Token { tok: Tok::RParen, .. }) => self.i += 1,
                    _ => return Err(self.lx.err(pos, "unclosed left paren")),
                }
                Arg::Pipe(Box::new(p))
            }
            Tok::RParen => return Err(self.lx.err(pos, "unexpected right paren")),
            Tok::Pipe => return Err(self.lx.err(pos, "unexpected \"|\" in operand")),
        };
        // field chain: a field token glued to the operand
        if let Some(Token {
            tok: Tok::Field(names, _),
            space_before: false,
            pos: fpos,
        }) = self.peek()
        {
            let (names, fpos) = (names.clone(), *fpos);
            match term {
                Arg::Pipe(_) => {
                    self.i += 1;
                    return Ok(Arg::Chain(fpos, Box::new(term), names));
                }
                _ => return Err(self.lx.err(pos, format!("unexpected . after term \"{term}\""))),
            }
        }
        Ok(term)
    }
}

enum Frame {
    Root(Vec<Node>),
    If {
        pipe: Pipe,
        then: Vec<Node>,
        els: Option<Vec<Node>>,
        /// Opened by `{{ else if }}`: closed by the same `{{ end }}` as its parent.
        chained: bool,
    },
}

impl Frame {
    fn list(&mut self) -> &mut Vec<Node> {
        match self {
            Frame::Root(l) => l,
            Frame::If { then, els: None, .. } => then,
            Frame::If { els: Some(e), .. } => e,
        }
    }
}

impl Template {
    /// Parse `text`. `name` is used in errors, like `template.New(name)`.
    pub fn parse(name: &str, text: &str) -> Result<Template, String> {
        let lx = Lexer { src: text, name };
        let mut stack = vec![Frame::Root(Vec::new())];
        for item in lx.items()? {
            let (pos, toks) = match item {
                Item::Text(t) => {
                    stack.last_mut().unwrap().list().push(Node::Text(t));
                    continue;
                }
                Item::Action { pos, toks } => (pos, toks),
            };
            let kw = match &toks[0].tok {
                Tok::Ident(k) => k.as_str(),
                _ => "",
            };
            let end = toks.last().map(|t| t.pos).unwrap_or(pos);
            match kw {
                "if" => {
                    let pipe = Parser {
                        lx: &lx,
                        toks,
                        i: 1,
                        end,
                    }
                    .pipe(pos, false)?;
                    stack.push(Frame::If {
                        pipe,
                        then: Vec::new(),
                        els: None,
                        chained: false,
                    });
                }
                "else" => {
                    match stack.last_mut() {
                        Some(Frame::If { els: els @ None, .. }) => *els = Some(Vec::new()),
                        _ => return Err(lx.err(pos, "unexpected {{else}}")),
                    }
                    if toks.len() > 1 {
                        if !matches!(&toks[1].tok, Tok::Ident(k) if k == "if") {
                            return Err(lx.err(pos, "unexpected token in else; expected if or end"));
                        }
                        let pipe = Parser {
                            lx: &lx,
                            toks,
                            i: 2,
                            end,
                        }
                        .pipe(pos, false)?;
                        stack.push(Frame::If {
                            pipe,
                            then: Vec::new(),
                            els: None,
                            chained: true,
                        });
                    }
                }
                "end" => {
                    if toks.len() > 1 {
                        return Err(lx.err(pos, "unexpected token in end"));
                    }
                    loop {
                        let Some(Frame::If {
                            pipe,
                            then,
                            els,
                            chained,
                        }) = stack.pop()
                        else {
                            return Err(lx.err(pos, "unexpected {{end}}"));
                        };
                        stack.last_mut().unwrap().list().push(Node::If { pipe, then, els });
                        if !chained {
                            break;
                        }
                    }
                }
                "range" | "with" | "define" | "template" | "block" | "break" | "continue" => {
                    return Err(lx.err(pos, format!("{{{{{kw}}}}} is not supported")));
                }
                _ => {
                    let pipe = Parser {
                        lx: &lx,
                        toks,
                        i: 0,
                        end,
                    }
                    .pipe(pos, false)?;
                    stack.last_mut().unwrap().list().push(Node::Action(pipe));
                }
            }
        }
        if stack.len() != 1 {
            return Err(lx.err(text.len(), "unexpected EOF"));
        }
        let Some(Frame::Root(root)) = stack.pop() else {
            unreachable!()
        };
        let t = Template {
            name: name.to_string(),
            text: text.to_string(),
            root,
        };
        t.validate(&t.root)?;
        Ok(t)
    }

    /// Reject `.Message` and `.Question` fields this engine does not know.
    fn validate(&self, nodes: &[Node]) -> Result<(), String> {
        for n in nodes {
            match n {
                Node::Text(_) => {}
                Node::Action(p) => self.validate_pipe(p)?,
                Node::If { pipe, then, els } => {
                    self.validate_pipe(pipe)?;
                    self.validate(then)?;
                    if let Some(e) = els {
                        self.validate(e)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_pipe(&self, p: &Pipe) -> Result<(), String> {
        for c in &p.cmds {
            if let [Arg::Func(_, f), Arg::Str(pos, format, _), ..] = c.args.as_slice()
                && f == "printf"
            {
                let lx = Lexer {
                    src: &self.text,
                    name: &self.name,
                };
                check_format(format).map_err(|e| lx.err(*pos, e))?;
            }
            for a in &c.args {
                self.validate_arg(a)?;
            }
        }
        Ok(())
    }

    fn validate_arg(&self, a: &Arg) -> Result<(), String> {
        let lx = Lexer {
            src: &self.text,
            name: &self.name,
        };
        match a {
            Arg::Pipe(p) => self.validate_pipe(p),
            Arg::Chain(_, base, _) => self.validate_arg(base),
            Arg::Dot(pos) => Err(lx.err(
                *pos,
                "the dot (.) on its own is not supported, use a field such as .Name",
            )),
            Arg::Field(pos, names) => {
                let unsupported = |what: String| Err(lx.err(*pos, format!("{what} is not supported")));
                match names[0].as_str() {
                    "Message" => match names.get(1) {
                        None => unsupported("printing or passing the whole .Message".into()),
                        Some(f) if !MESSAGE_FIELDS.contains(&f.as_str()) => unsupported(format!(".Message.{f}")),
                        _ => Ok(()),
                    },
                    "Question" => match names.get(1) {
                        Some(f) if !QUESTION_FIELDS.contains(&f.as_str()) => unsupported(format!(".Question.{f}")),
                        _ => Ok(()),
                    },
                    _ => Ok(()),
                }
            }
            _ => Ok(()),
        }
    }

    /// Run the template, like `Template.Execute`.
    pub fn execute(&self, data: &Data<'_>) -> Result<String, String> {
        let mut out = String::new();
        let ex = Exec { t: self, data };
        ex.walk(&self.root, &mut out)?;
        Ok(out)
    }
}

// ----------------------------------------------------------------- execution

#[derive(Debug, Clone)]
enum Value {
    /// A missing map entry, printed as `<no value>`.
    Missing,
    Nil,
    Str(String),
    Int(i64, &'static str),
    Uint(u64, &'static str),
    Float(f64),
    Bool(bool),
    List(Vec<Value>, &'static str),
    Map(BTreeMap<String, Value>, &'static str),
    Question(Question),
    /// `.Message`; only its fields can be used.
    Message,
    /// The template data (the dot).
    Data,
}

impl Value {
    fn type_name(&self) -> String {
        match self {
            Value::Missing | Value::Nil => "<nil>".into(),
            Value::Str(_) => "string".into(),
            Value::Int(_, t) | Value::Uint(_, t) => (*t).into(),
            Value::Float(_) => "float64".into(),
            Value::Bool(_) => "bool".into(),
            Value::List(_, t) | Value::Map(_, t) => (*t).into(),
            Value::Question(_) => "dns.Question".into(),
            Value::Message => "*dns.Msg".into(),
            Value::Data => "*template.templateData".into(),
        }
    }

    fn truth(&self) -> bool {
        match self {
            Value::Missing | Value::Nil => false,
            Value::Str(s) => !s.is_empty(),
            Value::Int(i, _) => *i != 0,
            Value::Uint(u, _) => *u != 0,
            Value::Float(f) => *f != 0.0,
            Value::Bool(b) => *b,
            Value::List(l, _) => !l.is_empty(),
            Value::Map(m, _) => !m.is_empty(),
            Value::Question(_) | Value::Message | Value::Data => true,
        }
    }
}

/// `%v` formatting.
fn fmt_v(v: &Value, top: bool) -> String {
    match v {
        Value::Missing if top => "<no value>".into(),
        Value::Missing | Value::Nil => "<nil>".into(),
        Value::Str(s) => s.clone(),
        Value::Int(i, _) => i.to_string(),
        Value::Uint(u, _) => u.to_string(),
        Value::Float(f) => fmt_float_g(*f, None, false),
        Value::Bool(b) => b.to_string(),
        Value::List(l, _) => format!("[{}]", l.iter().map(fmt_elem).collect::<Vec<_>>().join(" ")),
        Value::Map(m, _) => format!(
            "map[{}]",
            m.iter()
                .map(|(k, e)| format!("{k}:{}", fmt_elem(e)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Value::Question(q) => q.to_string(),
        Value::Message => "<*dns.Msg>".into(),
        Value::Data => "<*template.templateData>".into(),
    }
}

/// A parameter type of a function with a fixed signature.
#[derive(Clone, Copy)]
enum Kind {
    Str,
    Int,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Str => "string",
            Kind::Int => "int",
        }
    }
}

/// `%v` of a slice or map element: questions are plain structs there (their
/// `String` method needs a pointer).
fn fmt_elem(v: &Value) -> String {
    match v {
        Value::Question(q) => format!("{{{} {} {}}}", q.name, q.qtype, q.qclass),
        v => fmt_v(v, false),
    }
}

struct Exec<'a, 'b> {
    t: &'a Template,
    data: &'a Data<'b>,
}

/// Where an error happened: the node's position and its text.
struct At<'n> {
    pos: usize,
    ctx: &'n dyn fmt::Display,
}

impl Exec<'_, '_> {
    fn err(&self, at: &At<'_>, msg: impl fmt::Display) -> String {
        let text = &self.t.text[..at.pos.min(self.t.text.len())];
        let (line, col) = match text.rfind('\n') {
            Some(nl) => (1 + text.matches('\n').count(), at.pos - (nl + 1)),
            None => (1, at.pos),
        };
        format!(
            "template: {}:{line}:{col}: executing {:?} at <{}>: {msg}",
            self.t.name, self.t.name, at.ctx
        )
    }

    fn walk(&self, nodes: &[Node], out: &mut String) -> Result<(), String> {
        for n in nodes {
            match n {
                Node::Text(t) => out.push_str(t),
                Node::Action(p) => {
                    let v = self.pipe(p)?;
                    if matches!(v, Value::Message | Value::Data) {
                        return Err(self.err(
                            &At { pos: p.pos, ctx: p },
                            format!("printing a {} is not supported", v.type_name()),
                        ));
                    }
                    out.push_str(&fmt_v(&v, true));
                }
                Node::If { pipe, then, els } => {
                    if self.pipe(pipe)?.truth() {
                        self.walk(then, out)?;
                    } else if let Some(e) = els {
                        self.walk(e, out)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn pipe(&self, p: &Pipe) -> Result<Value, String> {
        let mut prev: Option<Value> = None;
        for c in &p.cmds {
            prev = Some(self.cmd(c, prev)?);
        }
        Ok(prev.unwrap_or(Value::Missing))
    }

    fn cmd(&self, c: &Cmd, final_arg: Option<Value>) -> Result<Value, String> {
        let at = At { pos: c.pos, ctx: c };
        let first = &c.args[0];
        let rest = &c.args[1..];
        match first {
            Arg::Func(_, name) => {
                let mut args = Vec::with_capacity(rest.len() + 1);
                // and/or short-circuit
                if name == "and" || name == "or" {
                    let n = rest.len() + usize::from(final_arg.is_some());
                    if n == 0 {
                        return Err(self.err(&at, format!("wrong number of args for {name}: want at least 1 got 0")));
                    }
                    let mut last = Value::Missing;
                    for a in rest {
                        last = self.arg(a)?;
                        if last.truth() != (name == "and") {
                            return Ok(last);
                        }
                    }
                    if let Some(f) = final_arg {
                        last = f;
                    }
                    return Ok(last);
                }
                if name == "parseInt" {
                    args = self.typed_args(&at, name, rest, final_arg, &[Kind::Str, Kind::Int, Kind::Int])?;
                } else {
                    for a in rest {
                        args.push(self.arg(a)?);
                    }
                    if let Some(f) = final_arg {
                        args.push(f);
                    }
                }
                self.call(&at, name, args)
            }
            Arg::Field(pos, names) => {
                let fat = At { pos: *pos, ctx: first };
                let mut args = Vec::new();
                if names.len() == 1 && names[0] == "Meta" {
                    args = self.typed_args(&fat, "Meta", rest, final_arg, &[Kind::Str])?;
                } else {
                    for a in rest {
                        args.push(self.arg(a)?);
                    }
                    if let Some(f) = final_arg {
                        args.push(f);
                    }
                }
                self.field_chain(&fat, Value::Data, names, args)
            }
            Arg::Chain(pos, base, names) => {
                let mut args = Vec::new();
                for a in rest {
                    args.push(self.arg(a)?);
                }
                if let Some(f) = final_arg {
                    args.push(f);
                }
                let base = self.arg(base)?;
                let fat = At { pos: *pos, ctx: first };
                self.field_chain(&fat, base, names, args)
            }
            _ => {
                if !rest.is_empty() || final_arg.is_some() {
                    let fat = At {
                        pos: first.pos(),
                        ctx: first,
                    };
                    return Err(self.err(&fat, format!("can't give argument to non-function {first}")));
                }
                self.arg(first)
            }
        }
    }

    /// Evaluate the arguments of a function with a fixed signature, with
    /// Go's arity and type errors.
    fn typed_args(
        &self,
        at: &At<'_>,
        name: &str,
        rest: &[Arg],
        final_arg: Option<Value>,
        sig: &[Kind],
    ) -> Result<Vec<Value>, String> {
        let n = rest.len() + usize::from(final_arg.is_some());
        if n != sig.len() {
            return Err(self.err(
                at,
                format!("wrong number of args for {name}: want {} got {n}", sig.len()),
            ));
        }
        let mut out = Vec::with_capacity(n);
        for (a, k) in rest.iter().zip(sig) {
            let aat = At { pos: a.pos(), ctx: a };
            let v = match (a, k) {
                (Arg::Nil(_), k) => return Err(self.err(&aat, format!("cannot assign nil to {}", k.name()))),
                (Arg::Field(..) | Arg::Chain(..) | Arg::Pipe(_) | Arg::Dot(_) | Arg::Func(..), k) => {
                    let v = self.arg(a)?;
                    self.check_type(&aat, v, *k)?
                }
                (Arg::Str(..), Kind::Str) | (Arg::Num(_, Num::Int(_), _), Kind::Int) => self.arg(a)?,
                (_, Kind::Str) => return Err(self.err(&aat, format!("expected string; found {a}"))),
                (_, Kind::Int) => return Err(self.err(&aat, format!("expected integer; found {a}"))),
            };
            out.push(v);
        }
        if let Some(f) = final_arg {
            out.push(self.check_type(at, f, sig[n - 1])?);
        }
        Ok(out)
    }

    fn check_type(&self, at: &At<'_>, v: Value, k: Kind) -> Result<Value, String> {
        match (&v, k) {
            (Value::Str(_), Kind::Str) | (Value::Int(_, "int"), Kind::Int) => Ok(v),
            (Value::Missing | Value::Nil, k) => Err(self.err(at, format!("invalid value; expected {}", k.name()))),
            (v, k) => Err(self.err(
                at,
                format!("wrong type for value; expected {}; got {}", k.name(), v.type_name()),
            )),
        }
    }

    fn arg(&self, a: &Arg) -> Result<Value, String> {
        match a {
            Arg::Dot(_) => Ok(Value::Data),
            Arg::Field(pos, names) => self.field_chain(&At { pos: *pos, ctx: a }, Value::Data, names, Vec::new()),
            Arg::Chain(pos, base, names) => {
                let b = self.arg(base)?;
                self.field_chain(&At { pos: *pos, ctx: a }, b, names, Vec::new())
            }
            Arg::Func(_, name) => self.call(&At { pos: a.pos(), ctx: a }, name, Vec::new()),
            Arg::Str(_, s, _) => Ok(Value::Str(s.clone())),
            Arg::Num(_, Num::Int(i), _) => Ok(Value::Int(*i, "int")),
            Arg::Num(_, Num::Float(f), _) => Ok(Value::Float(*f)),
            Arg::Bool(_, b) => Ok(Value::Bool(*b)),
            Arg::Nil(_) => Ok(Value::Nil),
            Arg::Pipe(p) => self.pipe(p),
        }
    }

    /// Evaluate `.A.B.C` on `recv`; `args` go to the last element (a method).
    fn field_chain(&self, at: &At<'_>, mut recv: Value, names: &[String], args: Vec<Value>) -> Result<Value, String> {
        let mut args = Some(args);
        for (i, n) in names.iter().enumerate() {
            let last = i + 1 == names.len();
            let a = if last {
                args.take().unwrap_or_default()
            } else {
                Vec::new()
            };
            recv = self.field(at, recv, n, a)?;
        }
        Ok(recv)
    }

    fn field(&self, at: &At<'_>, recv: Value, name: &str, args: Vec<Value>) -> Result<Value, String> {
        let no_args = |v: Value| -> Result<Value, String> {
            if args.is_empty() {
                Ok(v)
            } else {
                Err(self.err(at, format!("{name} has arguments but cannot be invoked as function")))
            }
        };
        let d = self.data;
        let strs = |l: &[String]| Value::List(l.iter().cloned().map(Value::Str).collect(), "[]string");
        match recv {
            Value::Data => {
                if name == "Meta" {
                    if args.len() != 1 {
                        return Err(self.err(at, format!("wrong number of args for Meta: want 1 got {}", args.len())));
                    }
                    let key = match &args[0] {
                        Value::Str(s) => s.clone(),
                        v => {
                            return Err(self.err(
                                at,
                                format!("wrong type for value; expected string; got {}", v.type_name()),
                            ));
                        }
                    };
                    return Ok(Value::Str(
                        d.meta.and_then(|m| m.get(&key)).cloned().unwrap_or_default(),
                    ));
                }
                let v = match name {
                    "Zone" => Value::Str(d.zone.clone()),
                    "Name" => Value::Str(d.name.clone()),
                    "Regex" => Value::Str(d.regex.clone()),
                    "Class" => Value::Str(d.class.clone()),
                    "Type" => Value::Str(d.typ.clone()),
                    "Remote" => Value::Str(d.remote.clone()),
                    "Match" => strs(&d.matches),
                    "Group" => Value::Map(
                        d.group
                            .iter()
                            .map(|(k, v)| (k.clone(), Value::Str(v.clone())))
                            .collect(),
                        "map[string]string",
                    ),
                    // `var` is not supported, so there are never variables.
                    "Var" => Value::Map(BTreeMap::new(), "map[string]interface {}"),
                    "Message" => match d.message {
                        Some(_) => Value::Message,
                        None => Value::Nil,
                    },
                    "Question" => match &d.question {
                        Some(q) => Value::Question(q.clone()),
                        None => Value::Nil,
                    },
                    _ => {
                        debug_assert!(!DATA_FIELDS.contains(&name));
                        return Err(self.err(
                            at,
                            format!("can't evaluate field {name} in type *template.templateData"),
                        ));
                    }
                };
                no_args(v)
            }
            Value::Map(m, _) => {
                if !args.is_empty() {
                    return Err(self.err(at, format!("{name} is not a method but has arguments")));
                }
                Ok(m.get(name).cloned().unwrap_or(Value::Missing))
            }
            Value::Question(q) => no_args(match name {
                "Name" => Value::Str(q.name),
                "Qtype" => Value::Uint(q.qtype.into(), "uint16"),
                "Qclass" => Value::Uint(q.qclass.into(), "uint16"),
                _ => return Err(self.err(at, format!("can't evaluate field {name} in type dns.Question"))),
            }),
            Value::Message => {
                let Some(m) = d.message else {
                    return Err(self.err(at, format!("nil pointer evaluating *dns.Msg.{name}")));
                };
                let h = &m.metadata;
                no_args(match name {
                    "Id" => Value::Uint(h.id.into(), "uint16"),
                    "Response" => Value::Bool(h.message_type == kerndns_core::proto::op::MessageType::Response),
                    "Opcode" => Value::Int(u8::from(h.op_code).into(), "int"),
                    "Authoritative" => Value::Bool(h.authoritative),
                    "Truncated" => Value::Bool(h.truncation),
                    "RecursionDesired" => Value::Bool(h.recursion_desired),
                    "RecursionAvailable" => Value::Bool(h.recursion_available),
                    "Zero" => Value::Bool(false),
                    "AuthenticatedData" => Value::Bool(h.authentic_data),
                    "CheckingDisabled" => Value::Bool(h.checking_disabled),
                    "Rcode" => Value::Int(u16::from(h.response_code).into(), "int"),
                    "Question" => Value::List(
                        m.queries
                            .iter()
                            .map(|q| {
                                let mut name = q.name().to_ascii();
                                if !name.ends_with('.') {
                                    name.push('.');
                                }
                                Value::Question(Question {
                                    name,
                                    qtype: q.query_type().into(),
                                    qclass: q.query_class().into(),
                                })
                            })
                            .collect(),
                        "[]dns.Question",
                    ),
                    _ => return Err(self.err(at, format!("can't evaluate field {name} in type *dns.Msg"))),
                })
            }
            Value::Missing | Value::Nil => Err(self.err(at, format!("nil pointer evaluating interface {{}}.{name}"))),
            v => Err(self.err(at, format!("can't evaluate field {name} in type {}", v.type_name()))),
        }
    }

    fn call(&self, at: &At<'_>, name: &str, args: Vec<Value>) -> Result<Value, String> {
        let want = |n: usize| -> Result<(), String> {
            if args.len() != n {
                return Err(self.err(
                    at,
                    format!("wrong number of args for {name}: want {n} got {}", args.len()),
                ));
            }
            Ok(())
        };
        let calling = |e: String| self.err(at, format!("error calling {name}: {e}"));
        match name {
            "not" => {
                want(1)?;
                Ok(Value::Bool(!args[0].truth()))
            }
            "len" => {
                want(1)?;
                let n = match &args[0] {
                    Value::Str(s) => s.len(),
                    Value::List(l, _) => l.len(),
                    Value::Map(m, _) => m.len(),
                    Value::Missing | Value::Nil => return Err(calling("len of nil pointer".into())),
                    v => return Err(calling(format!("len of type {}", v.type_name()))),
                };
                Ok(Value::Int(n as i64, "int"))
            }
            "index" => {
                if args.is_empty() {
                    return Err(self.err(at, "wrong number of args for index: want at least 1 got 0"));
                }
                let mut item = args[0].clone();
                for ix in &args[1..] {
                    item = index(item, ix).map_err(calling)?;
                }
                Ok(item)
            }
            "eq" | "ne" | "lt" | "le" | "gt" | "ge" => {
                if name == "eq" {
                    if args.is_empty() {
                        return Err(self.err(at, "wrong number of args for eq: want at least 1 got 0"));
                    }
                    if args.len() == 1 {
                        return Err(calling("missing argument for comparison".into()));
                    }
                    for b in &args[1..] {
                        if equal(&args[0], b).map_err(calling)? {
                            return Ok(Value::Bool(true));
                        }
                    }
                    return Ok(Value::Bool(false));
                }
                want(2)?;
                let (a, b) = (&args[0], &args[1]);
                let r = match name {
                    "ne" => !equal(a, b).map_err(calling)?,
                    "lt" => less(a, b).map_err(calling)?,
                    "le" => less(a, b).map_err(calling)? || equal(a, b).map_err(calling)?,
                    "gt" => !(less(a, b).map_err(calling)? || equal(a, b).map_err(calling)?),
                    _ => !less(a, b).map_err(calling)?,
                };
                Ok(Value::Bool(r))
            }
            "print" => {
                let mut s = String::new();
                for (i, a) in args.iter().enumerate() {
                    let is_str = |v: &Value| matches!(v, Value::Str(_));
                    if i > 0 && !is_str(a) && !is_str(&args[i - 1]) {
                        s.push(' ');
                    }
                    s.push_str(&fmt_v(a, false));
                }
                Ok(Value::Str(s))
            }
            "println" => {
                let parts: Vec<String> = args.iter().map(|a| fmt_v(a, false)).collect();
                Ok(Value::Str(parts.join(" ") + "\n"))
            }
            "printf" => {
                if args.is_empty() {
                    return Err(self.err(at, "wrong number of args for printf: want at least 1 got 0"));
                }
                let Value::Str(f) = &args[0] else {
                    return Err(self.err(
                        at,
                        format!("wrong type for value; expected string; got {}", args[0].type_name()),
                    ));
                };
                sprintf(f, &args[1..]).map(Value::Str).map_err(|e| self.err(at, e))
            }
            "parseInt" => {
                want(3)?;
                let Value::Str(s) = &args[0] else {
                    let msg = match &args[0] {
                        Value::Missing | Value::Nil => "invalid value; expected string".to_string(),
                        v => format!("wrong type for value; expected string; got {}", v.type_name()),
                    };
                    return Err(self.err(at, msg));
                };
                let int_arg = |v: &Value| -> Result<i64, String> {
                    match v {
                        Value::Int(i, _) => Ok(*i),
                        Value::Uint(u, _) if *u <= i64::MAX as u64 => Ok(*u as i64),
                        v => Err(self.err(at, format!("wrong type for value; expected int; got {}", v.type_name()))),
                    }
                };
                let base = int_arg(&args[1])?;
                let bits = int_arg(&args[2])?;
                parse_uint(s, base, bits)
                    .map(|u| Value::Uint(u, "uint64"))
                    .map_err(calling)
            }
            _ => Err(self.err(at, format!("function {name:?} not defined"))),
        }
    }
}

fn index(item: Value, ix: &Value) -> Result<Value, String> {
    // Go checks the index against the capacity, which is the length here;
    // an index equal to it trips reflect's own check.
    let int_ix = |len: usize, what: &str| -> Result<usize, String> {
        let i = match ix {
            Value::Int(i, _) => *i,
            Value::Uint(u, _) => i64::try_from(*u).unwrap_or(i64::MAX),
            Value::Missing | Value::Nil => return Err("cannot index slice/array with nil".into()),
            v => return Err(format!("cannot index slice/array with type {}", v.type_name())),
        };
        if i < 0 || i as usize > len {
            return Err(format!("index out of range: {i}"));
        }
        if i as usize == len {
            return Err(format!("reflect: {what} index out of range"));
        }
        Ok(i as usize)
    };
    match item {
        Value::List(l, _) => {
            let i = int_ix(l.len(), "slice")?;
            Ok(l[i].clone())
        }
        Value::Str(s) => {
            let i = int_ix(s.len(), "string")?;
            Ok(Value::Uint(s.as_bytes()[i].into(), "uint8"))
        }
        Value::Map(m, _) => match ix {
            Value::Str(k) => Ok(m.get(k).cloned().unwrap_or(Value::Str(String::new()))),
            Value::Missing | Value::Nil => Ok(Value::Str(String::new())),
            v => Err(format!("value has type {}; should be string", v.type_name())),
        },
        Value::Missing | Value::Nil => Err("index of untyped nil".into()),
        v => Err(format!("can't index item of type {}", v.type_name())),
    }
}

fn equal(a: &Value, b: &Value) -> Result<bool, String> {
    use Value::*;
    Ok(match (a, b) {
        (Str(x), Str(y)) => x == y,
        (Bool(x), Bool(y)) => x == y,
        (Float(x), Float(y)) => x == y,
        (Int(x, _), Int(y, _)) => x == y,
        (Uint(x, _), Uint(y, _)) => x == y,
        (Int(x, _), Uint(y, _)) | (Uint(y, _), Int(x, _)) => *x >= 0 && *x as u64 == *y,
        (Missing | Nil, Missing | Nil) => true,
        (Missing | Nil, _) | (_, Missing | Nil) => false,
        (Question(_) | List(..) | Map(..) | Message | Data, _)
        | (_, Question(_) | List(..) | Map(..) | Message | Data) => {
            return Err(format!(
                "non-comparable types {}: {}, {}: {}",
                fmt_v(a, false),
                a.type_name(),
                b.type_name(),
                fmt_v(b, false)
            ));
        }
        _ => return Err(incompatible(a, b)),
    })
}

fn incompatible(a: &Value, b: &Value) -> String {
    format!(
        "incompatible types for comparison: {} and {}",
        a.type_name(),
        b.type_name()
    )
}

fn less(a: &Value, b: &Value) -> Result<bool, String> {
    use Value::*;
    Ok(match (a, b) {
        (Str(x), Str(y)) => x < y,
        (Float(x), Float(y)) => x < y,
        (Int(x, _), Int(y, _)) => x < y,
        (Uint(x, _), Uint(y, _)) => x < y,
        (Int(x, _), Uint(y, _)) => *x < 0 || (*x as u64) < *y,
        (Uint(x, _), Int(y, _)) => *y >= 0 && *x < *y as u64,
        (Missing | Nil, _) | (_, Missing | Nil) => return Err("invalid type for comparison".into()),
        (Bool(_) | Question(_) | List(..) | Map(..) | Message | Data, _) => {
            return Err("invalid type for comparison".into());
        }
        _ => return Err(incompatible(a, b)),
    })
}

/// `strconv.ParseUint(s, base, bitSize)` including its error messages.
fn parse_uint(s: &str, base: i64, bits: i64) -> Result<u64, String> {
    let fail = |what: &str| format!("strconv.ParseUint: parsing {}: {what}", go_quote(s));
    if s.is_empty() {
        return Err(fail("invalid syntax"));
    }
    let bits = if bits == 0 { 64 } else { bits };
    if !(1..=64).contains(&bits) {
        return Err(fail(&format!("invalid bit size {bits}")));
    }
    let mut digits = s;
    let base = match base {
        0 => {
            let lower = s.to_ascii_lowercase();
            if lower.starts_with("0x") {
                digits = &s[2..];
                16
            } else if lower.starts_with("0o") {
                digits = &s[2..];
                8
            } else if lower.starts_with("0b") {
                digits = &s[2..];
                2
            } else if s.len() > 1 && s.starts_with('0') {
                digits = &s[1..];
                8
            } else {
                10
            }
        }
        2..=36 => base as u32,
        b => return Err(fail(&format!("invalid base {b}"))),
    };
    let underscores_ok = base != 10 || digits.len() != s.len();
    let max: u64 = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let mut n: u64 = 0;
    let mut any = false;
    let mut overflow = false;
    for c in digits.chars() {
        if c == '_' && underscores_ok && s.len() != digits.len() {
            continue;
        }
        let Some(d) = c.to_digit(base) else {
            return Err(fail("invalid syntax"));
        };
        any = true;
        match n.checked_mul(base.into()).and_then(|v| v.checked_add(d.into())) {
            Some(v) if v <= max => n = v,
            _ => overflow = true,
        }
    }
    if !any {
        return Err(fail("invalid syntax"));
    }
    if overflow {
        return Err(fail("value out of range"));
    }
    Ok(n)
}

/// `strconv.Quote` for the ASCII and common Unicode cases.
fn go_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if c.is_control() => {
                if (c as u32) < 0x10000 {
                    let _ = write!(out, "\\u{:04x}", c as u32);
                } else {
                    let _ = write!(out, "\\U{:08x}", c as u32);
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// -------------------------------------------------------------------- printf

#[derive(Default, Clone, Copy)]
struct Spec {
    minus: bool,
    plus: bool,
    sharp: bool,
    space: bool,
    zero: bool,
    width: Option<usize>,
    prec: Option<usize>,
}

impl Spec {
    fn pad(&self, s: String, numeric: bool) -> String {
        let Some(w) = self.width else { return s };
        let n = s.chars().count();
        if n >= w {
            return s;
        }
        let fill = w - n;
        if self.minus {
            return s + &" ".repeat(fill);
        }
        if self.zero {
            // zeros go after the sign
            if numeric && (s.starts_with('-') || s.starts_with('+') || s.starts_with(' ')) {
                let (sign, rest) = s.split_at(1);
                return format!("{sign}{}{rest}", "0".repeat(fill));
            }
            return "0".repeat(fill) + &s;
        }
        " ".repeat(fill) + &s
    }
}

/// Check a format string at parse time: only the verbs and flags `sprintf`
/// implements.
pub fn check_format(f: &str) -> Result<(), String> {
    let mut chars = f.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            continue;
        }
        while let Some(&c) = chars.peek() {
            if matches!(c, '-' | '+' | '#' | ' ' | '0'..='9' | '.') {
                chars.next();
            } else {
                break;
            }
        }
        match chars.next() {
            Some(
                '%' | 'v' | 's' | 'd' | 'x' | 'X' | 'o' | 'b' | 'c' | 'q' | 't' | 'f' | 'F' | 'e' | 'E' | 'g' | 'G',
            ) => {}
            Some(c) if c == '*' || c == '[' => {
                return Err(format!("printf: {c:?} in format {f:?} is not supported"));
            }
            Some(c) => return Err(format!("printf: verb %{c} in format {f:?} is not supported")),
            None => {}
        }
    }
    Ok(())
}

/// `fmt.Sprintf` for the verbs [`check_format`] accepts.
fn sprintf(f: &str, args: &[Value]) -> Result<String, String> {
    check_format(f)?;
    let mut out = String::new();
    let mut next = 0;
    let mut chars = f.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let mut sp = Spec::default();
        while let Some(&c) = chars.peek() {
            match c {
                '-' => sp.minus = true,
                '+' => sp.plus = true,
                '#' => sp.sharp = true,
                ' ' => sp.space = true,
                '0' => sp.zero = !sp.minus,
                _ => break,
            }
            chars.next();
        }
        let num = |chars: &mut std::iter::Peekable<std::str::Chars<'_>>| {
            let mut n: Option<usize> = None;
            while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
                n = Some(n.unwrap_or(0) * 10 + d as usize);
                chars.next();
            }
            n
        };
        sp.width = num(&mut chars);
        if chars.peek() == Some(&'.') {
            chars.next();
            sp.prec = Some(num(&mut chars).unwrap_or(0));
        }
        let Some(verb) = chars.next() else {
            out.push_str("%!(NOVERB)");
            break;
        };
        if verb == '%' {
            out.push('%');
            continue;
        }
        let Some(arg) = args.get(next) else {
            let _ = write!(out, "%!{verb}(MISSING)");
            continue;
        };
        next += 1;
        out.push_str(&format_one(verb, &sp, arg)?);
    }
    if next < args.len() {
        out.push_str("%!(EXTRA ");
        let extra: Vec<String> = args[next..]
            .iter()
            .map(|a| match a {
                Value::Missing | Value::Nil => "<nil>".to_string(),
                a => format!("{}={}", a.type_name(), fmt_v(a, false)),
            })
            .collect();
        out.push_str(&extra.join(", "));
        out.push(')');
    }
    Ok(out)
}

fn bad_verb(verb: char, v: &Value) -> String {
    match v {
        Value::Missing | Value::Nil => format!("%!{verb}(<nil>)"),
        v => format!("%!{verb}({}={})", v.type_name(), fmt_v(v, false)),
    }
}

fn format_one(verb: char, sp: &Spec, v: &Value) -> Result<String, String> {
    Ok(match v {
        Value::List(l, _) => {
            let parts = l
                .iter()
                .map(|e| match e {
                    Value::Question(_) if verb == 'v' => Ok(fmt_elem(e)),
                    e => format_one(verb, sp, e),
                })
                .collect::<Result<Vec<String>, String>>()?;
            format!("[{}]", parts.join(" "))
        }
        Value::Missing | Value::Nil if verb == 'v' => sp.pad("<nil>".into(), false),
        Value::Str(s) => match verb {
            'v' | 's' => {
                let s = match sp.prec {
                    Some(p) => s.chars().take(p).collect(),
                    None => s.clone(),
                };
                sp.pad(s, false)
            }
            'q' => sp.pad(go_quote(s), false),
            'x' | 'X' => {
                let mut h = String::new();
                for (i, b) in s.bytes().enumerate() {
                    if sp.space && i > 0 {
                        h.push(' ');
                    }
                    if sp.sharp && (i == 0 || sp.space) {
                        h.push_str(if verb == 'x' { "0x" } else { "0X" });
                    }
                    let _ = if verb == 'x' {
                        write!(h, "{b:02x}")
                    } else {
                        write!(h, "{b:02X}")
                    };
                }
                sp.pad(h, false)
            }
            _ => bad_verb(verb, v),
        },
        Value::Bool(b) => match verb {
            'v' | 't' => sp.pad(b.to_string(), false),
            _ => bad_verb(verb, v),
        },
        Value::Int(i, _) => fmt_integer(verb, sp, i128::from(*i), v),
        Value::Uint(u, _) => fmt_integer(verb, sp, i128::from(*u), v),
        Value::Float(f) => {
            let s = match verb {
                'v' | 'g' | 'G' => fmt_float_g(*f, sp.prec, verb == 'G'),
                'f' | 'F' => format!("{:.*}", sp.prec.unwrap_or(6), f),
                'e' | 'E' => fmt_float_e(*f, sp.prec.unwrap_or(6), verb == 'E'),
                'x' | 'X' => return Err(format!("printf: %{verb} of a float64 is not supported")),
                _ => return Ok(bad_verb(verb, v)),
            };
            let s = if sp.plus && *f >= 0.0 {
                format!("+{s}")
            } else if sp.space && *f >= 0.0 {
                format!(" {s}")
            } else {
                s
            };
            sp.pad(s, true)
        }
        Value::Question(q) if matches!(verb, 'v' | 's') => sp.pad(q.to_string(), false),
        Value::Map(..) if verb == 'v' => sp.pad(fmt_v(v, false), false),
        _ => bad_verb(verb, v),
    })
}

fn fmt_integer(verb: char, sp: &Spec, n: i128, v: &Value) -> String {
    // a precision turns off zero padding for integers
    let sp = &Spec {
        zero: sp.zero && sp.prec.is_none(),
        ..*sp
    };
    let neg = n < 0;
    let abs = n.unsigned_abs();
    let (mut digits, prefix) = match verb {
        'v' | 'd' => (abs.to_string(), ""),
        'x' => (format!("{abs:x}"), "0x"),
        'X' => (format!("{abs:X}"), "0X"),
        'o' => (format!("{abs:o}"), "0"),
        'b' => (format!("{abs:b}"), "0b"),
        'c' => {
            return sp.pad(
                char::from_u32(abs as u32)
                    .filter(|_| !neg)
                    .unwrap_or('\u{fffd}')
                    .to_string(),
                false,
            );
        }
        'q' => {
            let c = char::from_u32(abs as u32).filter(|_| !neg).unwrap_or('\u{fffd}');
            let q = go_quote(&c.to_string());
            return sp.pad(format!("'{}'", q[1..q.len() - 1].replace("\\\"", "\"")), false);
        }
        _ => return bad_verb(verb, v),
    };
    if let Some(p) = sp.prec {
        if p == 0 && abs == 0 {
            digits.clear();
        }
        while digits.len() < p {
            digits.insert(0, '0');
        }
    }
    let mut s = String::new();
    if neg {
        s.push('-');
    } else if sp.plus {
        s.push('+');
    } else if sp.space {
        s.push(' ');
    }
    if sp.sharp && !prefix.is_empty() && !(verb == 'o' && digits.starts_with('0')) {
        s.push_str(prefix);
    }
    s.push_str(&digits);
    sp.pad(s, true)
}

/// Shortest decimal digits and exponent of `f` (`d.ddd` x 10^exp).
fn float_digits(f: f64, prec: Option<usize>) -> (String, i32) {
    let s = match prec {
        Some(p) => format!("{:.*e}", p.saturating_sub(1), f.abs()),
        None => format!("{:e}", f.abs()),
    };
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    (digits, exp.parse().unwrap_or(0))
}

fn fmt_float_e(f: f64, prec: usize, upper: bool) -> String {
    if !f.is_finite() {
        return fmt_nonfinite(f);
    }
    let s = format!("{:.*e}", prec, f);
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let e = if upper { 'E' } else { 'e' };
    let sign = if exp < 0 { '-' } else { '+' };
    format!("{mant}{e}{sign}{:02}", exp.abs())
}

fn fmt_nonfinite(f: f64) -> String {
    if f.is_nan() {
        "NaN".into()
    } else if f > 0.0 {
        "+Inf".into()
    } else {
        "-Inf".into()
    }
}

/// `%g` / `%v` for floats, like `strconv.FormatFloat(f, 'g', prec, 64)`.
fn fmt_float_g(f: f64, prec: Option<usize>, upper: bool) -> String {
    if !f.is_finite() {
        return fmt_nonfinite(f);
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    let prec = prec.map(|p| p.max(1));
    let (mut digits, exp) = float_digits(f, prec);
    if prec.is_some() {
        while digits.len() > 1 && digits.ends_with('0') {
            digits.pop();
        }
    }
    let eprec: i32 = match prec {
        None => 6,
        Some(p) => p as i32,
    };
    let sign = if f < 0.0 { "-" } else { "" };
    if exp < -4 || exp >= eprec {
        let e = if upper { 'E' } else { 'e' };
        let (first, rest) = digits.split_at(1);
        let mant = if rest.is_empty() {
            first.to_string()
        } else {
            format!("{first}.{rest}")
        };
        let esign = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{mant}{e}{esign}{:02}", exp.abs());
    }
    let n = digits.len() as i32;
    let s = if exp < 0 {
        format!("0.{}{}", "0".repeat((-exp - 1) as usize), digits)
    } else if exp + 1 >= n {
        format!("{digits}{}", "0".repeat((exp + 1 - n) as usize))
    } else {
        let (a, b) = digits.split_at((exp + 1) as usize);
        format!("{a}.{b}")
    };
    format!("{sign}{s}")
}

/// Go's `dns.ClassToString` for the query class, empty if unknown.
pub fn class_name(c: DNSClass) -> String {
    match u16::from(c) {
        1 => "IN".into(),
        2 => "CS".into(),
        3 => "CH".into(),
        4 => "HS".into(),
        254 => "NONE".into(),
        255 => "ANY".into(),
        _ => String::new(),
    }
}

/// Go's `dns.TypeToString`, empty if unknown.
pub fn type_name(t: RecordType) -> String {
    match t {
        RecordType::Unknown(_) => String::new(),
        t => t.to_string(),
    }
}
