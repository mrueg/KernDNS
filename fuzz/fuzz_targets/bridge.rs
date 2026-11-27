//! The Rust side of the Go bridge, without loading the Go library:
//! arbitrary callback sequences (responses written by the Go plugin, calls
//! to next with an arbitrary message, results with arbitrary rcodes and
//! error text) through the same code a real request uses, plus the plugin
//! list parser and the directive rendering that crosses the other way
//! (rendered tokens must lex back to the same tokens).
#![no_main]

use std::ffi::CString;
use std::net::SocketAddr;
use std::sync::OnceLock;

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_core::{CaptureWriter, Context, Next, Protocol, Request};
use kerndns_corefile::tokenize;
use kerndns_fuzz::{fixtures, registry, runtime};
use kerndns_go_bridge::fuzz::{Callback, caddy_lex, plugin_list, replay};
use kerndns_go_bridge::render_tokens;
use kerndns_server::config::{Options, load};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Cb {
    Write(Vec<u8>),
    Next(u64, Vec<u8>),
    Done(i32, Option<Vec<u8>>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    callbacks: Vec<Cb>,
    plugin_list: String,
    corefile: String,
}

/// The rest of the chain a Go plugin's next would call: rewrite, cache and
/// a template answering everything.
fn next() -> &'static Next {
    static N: OnceLock<Next> = OnceLock::new();
    N.get_or_init(|| {
        let corefile = "example.org {\n rewrite name exact a.example.org b.example.org\n cache 30\n template ANY ANY {\n  answer \"{{ .Name }} 60 IN TXT ok\"\n }\n}\n";
        let path = fixtures().join("Corefile").display().to_string();
        let _guard = runtime().enter();
        let plan = load(corefile, &path, registry(), &Options::default()).expect("next chain loads");
        plan.listeners[0].zones[0].1.chain.clone()
    })
}

fn request() -> Request {
    let mut m = Message::new(7, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii("a.example.org.").unwrap(), RecordType::A));
    let a: SocketAddr = "127.0.0.1:53".parse().unwrap();
    Request::new(m, a, a, Protocol::Udp)
}

fuzz_target!(|input: Input| {
    let next = next();
    let errs: Vec<Option<CString>> = input
        .callbacks
        .iter()
        .map(|c| match c {
            Cb::Done(_, Some(e)) => {
                Some(CString::new(e.iter().copied().filter(|&b| b != 0).collect::<Vec<_>>()).unwrap())
            }
            _ => None,
        })
        .collect();
    let cbs: Vec<Callback<'_>> = input
        .callbacks
        .iter()
        .zip(&errs)
        .map(|(c, e)| match c {
            Cb::Write(b) => Callback::Write(b),
            Cb::Next(t, b) => Callback::Next(*t, b),
            Cb::Done(code, _) => Callback::Done(*code, e.as_deref()),
        })
        .collect();
    let req = request();
    runtime().block_on(async {
        let mut ctx = Context::new("example.org.", "dns://:53");
        let mut w = CaptureWriter::new();
        let (_res, nexts) = replay(next, &mut ctx, &mut w, &req, &cbs).await;
        // what next_done hands back: length-prefixed messages, each parsable
        for (_, _, out) in nexts {
            let mut rest = &out[..];
            while let [a, b, tail @ ..] = rest {
                let n = u16::from_be_bytes([*a, *b]) as usize;
                assert!(tail.len() >= n, "truncated message for next_done");
                Message::from_vec(&tail[..n]).expect("next_done message parses");
                rest = &tail[n..];
            }
            assert!(rest.is_empty());
        }
    });

    let _ = plugin_list(&input.plugin_list);

    // the Go side lexes render_tokens' output with caddy's lexer
    let tokens = tokenize(&input.corefile, "Corefile");
    if tokens.iter().all(|t| representable(&t.text)) {
        let rendered = render_tokens(&tokens);
        let texts: Vec<String> = tokens.iter().map(|t| t.text.clone()).collect();
        assert_eq!(texts, caddy_lex(&rendered), "rendered: {rendered:?}");
    }
});

/// Whether caddy's lexer can produce `text` at all: not if it needs quotes
/// and has an odd run of backslashes before a quote or at its end.
fn representable(text: &str) -> bool {
    let needs_quotes = text.is_empty() || text.starts_with('"') || text.chars().any(|c| c.is_whitespace() || c == '#');
    if !needs_quotes {
        return true;
    }
    let mut run = 0;
    for c in text.chars() {
        match c {
            '\\' => run += 1,
            '"' if run % 2 == 1 => return false,
            _ => run = 0,
        }
    }
    run % 2 == 0
}
