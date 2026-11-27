//! Corefile parsing for KernDNS.
//!
//! The Corefile is CoreDNS's configuration format, a dialect of the Caddy v1
//! Caddyfile. This crate has no DNS dependencies: it turns text into
//! [`ServerBlock`]s and gives setup code a [`Dispenser`] over a directive's
//! tokens with the same semantics as `caddy.Controller`.

mod dispenser;
mod lexer;
mod parser;

pub use dispenser::Dispenser;
pub use lexer::{Token, expand_env, tokenize};
pub use parser::{Directive, ParseError, ServerBlock, parse, parse_file};
