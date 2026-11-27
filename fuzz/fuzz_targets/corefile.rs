//! Arbitrary Corefiles through the parser, the dispenser and every
//! plugin's setup (`config::load`), without binding sockets or running
//! startup hooks. Errors are fine; panics are bugs.
#![no_main]

use kerndns_corefile::{Dispenser, parse, tokenize};
use kerndns_fuzz::{escapes_sandbox, fixtures, registry, runtime};
use kerndns_server::config::{Options, load};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = fixtures();
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    if escapes_sandbox(input) {
        return;
    }
    let path = dir.join("Corefile").display().to_string();

    // the lexer and the dispenser on their own
    let mut d = Dispenser::new(tokenize(input, "Corefile"));
    let mut steps = 0;
    while d.next() && steps < 10_000 {
        let _ = d.val();
        d.next_block();
        let _ = d.remaining_args();
        d.next_line();
        d.next_arg();
        steps += 1;
    }

    if parse(input, &path).is_err() {
        return;
    }
    let _guard = runtime().enter();
    let _ = load(input, &path, registry(), &Options { dns_port: "0".into() });
});
