//! The shared parser of the listener-limit plugins `https`, `https3`,
//! `grpc_server` and `quic`. Each reads a block of integer options into
//! [`ListenerLimits`]; errors and messages follow CoreDNS's setup code.

use kerndns_core::plugin::ListenerLimits;
use kerndns_core::{Controller, SetupError};

/// One `NAME N` option of a listener plugin's block.
pub(crate) struct Opt {
    pub name: &'static str,
    /// `N` must be at least 1 (else at least 0).
    pub positive: bool,
    /// Upper bound, if any (`https`'s `max_streams` is a uint32).
    pub max: Option<u64>,
    pub slot: fn(&mut ListenerLimits) -> &mut Option<u64>,
}

/// Go's `strconv.Atoi` on a 64-bit platform, with its error text.
pub(crate) fn atoi(s: &str) -> Result<i64, String> {
    use std::num::IntErrorKind;
    // like Go, a leading sign is fine and nothing else is
    s.parse::<i64>().map_err(|e| {
        let why = match e.kind() {
            IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => "value out of range",
            _ => "invalid syntax",
        };
        format!("strconv.Atoi: parsing {s:?}: {why}")
    })
}

/// Parse the directive's first occurrence: no arguments, then a block of
/// `opts`. Like CoreDNS, a value set twice is an error, and later
/// occurrences of the directive in the same server block are not read.
pub(crate) fn parse(c: &mut Controller<'_>, opts: &[Opt]) -> Result<(), SetupError> {
    c.next();
    if !c.remaining_args().is_empty() {
        return Err(c.arg_err());
    }
    while c.next_block() {
        let key = c.val().to_string();
        let Some(opt) = opts.iter().find(|o| o.name == key) else {
            return Err(c.errf(format!("unknown property '{key}'")));
        };
        let args = c.remaining_args();
        if args.len() != 1 {
            return Err(c.arg_err());
        }
        let val = atoi(&args[0]).map_err(|e| c.errf(format!("invalid {key} value '{}': {e}", args[0])))?;
        if opt.positive && val <= 0 {
            return Err(c.errf(format!("{key} must be a positive integer: {val}")));
        }
        if val < 0 {
            return Err(c.errf(format!("{key} must be a non-negative integer: {val}")));
        }
        let val = val as u64;
        if let Some(max) = opt.max
            && val > max
        {
            return Err(c.errf(format!("{key} must not exceed {max}: {val}")));
        }
        let slot = (opt.slot)(&mut c.config.limits);
        if slot.is_some() {
            return Err(c.errf(format!("{key} already defined for this server block")));
        }
        *slot = Some(val);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::run_setup;
    use kerndns_core::PluginFactory;

    /// One row of an upstream setup table: the directive's text, then
    /// either the values of the checked fields afterwards or a substring of
    /// the error.
    pub(crate) type Case<'a> = (&'a str, Result<&'a [Option<u64>], &'a str>);

    pub(crate) type Field = fn(&ListenerLimits) -> Option<u64>;

    pub(crate) fn check(f: &dyn PluginFactory, fields: &[Field], cases: &[Case<'_>]) {
        for (i, (input, want)) in cases.iter().enumerate() {
            let (res, cfg) = run_setup(f, input);
            match (want, res) {
                (Ok(vals), Ok(())) => {
                    let got: Vec<Option<u64>> = fields.iter().map(|g| g(&cfg.limits)).collect();
                    assert_eq!(&got, vals, "case {i}: {input}");
                }
                (Err(sub), Err(e)) => assert!(e.contains(sub), "case {i}: {input}: {e:?} lacks {sub:?}"),
                (want, got) => panic!("case {i}: {input}: want {want:?}, got {got:?}"),
            }
        }
    }

    #[test]
    fn go_atoi() {
        assert_eq!(atoi("+5"), Ok(5));
        assert_eq!(atoi("-10"), Ok(-10));
        assert_eq!(
            atoi("abc").unwrap_err(),
            r#"strconv.Atoi: parsing "abc": invalid syntax"#
        );
        assert_eq!(
            atoi("99999999999999999999").unwrap_err(),
            r#"strconv.Atoi: parsing "99999999999999999999": value out of range"#
        );
    }
}
