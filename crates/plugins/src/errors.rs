//! `errors`: logs errors returned by the plugins after it. Port of
//! `plugin/errors`, including `consolidate DURATION REGEXP [LEVEL] [show_first]`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kerndns_core::duration::{format_duration, parse_duration};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};
use regex::Regex;

/// Hard limit on the length of a `consolidate` pattern (`maxRegexpLen`).
const MAX_REGEXP_LEN: usize = 10000;

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "errors"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut patterns = Vec::new();
        let mut seen = false;
        while c.next() {
            if seen {
                return Err(SetupError::new(
                    "errors",
                    "this plugin can only be used once per Server Block",
                ));
            }
            seen = true;
            let args = c.remaining_args();
            match args.as_slice() {
                [] => {}
                [a] if a == "stdout" => {}
                [a] => return Err(c.errf(format!("invalid log file: {a}"))),
                _ => return Err(c.arg_err()),
            }
            while c.next_block() {
                match c.val() {
                    // KernDNS has no panic recovery to print a stack trace for.
                    "stacktrace" => {}
                    "consolidate" => patterns.push(parse_consolidate(c)?),
                    v => return Err(c.syntax_err(&format!("Unknown field {v}"))),
                }
            }
        }
        let inner = Arc::new(Inner {
            patterns,
            stopped: AtomicBool::new(false),
            #[cfg(test)]
            sink: None,
        });
        if !inner.patterns.is_empty() {
            let stop = inner.clone();
            c.on_shutdown(move || stop.stop());
        }
        c.add_plugin(move |next| {
            Arc::new(Errors {
                next,
                inner: inner.clone(),
            })
        });
        Ok(())
    }
}

fn parse_consolidate(c: &mut Controller<'_>) -> Result<Pattern, SetupError> {
    let args = c.remaining_args();
    if !(2..=4).contains(&args.len()) {
        return Err(c.arg_err());
    }
    let period = parse_duration(&args[0]).map_err(|e| c.errf(e))?;
    if args[1].len() > MAX_REGEXP_LEN {
        return Err(c.errf(format!("regex pattern too long: {} > {MAX_REGEXP_LEN}", args[1].len())));
    }
    let re = Regex::new(&args[1]).map_err(|e| c.errf(regexp_error(&e)))?;
    let mut level = None;
    let mut show_first = false;
    for a in &args[2..] {
        if let Some(l) = Level::parse(a) {
            if level.is_some() {
                return Err(c.errf("multiple log levels specified in consolidate"));
            }
            if show_first {
                return Err(c.errf("log level must come before show_first in consolidate"));
            }
            level = Some(l);
        } else if a == "show_first" {
            show_first = true;
        } else {
            return Err(c.errf(format!("unknown option in consolidate: {a}")));
        }
    }
    Ok(Pattern {
        period,
        re,
        level: level.unwrap_or(Level::Error),
        show_first,
        state: Mutex::new(PatternState::default()),
    })
}

/// Go's regexp error text (`error parsing regexp: ...`) for a regex error.
fn regexp_error(e: &regex::Error) -> String {
    let s = e.to_string();
    let detail = s
        .lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix("error: "))
        .unwrap_or(s.trim());
    format!("error parsing regexp: {detail}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Warning,
    Error,
    Info,
    Debug,
}

impl Level {
    fn parse(s: &str) -> Option<Level> {
        Some(match s {
            "warning" => Level::Warning,
            "error" => Level::Error,
            "info" => Level::Info,
            "debug" => Level::Debug,
            _ => return None,
        })
    }
}

#[derive(Default)]
struct PatternState {
    count: u32,
    timer: Option<tokio::task::JoinHandle<()>>,
}

/// One `consolidate` option (`pattern` in Go).
struct Pattern {
    period: Duration,
    re: Regex,
    level: Level,
    show_first: bool,
    state: Mutex<PatternState>,
}

/// The patterns, shared by the handler, the timers and the shutdown hook.
struct Inner {
    patterns: Vec<Pattern>,
    stopped: AtomicBool,
    /// Captures log lines instead of printing them (tests).
    #[cfg(test)]
    sink: Option<Arc<Mutex<Vec<String>>>>,
}

impl Inner {
    fn log(&self, level: Level, msg: std::fmt::Arguments<'_>) {
        #[cfg(test)]
        if let Some(sink) = &self.sink {
            let prefix = match level {
                Level::Warning => "WARNING",
                Level::Error => "ERROR",
                Level::Info => "INFO",
                Level::Debug => "DEBUG",
            };
            sink.lock().unwrap().push(format!("[{prefix}] plugin/errors: {msg}"));
            return;
        }
        match level {
            Level::Warning => kerndns_core::warning!(plugin = "errors", "{msg}"),
            Level::Error => kerndns_core::error!(plugin = "errors", "{msg}"),
            Level::Info => kerndns_core::info!(plugin = "errors", "{msg}"),
            Level::Debug => kerndns_core::debug!(plugin = "errors", "{msg}"),
        }
    }

    /// Print the summary of pattern `i` and reset its count (`logPattern`).
    fn log_pattern(&self, i: usize) {
        let p = &self.patterns[i];
        let cnt = std::mem::take(&mut p.state.lock().unwrap().count);
        if cnt == 0 {
            return;
        }
        if cnt > 1 || !p.show_first {
            self.log(
                p.level,
                format_args!(
                    "{cnt} errors like '{}' occurred in last {}",
                    p.re.as_str(),
                    format_duration(p.period)
                ),
            );
        }
    }

    /// Count an error of pattern `i` (`consolidateError`). False means the
    /// caller logs it: after shutdown, or the first one with `show_first`.
    fn consolidate(self: &Arc<Self>, i: usize) -> bool {
        if self.stopped.load(Ordering::Acquire) {
            return false;
        }
        let p = &self.patterns[i];
        let mut st = p.state.lock().unwrap();
        st.count += 1;
        if st.count > 1 {
            return true;
        }
        let me = self.clone();
        let period = p.period;
        st.timer = Some(tokio::spawn(async move {
            tokio::time::sleep(period).await;
            me.log_pattern(i);
        }));
        !p.show_first
    }

    /// Print the pending summaries and stop consolidating (shutdown or reload).
    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        for (i, p) in self.patterns.iter().enumerate() {
            let pending = p.state.lock().unwrap().timer.take();
            if let Some(t) = pending
                && !t.is_finished()
            {
                t.abort();
                self.log_pattern(i);
            }
        }
    }
}

pub struct Errors {
    next: Next,
    inner: Arc<Inner>,
}

#[async_trait]
impl Handler for Errors {
    fn name(&self) -> &'static str {
        "errors"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let res = next_or_failure("errors", &self.next, ctx, w, req).await;
        if let Err(e) = &res {
            let msg = e.to_string();
            let mut level = Level::Error;
            if let Some(i) = self.inner.patterns.iter().position(|p| p.re.is_match(&msg)) {
                if self.inner.consolidate(i) {
                    return res;
                }
                level = self.inner.patterns[i].level;
            }
            self.inner.log(
                level,
                format_args!("{} {} {}: {}", u16::from(e.rcode), req.name(), req.qtype(), msg),
            );
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::op::ResponseCode;
    use kerndns_core::proto::rr::RecordType;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "errors"));
        assert!(setup_ok(&Setup, "errors stdout"));
        assert!(setup_ok(&Setup, "errors {\n stacktrace\n}"));
        assert!(setup_err(&Setup, "errors a b").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "errors visible").contains("invalid log file: visible"));
        assert!(setup_err(&Setup, "errors { log visible }").contains("Unknown field log"));
        assert!(setup_err(&Setup, "errors\nerrors").contains("only be used once"));
    }

    /// `TestErrorsParse`'s consolidate rows and `TestErrorsParseLargeRegex`.
    #[test]
    fn setup_consolidate() {
        for (input, ok) in [
            ("errors {\n consolidate\n}", false),
            ("errors {\n consolidate 1m\n}", false),
            ("errors {\n consolidate 1m .* extra\n}", false),
            ("errors {\n consolidate abc .*\n}", false),
            ("errors {\n consolidate 1 .*\n}", false),
            ("errors {\n consolidate 1m ())\n}", false),
            ("errors {\n stacktrace\n consolidate 1m ^exact$\n}", true),
            ("errors {\n consolidate 1m error\n}", true),
            ("errors {\n consolidate 1m \"format error\"\n}", true),
            ("errors {\n consolidate 1m error1\n consolidate 5s error2\n}", true),
            ("errors {\n consolidate 1m error show_first\n}", true),
            ("errors {\n consolidate 1m error warning show_first\n}", true),
            ("errors {\n consolidate 1m error invalid_option\n}", false),
            ("errors {\n consolidate 1m error warning error\n}", false),
            ("errors {\n consolidate 1m error info debug\n}", false),
            ("errors {\n consolidate 1m error show_first warning\n}", false),
            ("errors {\n consolidate 1m error show_first info\n}", false),
        ] {
            assert_eq!(setup_ok(&Setup, input), ok, "{input}");
        }
        assert!(setup_err(&Setup, "errors {\n consolidate 1m ())\n}").contains("error parsing regexp"));
        assert!(setup_err(&Setup, "errors {\n consolidate 1 .*\n}").contains("invalid duration"));
        let big = format!("errors {{\n consolidate 1m {}\n}}", "a".repeat(MAX_REGEXP_LEN + 1));
        assert!(setup_err(&Setup, &big).contains("too long"));
    }

    fn inner(level: Level, show_first: bool, sink: &Arc<Mutex<Vec<String>>>) -> Arc<Inner> {
        Arc::new(Inner {
            patterns: vec![Pattern {
                period: Duration::from_secs(2),
                re: Regex::new("^error.*!$").unwrap(),
                level,
                show_first,
                state: Mutex::new(PatternState::default()),
            }],
            stopped: AtomicBool::new(false),
            sink: Some(sink.clone()),
        })
    }

    #[tokio::test]
    async fn passes_errors_through() {
        let h = Errors {
            next: None,
            inner: Arc::new(Inner {
                patterns: Vec::new(),
                stopped: AtomicBool::new(false),
                sink: None,
            }),
        };
        let (res, _) = serve(&h, &query("example.org.", RecordType::A, "10.0.0.1:1")).await;
        let e = res.unwrap_err();
        assert_eq!(e.rcode, ResponseCode::ServFail);
        assert_eq!(e.to_string(), "plugin/errors: no next plugin found");
    }

    /// `TestLogPattern`.
    #[test]
    fn log_pattern_levels() {
        for (level, want) in [
            (Level::Error, "[ERROR]"),
            (Level::Warning, "[WARNING]"),
            (Level::Info, "[INFO]"),
            (Level::Debug, "[DEBUG]"),
        ] {
            let sink = Arc::default();
            let h = inner(level, false, &sink);
            h.patterns[0].state.lock().unwrap().count = 4;
            h.log_pattern(0);
            assert_eq!(
                *sink.lock().unwrap(),
                [format!(
                    "{want} plugin/errors: 4 errors like '^error.*!$' occurred in last 2s"
                )]
            );
        }
    }

    /// `TestInc` and `TestStop`.
    #[tokio::test]
    async fn consolidate_and_stop() {
        let sink = Arc::default();
        let h = inner(Level::Error, false, &sink);
        h.stopped.store(true, Ordering::Release);
        assert!(!h.consolidate(0));
        h.stopped.store(false, Ordering::Release);
        assert!(h.consolidate(0));
        assert!(h.consolidate(0));
        assert!(h.consolidate(0));
        assert_eq!(h.patterns[0].state.lock().unwrap().count, 3);
        h.stop();
        assert_eq!(h.patterns[0].state.lock().unwrap().count, 0);
        assert!(h.stopped.load(Ordering::Acquire));
        assert_eq!(
            *sink.lock().unwrap(),
            ["[ERROR] plugin/errors: 3 errors like '^error.*!$' occurred in last 2s"]
        );
    }

    /// `TestShowFirst`.
    #[tokio::test]
    async fn show_first() {
        for (n, summary) in [(3, true), (1, false)] {
            let sink = Arc::default();
            let h = inner(Level::Error, true, &sink);
            for i in 0..n {
                assert_eq!(h.consolidate(0), i != 0);
            }
            h.log_pattern(0);
            let got = sink.lock().unwrap().clone();
            if summary {
                assert_eq!(
                    got,
                    [format!(
                        "[ERROR] plugin/errors: {n} errors like '^error.*!$' occurred in last 2s"
                    )]
                );
            } else {
                assert!(got.is_empty(), "{got:?}");
            }
        }
    }

    /// Errors matching a pattern are counted and summarized once the period
    /// ends; the first is logged right away with `show_first`.
    #[tokio::test]
    async fn handler_consolidates() {
        let sink: Arc<Mutex<Vec<String>>> = Arc::default();
        let mut i = inner(Level::Warning, true, &sink);
        let p = &mut Arc::get_mut(&mut i).unwrap().patterns[0];
        p.re = Regex::new("no next plugin").unwrap();
        p.period = Duration::from_millis(100);
        let h = Errors { next: None, inner: i };
        let req = query("example.org.", RecordType::A, "10.0.0.1:1");
        for _ in 0..3 {
            assert!(serve(&h, &req).await.0.is_err());
        }
        assert_eq!(
            *sink.lock().unwrap(),
            ["[WARNING] plugin/errors: 2 example.org. A: plugin/errors: no next plugin found"]
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            sink.lock().unwrap()[1..],
            ["[WARNING] plugin/errors: 3 errors like 'no next plugin' occurred in last 100ms"]
        );
    }
}
