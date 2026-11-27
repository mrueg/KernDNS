//! `on`: run a command when the server starts or shuts down. Port of
//! caddy's `onevent`, which CoreDNS includes as `on`.
//!
//! ```text
//! on startup|shutdown|certrenew COMMAND [ARGS...] [&]
//! ```
//!
//! `startup` runs when the server has started, and again after every
//! reload; `shutdown` when the process stops on SIGTERM or SIGINT (not on
//! reload). A trailing `&` runs the command in the background; otherwise
//! the server waits for it. The command's output goes to the server's.
//! `certrenew` is accepted but never fires (CoreDNS doesn't emit it).
//!
//! Unlike caddy, a reload replaces the hooks instead of adding the new
//! ones to the old ones (with the `reload` plugin, CoreDNS runs the
//! startup commands of every configuration it has loaded so far).

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use kerndns_core::{Controller, Event, PluginFactory, SetupError};

const NAME: &str = "on";

/// One hook (`hook.Config`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookConfig {
    pub id: String,
    pub event: Event,
    pub command: String,
    pub args: Vec<String>,
}

impl HookConfig {
    /// `Hook`: run the command if `event` is ours.
    pub fn run(&self, event: Event) -> Result<(), String> {
        if event != self.event {
            return Ok(());
        }
        let mut args = self.args.clone();
        let nonblock = args.last().is_some_and(|a| a == "&");
        if nonblock {
            args.pop();
        }
        let mut cmd = Command::new(&self.command);
        cmd.args(&args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let what = if nonblock { "Nonblocking" } else { "Blocking" };
        println!(
            "[INFO] {what} Command \"{} {}\" with ID {}",
            self.command,
            args.join(" "),
            self.id
        );
        let spawn_err = |e: std::io::Error| exec_error(&self.command, e);
        if nonblock {
            let mut child = cmd.spawn().map_err(spawn_err)?;
            // reap it when it exits
            std::thread::spawn(move || child.wait());
            return Ok(());
        }
        let status = cmd.status().map_err(spawn_err)?;
        if status.success() {
            Ok(())
        } else {
            Err(exit_error(status))
        }
    }
}

/// `exec.Command`'s errors for a command that can't be started.
fn exec_error(cmd: &str, e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::NotFound && !cmd.contains('/') {
        format!("exec: \"{cmd}\": executable file not found in $PATH")
    } else {
        let msg = match e.kind() {
            std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
            std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
            _ => e.to_string(),
        };
        format!("fork/exec {cmd}: {msg}")
    }
}

/// `*exec.ExitError`'s message.
fn exit_error(status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(c), _) => format!("exit status {c}"),
        (None, Some(s)) => format!("signal: {}", signal_name(s)),
        _ => status.to_string(),
    }
}

fn signal_name(s: i32) -> String {
    match s {
        1 => "hangup".into(),
        2 => "interrupt".into(),
        6 => "aborted".into(),
        9 => "killed".into(),
        11 => "segmentation fault".into(),
        13 => "broken pipe".into(),
        15 => "terminated".into(),
        n => format!("signal {n}"),
    }
}

/// `shlex.Split` (github.com/google/shlex, as caddy uses): words split on
/// whitespace, with single quotes, double quotes, backslash escapes and
/// `#` comments.
fn shlex_split(s: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '#' if !in_word => {
                // a comment runs to the end of the line
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some(n) => cur.push(n),
                    None => return Err("EOF found after escape character".into()),
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(n) => cur.push(n),
                        None => return Err("EOF found when expecting closing quote".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(n @ ('"' | '\\' | '$' | '`')) => cur.push(n),
                            Some('\n') => {}
                            Some(n) => {
                                cur.push('\\');
                                cur.push(n);
                            }
                            None => return Err("EOF found after escape character".into()),
                        },
                        Some(n) => cur.push(n),
                        None => return Err("EOF found when expecting closing quote".into()),
                    }
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

/// A unique hook ID (caddy uses a random UUID).
fn new_id() -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    use std::hash::{BuildHasher, Hasher};
    let mut bytes = [0u8; 16];
    for (i, chunk) in bytes.chunks_mut(8).enumerate() {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(N.fetch_add(1, Ordering::Relaxed));
        h.write_usize(i);
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    // version 4, RFC 4122 variant
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// `onParse`.
fn parse(c: &mut Controller<'_>) -> Result<Vec<HookConfig>, SetupError> {
    // caddy's onevent returns its errors without plugin.Error
    let raw = |e: SetupError| SetupError::new("", e.msg);
    let mut out = Vec::new();
    while c.next() {
        if !c.next_arg() {
            return Err(raw(c.arg_err()));
        }
        let event = match c.val().to_lowercase().as_str() {
            "startup" => Event::Startup,
            "shutdown" => Event::Shutdown,
            "certrenew" => Event::CertRenew,
            _ => {
                let msg = format!("Wrong event name or event not supported: '{}'", c.val());
                return Err(raw(c.errf(msg)));
            }
        };
        let line = c.remaining_args().join(" ");
        let parts = match shlex_split(&line) {
            Ok(p) => p,
            Err(e) => return Err(raw(c.errf(format!("error parsing command: {e}")))),
        };
        let Some((command, args)) = parts.split_first() else {
            return Err(raw(c.errf(format!("no command contained in '{line}'"))));
        };
        out.push(HookConfig {
            id: new_id(),
            event,
            command: command.clone(),
            args: args.to_vec(),
        });
    }
    Ok(out)
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        for h in parse(c)? {
            c.on_event(format!("on-{}", h.id), move |e| h.run(e));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn parse_on(input: &str) -> Result<Vec<HookConfig>, String> {
        with_controller(NAME, input, |c| parse(c).map_err(|e| e.to_string()))
    }

    // on_test.go: TestSetup
    #[test]
    fn setup() {
        assert!(!setup_ok(&Setup, "on"));
        assert!(!setup_ok(&Setup, "on xyz cmd arg"));
        assert!(setup_ok(&Setup, "on startup cmd arg"));
        assert!(setup_ok(&Setup, "on shutdown cmd arg &"));
        assert!(setup_ok(&Setup, "on certrenew cmd arg"));
        assert_eq!(
            setup_err(&Setup, "on xyz cmd arg"),
            "Corefile:2 - Error during parsing: Wrong event name or event not supported: 'xyz'"
        );
        assert_eq!(
            setup_err(&Setup, "on"),
            "Corefile:2 - Error during parsing: Wrong argument count or unexpected line ending after 'on'"
        );
        assert_eq!(
            setup_err(&Setup, "on startup"),
            "Corefile:2 - Error during parsing: no command contained in ''"
        );
        // one hook per line, registered once per block
        let (r, _) = run_setup(&Setup, "on startup a\non shutdown b");
        r.unwrap();
    }

    // on_test.go: TestCommandParse
    #[test]
    fn command_parse() {
        let cases = [
            ("on startup cmd arg1 arg2", Event::Startup, "cmd", vec!["arg1", "arg2"]),
            (
                "on shutdown cmd arg1 arg2 &",
                Event::Shutdown,
                "cmd",
                vec!["arg1", "arg2", "&"],
            ),
            (
                "on certrenew cmd arg1 arg2",
                Event::CertRenew,
                "cmd",
                vec!["arg1", "arg2"],
            ),
            ("on STARTUP cmd", Event::Startup, "cmd", vec![]),
            // quotes from the Corefile are gone; shlex splits the rest
            (
                "on startup sh -c \"echo 'a b'\"",
                Event::Startup,
                "sh",
                vec!["-c", "echo", "a b"],
            ),
        ];
        for (input, event, command, args) in cases {
            let h = parse_on(input).unwrap().remove(0);
            assert_eq!(h.event, event, "{input}");
            assert_eq!(h.command, command, "{input}");
            assert_eq!(h.args, args, "{input}");
        }
        assert!(parse_on("on").is_err());
        assert!(parse_on("on xyz cmd arg").is_err());
        let a = parse_on("on startup a").unwrap().remove(0).id;
        let b = parse_on("on startup a").unwrap().remove(0).id;
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
    }

    #[test]
    fn shlex() {
        assert_eq!(
            shlex_split("a 'b c' \"d\\\"e\" f\\ g #x").unwrap(),
            ["a", "b c", "d\"e", "f g"]
        );
        assert_eq!(
            shlex_split("a 'b").unwrap_err(),
            "EOF found when expecting closing quote"
        );
        assert!(shlex_split("").unwrap().is_empty());
    }

    fn hook(event: Event, command: &str, args: &[&str]) -> HookConfig {
        HookConfig {
            id: new_id(),
            event,
            command: command.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    // hook_test.go: TestHook
    #[test]
    fn hook_runs_commands() {
        let dir = std::env::temp_dir().join(format!("kerndns-on-test-{}", std::process::id()));
        let d = dir.to_str().unwrap().to_string();
        let _ = std::fs::remove_dir_all(&dir);

        // blocking: the directory exists when the hook returns
        hook(Event::Startup, "mkdir", &[&d]).run(Event::Startup).unwrap();
        assert!(dir.is_dir());
        std::fs::remove_dir(&dir).unwrap();

        // other events are ignored
        hook(Event::Shutdown, "mkdir", &[&d]).run(Event::Startup).unwrap();
        assert!(!dir.exists());

        // nonblocking
        hook(Event::Shutdown, "mkdir", &[&d, "&"]).run(Event::Shutdown).unwrap();
        hook(Event::Shutdown, "echo", &["&"]).run(Event::Shutdown).unwrap();
        for _ in 0..50 {
            if dir.is_dir() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(dir.is_dir());
        std::fs::remove_dir(&dir).unwrap();

        // errors
        let e = hook(Event::CertRenew, "kerndns-no-such-command-1234", &[])
            .run(Event::CertRenew)
            .unwrap_err();
        assert_eq!(
            e,
            "exec: \"kerndns-no-such-command-1234\": executable file not found in $PATH"
        );
        assert_eq!(
            hook(Event::Startup, "false", &[]).run(Event::Startup).unwrap_err(),
            "exit status 1"
        );
    }
}
