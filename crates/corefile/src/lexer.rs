//! Tokenizer for the Corefile (Caddyfile) dialect.
//!
//! The rules follow `github.com/coredns/caddy/caddyfile/lexer.go`:
//! tokens are separated by whitespace, `#` starts a comment when it begins a
//! token, `"..."` and `` `...` `` quote tokens (which may span lines), and
//! `\"` escapes a quote inside a double-quoted token.

use std::sync::Arc;

/// A single token with its source position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The token text, with quotes removed and environment variables expanded.
    pub text: String,
    /// The file the token came from. Tokens spliced in by `import` get a
    /// distinct file label, so "same line" checks never join lines across files.
    pub file: Arc<str>,
    /// 1-based line number of the start of the token.
    pub line: usize,
}

impl Token {
    pub fn new(text: impl Into<String>, file: Arc<str>, line: usize) -> Self {
        Self {
            text: text.into(),
            file,
            line,
        }
    }

    /// Line on which the token ends (quoted tokens may span lines).
    pub fn end_line(&self) -> usize {
        self.line + self.text.matches('\n').count()
    }

    /// True if `next` starts on the line where `self` ends, in the same file.
    pub fn continues_with(&self, next: &Token) -> bool {
        self.file == next.file && self.end_line() == next.line
    }
}

/// Split `input` into tokens. `file` is used for error messages.
#[allow(unused_assignments)] // the final flush! resets state that is not read again
pub fn tokenize(input: &str, file: &str) -> Vec<Token> {
    let file: Arc<str> = Arc::from(file);
    let mut tokens = Vec::new();
    let mut line = 1usize;

    let mut cur = String::new();
    let mut cur_line = 0usize;
    let mut in_token = false;
    // quote char currently open, if any
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut in_comment = false;
    // Line breaks inside a quoted token; caddy counts the token at its start line.
    let mut pending_newlines = 0usize;

    macro_rules! flush {
        () => {
            if in_token {
                tokens.push(Token::new(
                    expand_env(&std::mem::take(&mut cur)),
                    file.clone(),
                    cur_line,
                ));
                in_token = false;
                line += pending_newlines;
                pending_newlines = 0;
            }
        };
    }

    for ch in input.chars() {
        if in_comment {
            if ch == '\n' {
                in_comment = false;
                line += 1;
            }
            continue;
        }

        if let Some(q) = quote {
            if q == '"' && escaped {
                // only \" is an escape; any other backslash is kept verbatim
                if ch != '"' {
                    cur.push('\\');
                }
                escaped = false;
                if ch == '\n' {
                    pending_newlines += 1;
                }
                cur.push(ch);
                continue;
            }
            if q == '"' && ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == q {
                quote = None;
                continue;
            }
            if ch == '\n' {
                pending_newlines += 1;
            }
            cur.push(ch);
            continue;
        }

        if ch.is_whitespace() {
            flush!();
            if ch == '\n' {
                line += 1;
            }
            continue;
        }

        if !in_token {
            if ch == '#' {
                in_comment = true;
                continue;
            }
            in_token = true;
            cur_line = line;
        }

        if ch == '"' || ch == '`' {
            quote = Some(ch);
            continue;
        }

        cur.push(ch);
    }
    if escaped {
        cur.push('\\');
    }
    flush!();
    tokens
}

/// Replace `{$NAME}` and `{%NAME%}` with the value of the environment variable
/// `NAME` (empty if unset), as caddy's `replaceEnvVars` does.
pub fn expand_env(s: &str) -> String {
    if !s.contains('{') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        let replaced = if let Some(body) = after.strip_prefix("{$") {
            body.find('}').map(|end| (&body[..end], 2 + end + 1))
        } else if let Some(body) = after.strip_prefix("{%") {
            body.find("%}").map(|end| (&body[..end], 2 + end + 2))
        } else {
            None
        };
        match replaced {
            Some((name, consumed)) if !name.is_empty() => {
                out.push_str(&std::env::var(name).unwrap_or_default());
                rest = &after[consumed..];
            }
            _ => {
                out.push('{');
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(input: &str) -> Vec<(String, usize)> {
        tokenize(input, "Corefile")
            .into_iter()
            .map(|t| (t.text, t.line))
            .collect()
    }

    #[test]
    fn basic() {
        assert_eq!(
            texts(".:53 {\n  whoami # hi\n  log\n}\n"),
            vec![
                (".:53".into(), 1),
                ("{".into(), 1),
                ("whoami".into(), 2),
                ("log".into(), 3),
                ("}".into(), 4)
            ]
        );
    }

    #[test]
    fn quotes() {
        assert_eq!(
            texts("a \"b c\" `d \"e\"` \"f\\\"g\" \"x\ny\" z"),
            vec![
                ("a".into(), 1),
                ("b c".into(), 1),
                ("d \"e\"".into(), 1),
                ("f\"g".into(), 1),
                ("x\ny".into(), 1),
                ("z".into(), 2)
            ]
        );
    }

    #[test]
    fn comment_only_at_token_start() {
        assert_eq!(texts("a#b # c\nd"), vec![("a#b".into(), 1), ("d".into(), 2)]);
    }

    #[test]
    fn env() {
        // SAFETY: tests in this module don't read this variable concurrently.
        unsafe { std::env::set_var("KERNDNS_TEST_PORT", "1053") };
        assert_eq!(expand_env(".:{$KERNDNS_TEST_PORT}"), ".:1053");
        assert_eq!(expand_env("{%KERNDNS_TEST_PORT%}"), "1053");
        assert_eq!(expand_env("{$KERNDNS_TEST_UNSET_XYZ}x"), "x");
        assert_eq!(expand_env("{args[0]}"), "{args[0]}");
    }
}
