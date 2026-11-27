//! Token dispenser with the same semantics as `caddyfile.Dispenser`, so
//! setup code can be ported from Go almost line by line:
//!
//! ```text
//! for c.Next() {            while c.next() {
//!     args := c.RemainingArgs()  let args = c.remaining_args();
//!     for c.NextBlock() {        while c.next_block() {
//!         switch c.Val() {           match c.val() { ... }
//! ```

use crate::lexer::Token;
use crate::parser::ParseError;

#[derive(Debug, Clone)]
pub struct Dispenser {
    tokens: Vec<Token>,
    cursor: isize,
    nesting: usize,
}

impl Dispenser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            cursor: -1,
            nesting: 0,
        }
    }

    fn len(&self) -> isize {
        self.tokens.len() as isize
    }

    /// Advance to the next token, regardless of line. False at the end.
    #[allow(clippy::should_implement_trait)] // named after caddy's Dispenser.Next
    pub fn next(&mut self) -> bool {
        if self.cursor < self.len() - 1 {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    /// Advance only if the next token is on the same line as the current one.
    pub fn next_arg(&mut self) -> bool {
        if self.cursor < 0 {
            self.cursor += 1;
            return true;
        }
        if self.cursor >= self.len() - 1 {
            return false;
        }
        let cur = &self.tokens[self.cursor as usize];
        let next = &self.tokens[self.cursor as usize + 1];
        if cur.continues_with(next) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    /// Advance only if the next token is on a different line.
    pub fn next_line(&mut self) -> bool {
        if self.cursor < 0 {
            self.cursor += 1;
            return true;
        }
        if self.cursor >= self.len() - 1 {
            return false;
        }
        let cur = &self.tokens[self.cursor as usize];
        let next = &self.tokens[self.cursor as usize + 1];
        if !cur.continues_with(next) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    /// Step through the lines of a `{ ... }` block that follows the current
    /// line. Returns false when the block ends (or there is none).
    pub fn next_block(&mut self) -> bool {
        if self.nesting > 0 {
            self.next();
            if self.val() == "}" {
                self.nesting -= 1;
                return false;
            }
            return true;
        }
        if !self.next_arg() {
            return false;
        }
        if self.val() != "{" {
            self.cursor -= 1;
            return false;
        }
        self.next();
        if self.val() == "}" {
            return false;
        }
        self.nesting += 1;
        true
    }

    /// Text of the current token, or "" if not positioned on a token.
    pub fn val(&self) -> &str {
        if self.cursor < 0 || self.cursor >= self.len() {
            ""
        } else {
            &self.tokens[self.cursor as usize].text
        }
    }

    /// Line of the current token (0 if none).
    pub fn line(&self) -> usize {
        self.token().map(|t| t.line).unwrap_or(0)
    }

    pub fn token(&self) -> Option<&Token> {
        if self.cursor < 0 || self.cursor >= self.len() {
            None
        } else {
            Some(&self.tokens[self.cursor as usize])
        }
    }

    /// Fill `out` with the next `out.len()` arguments on this line.
    /// Returns false (and leaves the cursor) if there are fewer.
    pub fn args(&mut self, out: &mut [String]) -> bool {
        let start = self.cursor;
        for slot in out.iter_mut() {
            if !self.next_arg() {
                self.cursor = start;
                return false;
            }
            *slot = self.val().to_string();
        }
        true
    }

    /// All remaining arguments on the current line, stopping before a `{`.
    pub fn remaining_args(&mut self) -> Vec<String> {
        let mut args = Vec::new();
        while self.next_arg() {
            if self.val() == "{" {
                self.cursor -= 1;
                break;
            }
            args.push(self.val().to_string());
        }
        args
    }

    /// Skip the rest of the current directive's block, if any.
    pub fn skip_block(&mut self) {
        while self.next_block() {}
    }

    // ---- error helpers with caddy's wording ----

    fn err_at(&self, msg: String) -> ParseError {
        match self.token() {
            Some(t) => ParseError::at(t, msg),
            None => ParseError {
                file: "Corefile".into(),
                line: 0,
                msg,
            },
        }
    }

    /// "Wrong argument count or unexpected line ending after 'X'"
    pub fn arg_err(&self) -> ParseError {
        if self.val() == "{" {
            return self.err_at("Unexpected token '{', expecting argument".into());
        }
        self.err_at(format!(
            "Wrong argument count or unexpected line ending after '{}'",
            self.val()
        ))
    }

    /// "Syntax error: Unexpected token 'X', expecting 'Y'"
    pub fn syntax_err(&self, expected: &str) -> ParseError {
        self.err_at(format!(
            "Syntax error: Unexpected token '{}', expecting '{}'",
            self.val(),
            expected
        ))
    }

    /// Error at the current token with a custom message.
    pub fn err(&self, msg: impl Into<String>) -> ParseError {
        self.err_at(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    fn dispenser(src: &str, directive: &str) -> Dispenser {
        let blocks = parse(src, "Corefile").unwrap();
        Dispenser::new(blocks[0].tokens_for(directive))
    }

    #[test]
    fn caddy_style_loop() {
        let mut c = dispenser(
            ".:53 {\n forward . 1.1.1.1 8.8.8.8 {\n  max_fails 3\n  force_tcp\n }\n forward example.org 9.9.9.9\n}",
            "forward",
        );
        let mut seen = Vec::new();
        while c.next() {
            assert_eq!(c.val(), "forward");
            let args = c.remaining_args();
            let mut block = Vec::new();
            while c.next_block() {
                let mut line = vec![c.val().to_string()];
                line.extend(c.remaining_args());
                block.push(line.join(" "));
            }
            seen.push((args, block));
        }
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, vec![".", "1.1.1.1", "8.8.8.8"]);
        assert_eq!(seen[0].1, vec!["max_fails 3", "force_tcp"]);
        assert_eq!(seen[1].0, vec!["example.org", "9.9.9.9"]);
        assert!(seen[1].1.is_empty());
    }

    #[test]
    fn arg_err_message() {
        let mut c = dispenser(".:53 {\n whoami extra\n}", "whoami");
        c.next();
        assert!(c.next_arg());
        let e = c.arg_err();
        assert_eq!(
            e.to_string(),
            "Corefile:2 - Error during parsing: Wrong argument count or unexpected line ending after 'extra'"
        );
    }

    #[test]
    fn empty_block() {
        let mut c = dispenser(".:53 {\n log {\n }\n}", "log");
        c.next();
        assert!(!c.next_block());
    }
}
