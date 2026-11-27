//! Turns tokens into server blocks, following `coredns/caddy/caddyfile/parse.go`.
//!
//! Supported: server block keys (comma or space separated), blocks with or
//! without braces, snippets `(name) { ... }`, `import <snippet|glob> [args...]`
//! with `{args[N]}` / `{args[:]}` replacement, and nested directive blocks.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::lexer::{Token, tokenize};

const MAX_IMPORT_DEPTH: usize = 32;

/// A parse error with the position of the offending token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{file}:{line} - Error during parsing: {msg}")]
pub struct ParseError {
    pub file: String,
    pub line: usize,
    pub msg: String,
}

impl ParseError {
    pub fn at(tok: &Token, msg: impl Into<String>) -> Self {
        Self {
            file: tok.file.to_string(),
            line: tok.line,
            msg: msg.into(),
        }
    }

    fn eof(file: &str, msg: impl Into<String>) -> Self {
        Self {
            file: file.to_string(),
            line: 0,
            msg: msg.into(),
        }
    }
}

/// One server block: `keys { directives }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerBlock {
    /// The keys as written, e.g. `.:53`, `dns://example.org`.
    pub keys: Vec<String>,
    /// The first key token, for error positions.
    pub key_token: Token,
    /// Directives in the order they appear.
    pub directives: Vec<Directive>,
}

impl ServerBlock {
    /// All tokens of every occurrence of directive `name`, concatenated, the
    /// way caddy hands them to a setup function.
    pub fn tokens_for(&self, name: &str) -> Vec<Token> {
        self.directives
            .iter()
            .filter(|d| d.name == name)
            .flat_map(|d| d.tokens.iter().cloned())
            .collect()
    }
}

/// One directive occurrence, including its name token and any block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub name: String,
    pub tokens: Vec<Token>,
}

/// Parse a Corefile from a string. `file` is the name used in error messages
/// and the directory of `file` is the base for relative `import` paths.
pub fn parse(input: &str, file: &str) -> Result<Vec<ServerBlock>, ParseError> {
    let base = Path::new(file).parent().map(Path::to_path_buf).unwrap_or_default();
    let mut ctx = ImportCtx {
        snippets: HashMap::new(),
        base,
        counter: 0,
    };
    let tokens = tokenize(input, file);
    let tokens = ctx.extract_snippets(tokens)?;
    let tokens = ctx.expand(tokens, 0)?;
    parse_blocks(&tokens, file)
}

/// Parse a Corefile from disk.
pub fn parse_file(path: impl AsRef<Path>) -> Result<Vec<ServerBlock>, ParseError> {
    let path = path.as_ref();
    let input = std::fs::read_to_string(path).map_err(|e| ParseError {
        file: path.display().to_string(),
        line: 0,
        msg: format!("could not read file: {e}"),
    })?;
    parse(&input, &path.display().to_string())
}

struct ImportCtx {
    snippets: HashMap<String, Vec<Token>>,
    base: PathBuf,
    counter: usize,
}

impl ImportCtx {
    /// Remove top-level `(name) { ... }` definitions and remember them.
    fn extract_snippets(&mut self, tokens: Vec<Token>) -> Result<Vec<Token>, ParseError> {
        let mut out = Vec::with_capacity(tokens.len());
        let mut depth = 0usize;
        let mut i = 0;
        while i < tokens.len() {
            let t = &tokens[i];
            let is_def = depth == 0
                && t.text.len() > 2
                && t.text.starts_with('(')
                && t.text.ends_with(')')
                && tokens.get(i + 1).is_some_and(|n| n.text == "{");
            if is_def {
                let name = t.text[1..t.text.len() - 1].to_string();
                if self.snippets.contains_key(&name) {
                    return Err(ParseError::at(
                        t,
                        format!("redeclaration of previously declared snippet {name}"),
                    ));
                }
                let (body, next) = block_body(&tokens, i + 1)?;
                self.snippets.insert(name, body.to_vec());
                i = next;
                continue;
            }
            match t.text.as_str() {
                "{" => depth += 1,
                "}" => depth = depth.saturating_sub(1),
                _ => {}
            }
            out.push(t.clone());
            i += 1;
        }
        Ok(out)
    }

    /// Expand every `import` that starts a line.
    fn expand(&mut self, tokens: Vec<Token>, depth: usize) -> Result<Vec<Token>, ParseError> {
        if depth > MAX_IMPORT_DEPTH {
            let line = tokens.first().map(|t| t.line).unwrap_or(0);
            let file = tokens.first().map(|t| t.file.to_string()).unwrap_or_default();
            return Err(ParseError {
                file,
                line,
                msg: "maximum import depth exceeded (import cycle?)".into(),
            });
        }
        let mut out = Vec::with_capacity(tokens.len());
        let mut i = 0;
        while i < tokens.len() {
            let t = &tokens[i];
            let starts_line = i == 0 || !tokens[i - 1].continues_with(t) || tokens[i - 1].text == "{";
            if t.text != "import" || !starts_line {
                out.push(t.clone());
                i += 1;
                continue;
            }
            let mut args = Vec::new();
            let mut j = i + 1;
            while j < tokens.len() && tokens[j - 1].continues_with(&tokens[j]) && tokens[j].text != "}" {
                args.push(tokens[j].text.clone());
                j += 1;
            }
            if args.is_empty() {
                return Err(ParseError::at(
                    t,
                    "Wrong argument count or unexpected line ending after 'import'",
                ));
            }
            let imported = self.import(t, &args)?;
            let imported = self.expand(imported, depth + 1)?;
            out.extend(imported);
            i = j;
        }
        Ok(out)
    }

    fn import(&mut self, at: &Token, args: &[String]) -> Result<Vec<Token>, ParseError> {
        self.counter += 1;
        if let Some(body) = self.snippets.get(&args[0]) {
            let label: Arc<str> = Arc::from(format!("{} (snippet {} #{})", at.file, args[0], self.counter));
            return Ok(replace_args(body, &args[1..], &label));
        }

        let pattern = &args[0];
        let full = if Path::new(pattern).is_absolute() {
            PathBuf::from(pattern)
        } else {
            self.base.join(pattern)
        };
        let full_str = full.to_string_lossy().to_string();
        let is_glob = pattern.contains(['*', '?', '[']);
        let mut paths: Vec<PathBuf> = if is_glob {
            glob::glob(&full_str)
                .map_err(|e| ParseError::at(at, format!("Failed to use import pattern {pattern}: {e}")))?
                .filter_map(Result::ok)
                .collect()
        } else {
            vec![full.clone()]
        };
        paths.sort();
        if !is_glob && !full.exists() {
            return Err(ParseError::at(
                at,
                format!("Could not import {pattern}: no such file or directory"),
            ));
        }

        let mut out = Vec::new();
        for path in paths {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| ParseError::at(at, format!("Could not read imported file {}: {e}", path.display())))?;
            let toks = tokenize(&content, &path.display().to_string());
            let toks = self.extract_snippets(toks)?;
            out.extend(replace_args(&toks, &args[1..], &Arc::from(path.display().to_string())));
        }
        Ok(out)
    }
}

/// Substitute `{args[N]}` and `{args[:]}` in snippet/file tokens and relabel
/// the tokens with `file` so they never join lines with the importing file.
fn replace_args(tokens: &[Token], args: &[String], file: &Arc<str>) -> Vec<Token> {
    let mut out = Vec::with_capacity(tokens.len());
    for t in tokens {
        if t.text == "{args[:]}" {
            for a in args {
                out.push(Token::new(a.clone(), file.clone(), t.line));
            }
            continue;
        }
        let mut text = t.text.clone();
        if text.contains("{args[") {
            for (n, a) in args.iter().enumerate() {
                text = text.replace(&format!("{{args[{n}]}}"), a);
            }
        }
        out.push(Token::new(text, file.clone(), t.line));
    }
    out
}

/// Given `tokens[open] == "{"`, return the tokens strictly inside the block
/// and the index after the matching `}`.
fn block_body(tokens: &[Token], open: usize) -> Result<(&[Token], usize), ParseError> {
    let mut depth = 0usize;
    for (k, t) in tokens.iter().enumerate().skip(open) {
        match t.text.as_str() {
            "{" => depth += 1,
            "}" => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&tokens[open + 1..k], k + 1));
                }
            }
            _ => {}
        }
    }
    Err(ParseError::at(&tokens[open], "Unexpected EOF: missing closing '}'"))
}

fn parse_blocks(tokens: &[Token], file: &str) -> Result<Vec<ServerBlock>, ParseError> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let key_token = tokens[i].clone();
        if key_token.text == "{" || key_token.text == "}" {
            return Err(ParseError::at(
                &key_token,
                format!("Unexpected '{}', expecting server block keys", key_token.text),
            ));
        }

        // Keys: tokens on one line, or continued after a trailing comma.
        let mut keys = Vec::new();
        loop {
            let t = &tokens[i];
            keys.extend(
                t.text
                    .split(',')
                    .map(str::trim)
                    .filter(|k| !k.is_empty())
                    .map(String::from),
            );
            let more = t.text.ends_with(',');
            i += 1;
            match tokens.get(i) {
                None => break,
                Some(n) if n.text == "{" => break,
                Some(n) if more || t.continues_with(n) => continue,
                Some(_) => break,
            }
        }

        let body: &[Token] = if tokens.get(i).is_some_and(|t| t.text == "{") {
            let (body, next) = block_body(tokens, i)?;
            i = next;
            body
        } else {
            // A block without braces runs to the end of the input.
            let body = &tokens[i..];
            i = tokens.len();
            body
        };

        blocks.push(ServerBlock {
            keys,
            key_token,
            directives: parse_directives(body)?,
        });
    }
    if blocks.is_empty() {
        return Err(ParseError::eof(file, "no server blocks found"));
    }
    Ok(blocks)
}

fn parse_directives(body: &[Token]) -> Result<Vec<Directive>, ParseError> {
    let mut out = Vec::new();
    let mut j = 0;
    while j < body.len() {
        let name = &body[j];
        if name.text == "{" || name.text == "}" {
            return Err(ParseError::at(name, format!("Unexpected '{}'", name.text)));
        }
        let start = j;
        j += 1;
        while j < body.len() && body[j - 1].continues_with(&body[j]) {
            if body[j].text == "{" {
                let (_, next) = block_body(body, j)?;
                j = next;
                break;
            }
            j += 1;
        }
        out.push(Directive {
            name: name.text.clone(),
            tokens: body[start..j].to_vec(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(d: &Directive) -> Vec<&str> {
        d.tokens.iter().map(|t| t.text.as_str()).collect()
    }

    #[test]
    fn single_block() {
        let b = parse(
            ".:53 {\n  whoami\n  forward . 8.8.8.8 {\n    max_fails 3\n  }\n  log\n}\n",
            "Corefile",
        )
        .unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].keys, vec![".:53"]);
        let names: Vec<_> = b[0].directives.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["whoami", "forward", "log"]);
        assert_eq!(
            texts(&b[0].directives[1]),
            vec!["forward", ".", "8.8.8.8", "{", "max_fails", "3", "}"]
        );
    }

    #[test]
    fn multiple_keys_and_blocks() {
        let b = parse(
            "example.org:1053, example.net:1053 {\n whoami\n}\n. a.b {\n log\n}",
            "Corefile",
        )
        .unwrap();
        assert_eq!(b[0].keys, vec!["example.org:1053", "example.net:1053"]);
        assert_eq!(b[1].keys, vec![".", "a.b"]);
    }

    #[test]
    fn keys_continued_with_comma_on_next_line() {
        let b = parse("a.,\nb. {\n whoami\n}", "Corefile").unwrap();
        assert_eq!(b[0].keys, vec!["a.", "b."]);
    }

    #[test]
    fn no_braces() {
        let b = parse(".:53\nwhoami\nlog", "Corefile").unwrap();
        assert_eq!(b[0].directives.len(), 2);
    }

    #[test]
    fn snippets_with_args() {
        let b = parse(
            "(common) {\n  log\n  errors {args[0]}\n}\n.:53 {\n  import common stdout\n  whoami\n}",
            "Corefile",
        )
        .unwrap();
        assert_eq!(b.len(), 1);
        let names: Vec<_> = b[0].directives.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["log", "errors", "whoami"]);
        assert_eq!(texts(&b[0].directives[1]), vec!["errors", "stdout"]);
    }

    #[test]
    fn snippet_does_not_join_lines() {
        // the snippet token on line 2 must not be read as an argument of the
        // directive that follows the import on line 2 of the main file
        let b = parse("(s) {\n  log\n}\n.:53 {\n  import s\n  whoami\n}", "Corefile").unwrap();
        assert_eq!(texts(&b[0].directives[0]), vec!["log"]);
        assert_eq!(texts(&b[0].directives[1]), vec!["whoami"]);
    }

    #[test]
    fn missing_brace() {
        let e = parse(".:53 {\n whoami\n", "Corefile").unwrap_err();
        assert_eq!(e.line, 1);
        assert!(e.to_string().starts_with("Corefile:1 - Error during parsing:"));
    }

    #[test]
    fn file_import() {
        let dir = std::env::temp_dir().join(format!("kerndns-import-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("extra.conf"), "example.org {\n whoami\n}\n").unwrap();
        let main = dir.join("Corefile");
        std::fs::write(&main, ".:53 {\n log\n}\nimport extra.conf\n").unwrap();
        let b = parse_file(&main).unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b[1].keys, vec!["example.org"]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
