//! `header`: sets or clears header flags on queries and responses. Port of
//! `plugin/header`.
//!
//! ```text
//! header {
//!     query|response set|clear FLAG...
//! }
//! ```
//!
//! FLAG is `aa`, `ra` or `rd`.

use std::sync::Arc;

use kerndns_core::proto::op::{Message, Metadata};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flag {
    Aa,
    Ra,
    Rd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    flag: Flag,
    state: bool,
}

fn new_rules(action: &str, args: &[String]) -> Result<Vec<Rule>, String> {
    if action.is_empty() {
        return Err("no flag action provided".into());
    }
    if args.is_empty() {
        return Err("invalid length for flags, at least one should be provided".into());
    }
    let state = match action.to_ascii_lowercase().as_str() {
        "set" => true,
        "clear" => false,
        a => return Err(format!("unknown flag action={a}, should be set or clear")),
    };
    args.iter()
        .map(|a| {
            let flag = match a.to_ascii_lowercase().as_str() {
                "aa" => Flag::Aa,
                "ra" => Flag::Ra,
                "rd" => Flag::Rd,
                f => return Err(format!("unknown/unsupported flag={f}")),
            };
            Ok(Rule { flag, state })
        })
        .collect()
}

fn apply(h: &mut Metadata, rules: &[Rule]) {
    for r in rules {
        match r.flag {
            Flag::Aa => h.authoritative = r.state,
            Flag::Ra => h.recursion_available = r.state,
            Flag::Rd => h.recursion_desired = r.state,
        }
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "header"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let err = |m: String| SetupError::new("header", format!("setting up rule: {m}"));
        let (mut query, mut response) = (Vec::new(), Vec::new());
        while c.next() {
            while c.next_block() {
                let selector = c.val().to_ascii_lowercase();
                if selector != "query" && selector != "response" {
                    return Err(SetupError::new(
                        "header",
                        format!("setting up rule: invalid selector={selector} should be query or response"),
                    ));
                }
                let action = if c.next_arg() {
                    c.val().to_string()
                } else {
                    String::new()
                };
                let args = c.remaining_args();
                let rules = new_rules(&action, &args).map_err(err)?;
                if selector == "response" {
                    response.extend(rules);
                } else {
                    query.extend(rules);
                }
            }
            if !query.is_empty() || !response.is_empty() {
                break;
            }
        }
        if query.is_empty() && response.is_empty() {
            return Err(c.arg_err());
        }
        let (query, response) = (Arc::new(query), Arc::new(response));
        c.add_plugin(move |next| {
            Arc::new(Header {
                query: query.clone(),
                response: response.clone(),
                next,
            })
        });
        Ok(())
    }
}

pub struct Header {
    query: Arc<Vec<Rule>>,
    response: Arc<Vec<Rule>>,
    next: Next,
}

struct RuleWriter<'a> {
    inner: &'a mut dyn ResponseWriter,
    rules: &'a [Rule],
}

#[async_trait]
impl ResponseWriter for RuleWriter<'_> {
    async fn write_msg(&mut self, mut m: Message) -> std::io::Result<()> {
        apply(&mut m.metadata, self.rules);
        self.inner.write_msg(m).await
    }
}

#[async_trait]
impl Handler for Header {
    fn name(&self) -> &'static str {
        "header"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let mut rw = RuleWriter {
            inner: w,
            rules: &self.response,
        };
        if self.query.is_empty() {
            return next_or_failure("header", &self.next, ctx, &mut rw, req).await;
        }
        let mut r = req.clone();
        apply(&mut r.msg.metadata, &self.query);
        next_or_failure("header", &self.next, ctx, &mut rw, &r).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::whoami::Whoami;
    use kerndns_core::proto::rr::RecordType;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "header {\n response set ra aa\n query clear rd\n}"));
        assert!(setup_err(&Setup, "header").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "header {\n foo set aa\n}").contains("invalid selector=foo"));
        assert!(setup_err(&Setup, "header {\n response toggle aa\n}").contains("unknown flag action=toggle"));
        assert!(setup_err(&Setup, "header {\n response set ad\n}").contains("unknown/unsupported flag=ad"));
        assert!(setup_err(&Setup, "header {\n response set\n}").contains("at least one"));
    }

    #[tokio::test]
    async fn rewrites_flags() {
        let h = Header {
            query: Arc::new(vec![Rule {
                flag: Flag::Rd,
                state: false,
            }]),
            response: Arc::new(vec![
                Rule {
                    flag: Flag::Ra,
                    state: true,
                },
                Rule {
                    flag: Flag::Aa,
                    state: false,
                },
            ]),
            next: Some(Arc::new(Whoami)),
        };
        let (_, w) = serve(&h, &query("example.org.", RecordType::A, "10.0.0.1:1")).await;
        let m = w.msg().unwrap();
        assert!(m.metadata.recursion_available);
        assert!(!m.metadata.authoritative);
        assert!(
            !m.metadata.recursion_desired,
            "query rd cleared before whoami copied it"
        );
    }
}
