//! `view`: makes a server block handle only the requests its expressions
//! accept, so several blocks can serve the same zone differently. Port of
//! `plugin/view`.
//!
//! ```text
//! view NAME {
//!     expr EXPRESSION
//! }
//! ```
//!
//! Expressions are the expr-lang subset in [`crate::expr`].

use std::sync::Arc;

use kerndns_core::plugin::{Metadata, MetadataProvider, RequestFilter};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};

use crate::expr::{Program, Value};

struct Filter {
    name: String,
    progs: Vec<Program>,
}

impl RequestFilter for Filter {
    /// All expressions must evaluate to `true`; errors count as `false`.
    fn filter(&self, ctx: &Context, req: &Request) -> bool {
        self.progs
            .iter()
            .all(|p| matches!(p.run(ctx, req), Ok(Value::Bool(true))))
    }
}

impl MetadataProvider for Filter {
    fn metadata(&self, ctx: &mut Context, _: &Request) {
        ctx.metadata.insert("view/name".into(), self.name.clone());
    }
}

pub struct View {
    next: Next,
}

#[async_trait]
impl Handler for View {
    fn name(&self) -> &'static str {
        "view"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        next_or_failure("view", &self.next, ctx, w, req).await
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "view"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let err = |m: String| SetupError::new("view", m);
        let mut filter = None;
        while c.next() {
            if filter.is_some() {
                return Err(err("this plugin can only be used once per Server Block".into()));
            }
            let args = c.remaining_args();
            if args.len() != 1 {
                return Err(c.arg_err());
            }
            let mut f = Filter {
                name: args[0].clone(),
                progs: Vec::new(),
            };
            while c.next_block() {
                match c.val() {
                    "expr" => {
                        let src = c.remaining_args().join(" ");
                        f.progs.push(Program::compile(&src).map_err(err)?);
                    }
                    other => {
                        let msg = format!("unknown property '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
            filter = Some(f);
        }
        let Some(f) = filter else { return Err(c.arg_err()) };
        let f = Arc::new(f);
        c.config.view_name = Some(f.name.clone());
        c.config.filters.push(f.clone());
        Metadata::of(c.config).add_provider(f);
        c.add_plugin(|next| Arc::new(View { next }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "view example {\n expr name() == 'example.com.'\n}"));
        assert!(setup_ok(
            &Setup,
            "view example {\n expr incidr(client_ip(), '10.0.0.0/24')\n}"
        ));
        let (r, cfg) = run_setup(&Setup, "view example {\n expr name() == 'a.'\n expr name() == 'b.'\n}");
        assert!(r.is_ok());
        assert_eq!(cfg.view_name.as_deref(), Some("example"));
        assert_eq!(cfg.filters.len(), 1);
        assert!(!setup_err(&Setup, "view example {\n expr invalid expression\n}").is_empty());
        assert!(!setup_err(&Setup, "view").is_empty());
        assert!(setup_err(&Setup, "view a\nview b").contains("only be used once"));
    }
}
