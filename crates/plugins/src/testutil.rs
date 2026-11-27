//! Helpers for plugin unit tests.

use kerndns_core::corefile::{Dispenser, parse};
use kerndns_core::proto::op::{Message, MessageType, OpCode, Query};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_core::{
    BlockConfig, CaptureWriter, Context, Controller, Handler, HandlerResult, Hooks, PluginFactory, Protocol, Request,
    ZoneAddr,
};

/// Run setup for `directive` inside `.:53 { ... }`. The directive starts on
/// line 2 of the generated Corefile.
pub fn run_setup(f: &dyn PluginFactory, directive: &str) -> (Result<(), String>, BlockConfig) {
    let blocks = parse(&format!(".:53 {{\n{directive}\n}}"), "Corefile").expect("parses");
    let mut cfg = BlockConfig::new(ZoneAddr::parse(".:53", "53").unwrap());
    let mut hooks = Hooks::default();
    let name = f.name();
    let res = {
        let mut c = Controller::new(
            name,
            Dispenser::new(blocks[0].tokens_for(name)),
            &mut cfg,
            &mut hooks,
            ".".into(),
        );
        f.setup(&mut c).map_err(|e| e.to_string())
    };
    (res, cfg)
}

/// Run `f` with a controller for `name`'s tokens in `directive` (inside
/// `.:53 { ... }`, starting on line 2), like `caddy.NewTestController`.
pub fn with_controller<T>(name: &'static str, directive: &str, f: impl FnOnce(&mut Controller<'_>) -> T) -> T {
    let blocks = parse(&format!(".:53 {{\n{directive}\n}}"), "Corefile").expect("parses");
    let mut cfg = BlockConfig::new(ZoneAddr::parse(".:53", "53").unwrap());
    let mut hooks = Hooks::default();
    let mut c = Controller::new(
        name,
        Dispenser::new(blocks[0].tokens_for(name)),
        &mut cfg,
        &mut hooks,
        ".".into(),
    );
    f(&mut c)
}

pub fn setup_ok(f: &dyn PluginFactory, directive: &str) -> bool {
    run_setup(f, directive).0.is_ok()
}

pub fn setup_err(f: &dyn PluginFactory, directive: &str) -> String {
    run_setup(f, directive).0.expect_err("setup should fail")
}

pub fn query(name: &str, qtype: RecordType, remote: &str) -> Request {
    let mut m = Message::new(1, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
    Request::new(
        m,
        "127.0.0.1:53".parse().unwrap(),
        remote.parse().unwrap(),
        Protocol::Udp,
    )
}

pub async fn serve(h: &dyn Handler, req: &Request) -> (HandlerResult, CaptureWriter) {
    let mut w = CaptureWriter::new();
    let mut ctx = Context::new(".", "dns://:53");
    let rc = h.serve_dns(&mut ctx, &mut w, req).await;
    (rc, w)
}

/// A next handler that writes the message `f` builds for the request.
pub struct Reply<F>(pub F);

#[kerndns_core::async_trait]
impl<F> Handler for Reply<F>
where
    F: Fn(&Request) -> kerndns_core::proto::op::Message + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "reply"
    }

    async fn serve_dns(
        &self,
        _: &mut Context,
        w: &mut dyn kerndns_core::ResponseWriter,
        req: &Request,
    ) -> HandlerResult {
        let _ = w.write_msg((self.0)(req)).await;
        Ok(kerndns_core::proto::op::ResponseCode::NoError)
    }
}

/// `Some(Arc<Reply>)`, ready to be a plugin's `next`.
pub fn reply<F>(f: F) -> kerndns_core::Next
where
    F: Fn(&Request) -> kerndns_core::proto::op::Message + Send + Sync + 'static,
{
    Some(std::sync::Arc::new(Reply(f)))
}
