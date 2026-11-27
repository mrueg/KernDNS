//! Response writers.

use std::io;

use async_trait::async_trait;
use hickory_proto::op::{Message, ResponseCode};

/// Where a handler sends its answer, like `dns.ResponseWriter`.
///
/// Plugins that need to see or change a response (cache, log, rewrite) wrap
/// the writer they were given and pass the wrapper down the chain.
#[async_trait]
pub trait ResponseWriter: Send {
    async fn write_msg(&mut self, msg: Message) -> io::Result<()>;
}

/// Keeps every written message. The server hands one of these to the chain
/// and sends what it collected; tests use it to inspect answers.
#[derive(Debug, Default)]
pub struct CaptureWriter {
    pub msgs: Vec<Message>,
}

impl CaptureWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn written(&self) -> bool {
        !self.msgs.is_empty()
    }

    /// The last message written, if any.
    pub fn msg(&self) -> Option<&Message> {
        self.msgs.last()
    }
}

#[async_trait]
impl ResponseWriter for CaptureWriter {
    async fn write_msg(&mut self, msg: Message) -> io::Result<()> {
        self.msgs.push(msg);
        Ok(())
    }
}

/// Wraps a writer and remembers what went through it, like CoreDNS's
/// `dnstest.Recorder`: the response code, the wire size and the message.
pub struct Recorder<'a> {
    inner: &'a mut dyn ResponseWriter,
    pub rcode: Option<ResponseCode>,
    pub len: usize,
    pub msg: Option<Message>,
}

impl<'a> Recorder<'a> {
    pub fn new(inner: &'a mut dyn ResponseWriter) -> Self {
        Self {
            inner,
            rcode: None,
            len: 0,
            msg: None,
        }
    }
}

#[async_trait]
impl ResponseWriter for Recorder<'_> {
    async fn write_msg(&mut self, msg: Message) -> io::Result<()> {
        self.rcode = Some(msg.metadata.response_code);
        self.len += crate::wire::to_wire(&msg).map(|v| v.len()).unwrap_or(0);
        self.msg = Some(msg.clone());
        self.inner.write_msg(msg).await
    }
}
