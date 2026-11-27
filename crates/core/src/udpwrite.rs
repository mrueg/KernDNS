//! Decorated UDP writes, like CoreDNS's `Config.UDPDecorateWriterFunc`
//! (used by `shed`): a plugin takes over how responses leave a UDP socket.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::UdpSocket;

/// One UDP socket's response path.
pub trait UdpWriter: Send + Sync {
    /// Send (or queue) an encoded response to `dst`; never blocks.
    fn write(&self, data: Vec<u8>, dst: SocketAddr);

    /// Whether the socket is saturated: queries arriving now are dropped
    /// before the chain runs (by the plugin that installed the writer).
    fn full(&self) -> bool;

    /// Count a query dropped because the socket was [`full`](Self::full).
    fn drop_query(&self);
}

/// The background work of a decorated socket (e.g. its single writer),
/// run by the listener until the socket closes.
pub type WriterTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Installs a [`UdpWriter`] on each UDP socket of a listener.
pub trait UdpDecorator: Send + Sync {
    /// Called once per UDP socket, before it serves its first packet.
    /// `server` is the listener's label (`dns://:53`).
    fn decorate(&self, server: &str, sock: Arc<UdpSocket>) -> (Arc<dyn UdpWriter>, WriterTask);
}
