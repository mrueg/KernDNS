//! Zone transfer wiring between plugins in one server block, like
//! CoreDNS's `transfer.Transferer` interface: zone sources (`file`, ...)
//! register here, the `transfer` plugin serves AXFR/IXFR from them, and
//! sources ask it to send NOTIFYs when their zones change.

use std::sync::{Arc, Mutex};

use hickory_proto::rr::Record;

use crate::plugin::BlockConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    /// This source doesn't have the zone; try the next one.
    NotAuthoritative,
    Other(String),
}

/// A plugin that can hand out a whole zone.
pub trait Transferer: Send + Sync {
    /// The zone's records in transfer order, in batches: first the apex
    /// (SOA first), then the rest, then the SOA again. For an IXFR whose
    /// `serial` equals the zone's, only the SOA (the "up to date" answer).
    fn transfer(&self, zone: &str, serial: u32) -> Result<Vec<Vec<Record>>, TransferError>;
}

/// Sends NOTIFYs for a zone (implemented by the `transfer` plugin).
#[async_trait::async_trait]
pub trait Notifier: Send + Sync {
    /// Send the NOTIFYs and wait until every target answered or gave up.
    async fn notify(&self, zone: &str);
}

/// The block's transfer sources and notifier.
#[derive(Clone, Default)]
pub struct TransferRegistry {
    sources: Arc<Mutex<Vec<Arc<dyn Transferer>>>>,
    notifier: Arc<Mutex<Option<Arc<dyn Notifier>>>>,
}

impl TransferRegistry {
    /// The registry of this block (created on first use).
    pub fn of(cfg: &mut BlockConfig) -> TransferRegistry {
        if cfg.extensions.get::<TransferRegistry>().is_none() {
            cfg.extensions.insert(TransferRegistry::default());
        }
        cfg.extensions
            .get::<TransferRegistry>()
            .cloned()
            .expect("inserted above")
    }

    pub fn add_source(&self, t: Arc<dyn Transferer>) {
        self.sources.lock().unwrap().push(t);
    }

    pub fn sources(&self) -> Vec<Arc<dyn Transferer>> {
        self.sources.lock().unwrap().clone()
    }

    pub fn set_notifier(&self, n: Arc<dyn Notifier>) {
        *self.notifier.lock().unwrap() = Some(n);
    }

    /// Send NOTIFYs for `zone` if `transfer` is configured (no-op otherwise).
    /// Send NOTIFYs for `zone` in the background.
    pub fn notify(&self, zone: &str) {
        let n = self.notifier.lock().unwrap().clone();
        let (Some(n), Ok(handle)) = (n, tokio::runtime::Handle::try_current()) else {
            return;
        };
        let zone = zone.to_string();
        handle.spawn(async move { n.notify(&zone).await });
    }

    /// Send NOTIFYs for `zone` and wait for them; false without a notifier.
    pub async fn notify_wait(&self, zone: &str) -> bool {
        let n = self.notifier.lock().unwrap().clone();
        match n {
            Some(n) => {
                n.notify(zone).await;
                true
            }
            None => false,
        }
    }

    pub fn has_notifier(&self) -> bool {
        self.notifier.lock().unwrap().is_some()
    }
}
