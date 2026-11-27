//! Zone transfer wiring between plugins in one server block, like
//! CoreDNS's `transfer.Transferer` interface: zone sources (`file`, ...)
//! register here, the `transfer` plugin serves AXFR/IXFR from them, and
//! sources ask it to send NOTIFYs when their zones change.

use std::sync::{Arc, Mutex, Weak};

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
///
/// The registry holds its sources, and the sources hold the zones; a zone
/// that sends NOTIFYs keeps a [`WeakTransferRegistry`], and the notifier
/// (the `transfer` plugin, which holds the registry) is kept weakly, so
/// none of them form a reference cycle that would leak every zone on each
/// reload.
#[derive(Clone, Default)]
pub struct TransferRegistry {
    sources: Arc<Mutex<Vec<Arc<dyn Transferer>>>>,
    notifier: Arc<Mutex<Option<Weak<dyn Notifier>>>>,
}

/// A handle on a [`TransferRegistry`] that doesn't keep it alive, for zone
/// sources (which the registry holds) to send NOTIFYs.
#[derive(Clone, Default)]
pub struct WeakTransferRegistry {
    sources: Weak<Mutex<Vec<Arc<dyn Transferer>>>>,
    notifier: Weak<Mutex<Option<Weak<dyn Notifier>>>>,
}

impl WeakTransferRegistry {
    fn upgrade(&self) -> Option<TransferRegistry> {
        Some(TransferRegistry {
            sources: self.sources.upgrade()?,
            notifier: self.notifier.upgrade()?,
        })
    }

    /// [`TransferRegistry::notify`], if the registry still exists.
    pub fn notify(&self, zone: &str) {
        if let Some(r) = self.upgrade() {
            r.notify(zone);
        }
    }

    /// [`TransferRegistry::notify_wait`], if the registry still exists.
    pub async fn notify_wait(&self, zone: &str) -> bool {
        match self.upgrade() {
            Some(r) => r.notify_wait(zone).await,
            None => false,
        }
    }

    /// [`TransferRegistry::has_notifier`], if the registry still exists.
    pub fn has_notifier(&self) -> bool {
        self.upgrade().is_some_and(|r| r.has_notifier())
    }
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

    /// A handle that doesn't keep the registry alive.
    pub fn downgrade(&self) -> WeakTransferRegistry {
        WeakTransferRegistry {
            sources: Arc::downgrade(&self.sources),
            notifier: Arc::downgrade(&self.notifier),
        }
    }

    /// Set the notifier, held weakly: its owner keeps it alive.
    pub fn set_notifier(&self, n: &Arc<dyn Notifier>) {
        *self.notifier.lock().unwrap() = Some(Arc::downgrade(n));
    }

    fn notifier(&self) -> Option<Arc<dyn Notifier>> {
        self.notifier.lock().unwrap().as_ref().and_then(Weak::upgrade)
    }

    /// Send NOTIFYs for `zone` if `transfer` is configured (no-op otherwise).
    /// Send NOTIFYs for `zone` in the background.
    pub fn notify(&self, zone: &str) {
        let n = self.notifier();
        let (Some(n), Ok(handle)) = (n, tokio::runtime::Handle::try_current()) else {
            return;
        };
        let zone = zone.to_string();
        handle.spawn(async move { n.notify(&zone).await });
    }

    /// Send NOTIFYs for `zone` and wait for them; false without a notifier.
    pub async fn notify_wait(&self, zone: &str) -> bool {
        match self.notifier() {
            Some(n) => {
                n.notify(zone).await;
                true
            }
            None => false,
        }
    }

    pub fn has_notifier(&self) -> bool {
        self.notifier().is_some()
    }
}
