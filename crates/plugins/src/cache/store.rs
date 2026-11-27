//! A fixed-capacity, sharded hash map that evicts an arbitrary entry when a
//! shard is full, like CoreDNS's `plugin/pkg/cache`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const SHARDS: usize = 256;
/// Smallest shard capacity, like Go's `max(size/shardSize, 4)`.
const MIN_SHARD_CAP: usize = 4;

pub struct Store<T> {
    shards: Vec<Mutex<HashMap<u64, Arc<T>>>>,
    shard_cap: usize,
    /// Number of entries, kept next to the shards so [`Store::len`] (read
    /// after every insert for the `cache_entries` gauge) doesn't have to
    /// lock all of them.
    len: AtomicUsize,
}

impl<T> Store<T> {
    pub fn new(cap: usize) -> Self {
        let shard_cap = (cap / SHARDS).max(MIN_SHARD_CAP);
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            shard_cap,
            len: AtomicUsize::new(0),
        }
    }

    fn shard(&self, key: u64) -> &Mutex<HashMap<u64, Arc<T>>> {
        &self.shards[(key & (SHARDS as u64 - 1)) as usize]
    }

    /// Insert; returns true if another entry was evicted to make room.
    pub fn add(&self, key: u64, v: Arc<T>) -> bool {
        let mut s = self.shard(key).lock().unwrap();
        let mut evicted = false;
        if s.len() >= self.shard_cap
            && !s.contains_key(&key)
            && let Some(&k) = s.keys().next()
        {
            // whatever the map yields first, like Go's map iteration
            s.remove(&k);
            evicted = true;
        }
        if s.insert(key, v).is_none() && !evicted {
            self.len.fetch_add(1, Ordering::Relaxed);
        }
        evicted
    }

    pub fn get(&self, key: u64) -> Option<Arc<T>> {
        self.shard(key).lock().unwrap().get(&key).cloned()
    }

    pub fn remove(&self, key: u64) {
        if self.shard(key).lock().unwrap().remove(&key).is_some() {
            self.len.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Keep only the entries for which `f` is true, like `Cache.Walk`
    /// deleting items.
    pub fn retain(&self, mut f: impl FnMut(&T) -> bool) {
        for s in &self.shards {
            let mut m = s.lock().unwrap();
            let before = m.len();
            m.retain(|_, v| f(v));
            self.len.fetch_sub(before - m.len(), Ordering::Relaxed);
        }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_and_eviction() {
        let s: Store<u32> = Store::new(256);
        for k in 0..512u64 {
            s.add(k * 256, Arc::new(k as u32)); // all in shard 0, capacity 4 (the minimum)
        }
        assert_eq!(s.len(), 4);
        assert_eq!(*s.get(511 * 256).unwrap(), 511);
        assert!(!s.add(511 * 256, Arc::new(0)), "replacing doesn't evict");
        assert_eq!(s.len(), 4);
        s.remove(511 * 256);
        s.remove(511 * 256);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn capacity_per_shard() {
        let s: Store<u32> = Store::new(256 * 10);
        let mut evictions = 0;
        for k in 0..100_000u64 {
            evictions += usize::from(s.add(k.wrapping_mul(0x9E37_79B9_7F4A_7C15), Arc::new(0)));
        }
        assert_eq!(s.len(), 2560);
        assert_eq!(evictions, 100_000 - 2560);
    }

    #[test]
    fn retain_keeps_count() {
        let s: Store<u32> = Store::new(256 * 10);
        for k in 0..1000u64 {
            s.add(k, Arc::new(k as u32));
        }
        s.retain(|v| v % 2 == 0);
        assert_eq!(s.len(), 500);
    }
}
