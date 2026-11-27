//! A fixed-capacity, sharded hash map that evicts an arbitrary entry when a
//! shard is full, like CoreDNS's `plugin/pkg/cache`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const SHARDS: usize = 256;

pub struct Store<T> {
    shards: Vec<Mutex<HashMap<u64, Arc<T>>>>,
    shard_cap: usize,
}

impl<T> Store<T> {
    pub fn new(cap: usize) -> Self {
        let shard_cap = (cap / SHARDS).max(1);
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            shard_cap,
        }
    }

    fn shard(&self, key: u64) -> &Mutex<HashMap<u64, Arc<T>>> {
        &self.shards[(key & (SHARDS as u64 - 1)) as usize]
    }

    /// Insert; returns true if another entry was evicted to make room.
    pub fn add(&self, key: u64, v: Arc<T>) -> bool {
        let mut s = self.shard(key).lock().unwrap();
        let mut evicted = false;
        if !s.contains_key(&key)
            && s.len() >= self.shard_cap
            && let Some(&k) = s.keys().next()
        {
            s.remove(&k);
            evicted = true;
        }
        s.insert(key, v);
        evicted
    }

    pub fn get(&self, key: u64) -> Option<Arc<T>> {
        self.shard(key).lock().unwrap().get(&key).cloned()
    }

    pub fn remove(&self, key: u64) {
        self.shard(key).lock().unwrap().remove(&key);
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
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
            s.add(k * 256, Arc::new(k as u32)); // all in shard 0, capacity 1
        }
        assert_eq!(s.len(), 1);
        assert_eq!(*s.get(511 * 256).unwrap(), 511);
        assert!(!s.add(511 * 256, Arc::new(0)), "replacing doesn't evict");
    }
}
