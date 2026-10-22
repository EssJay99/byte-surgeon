use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

const DEFAULT_CACHE_SIZE: usize = 100 * 1024 * 1024;

struct CacheEntry {
    data: Vec<u8>,
    generation: u64,
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub entries: usize,
    pub bytes_used: usize,
    pub max_bytes: usize,
}

struct CacheInner {
    entries: HashMap<u64, CacheEntry>,
    bytes_used: usize,
    generation: u64,
    hits: u64,
    misses: u64,
    evictions: u64,
}

#[derive(Clone)]
pub struct SectorCache {
    inner: Arc<RwLock<CacheInner>>,
    max_bytes: usize,
}

impl SectorCache {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CACHE_SIZE)
    }

    pub fn with_capacity(max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CacheInner {
                entries: HashMap::new(),
                bytes_used: 0,
                generation: 0,
                hits: 0,
                misses: 0,
                evictions: 0,
            })),
            max_bytes,
        }
    }

    pub fn read_cached(&self, sector_id: u64) -> Option<Vec<u8>> {
        let mut inner = self.inner.write();
        inner.generation += 1;
        let gen = inner.generation;
        if inner.entries.contains_key(&sector_id) {
            inner.hits += 1;
            let entry = inner.entries.get_mut(&sector_id).unwrap();
            entry.generation = gen;
            Some(entry.data.clone())
        } else {
            inner.misses += 1;
            None
        }
    }

    pub fn write_cache(&self, sector_id: u64, data: Vec<u8>) {
        let data_len = data.len();
        let mut inner = self.inner.write();

        if let Some(existing) = inner.entries.get(&sector_id) {
            inner.bytes_used -= existing.data.len();
        }

        inner.generation += 1;
        let gen = inner.generation;

        inner.entries.insert(sector_id, CacheEntry {
            data,
            generation: gen,
        });
        inner.bytes_used += data_len;

        while inner.bytes_used > self.max_bytes {
            if !Self::evict_one(&mut inner) {
                break;
            }
        }
    }

    fn evict_one(inner: &mut CacheInner) -> bool {
        if inner.entries.is_empty() {
            return false;
        }
        let oldest_key = inner
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.generation)
            .map(|(&key, _)| key);

        if let Some(key) = oldest_key {
            if let Some(removed) = inner.entries.remove(&key) {
                inner.bytes_used -= removed.data.len();
                inner.evictions += 1;
            }
            true
        } else {
            false
        }
    }

    pub fn clear_cache(&self) {
        let mut inner = self.inner.write();
        inner.entries.clear();
        inner.bytes_used = 0;
    }

    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.read();
        CacheStats {
            hits: inner.hits,
            misses: inner.misses,
            evictions: inner.evictions,
            entries: inner.entries.len(),
            bytes_used: inner.bytes_used,
            max_bytes: self.max_bytes,
        }
    }

    pub fn contains(&self, sector_id: u64) -> bool {
        let inner = self.inner.read();
        inner.entries.contains_key(&sector_id)
    }

    pub fn remove(&self, sector_id: u64) -> Option<Vec<u8>> {
        let mut inner = self.inner.write();
        inner.entries.remove(&sector_id).map(|entry| {
            inner.bytes_used -= entry.data.len();
            entry.data
        })
    }
}

impl Default for SectorCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_hit() {
        let cache = SectorCache::new();
        let data = vec![0xAA; 512];
        cache.write_cache(1, data.clone());

        let result = cache.read_cached(1);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), data);

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn test_cache_miss() {
        let cache = SectorCache::new();
        let result = cache.read_cached(999);
        assert!(result.is_none());

        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_cache_eviction() {
        let cache = SectorCache::with_capacity(1024);

        for i in 0..3 {
            cache.write_cache(i, vec![0xFF; 512]);
        }

        let stats = cache.stats();
        assert!(stats.bytes_used <= 1024);
        assert!(stats.evictions > 0);
        assert_eq!(stats.entries, 2);
    }

    #[test]
    fn test_lru_eviction_order() {
        let cache = SectorCache::with_capacity(1536);

        cache.write_cache(1, vec![0x01; 512]);
        cache.write_cache(2, vec![0x02; 512]);
        cache.write_cache(3, vec![0x03; 512]);

        let _ = cache.read_cached(1);

        cache.write_cache(4, vec![0x04; 512]);

        assert!(cache.contains(1));
        assert!(!cache.contains(2));
        assert!(cache.contains(3));
        assert!(cache.contains(4));
    }

    #[test]
    fn test_clear_cache() {
        let cache = SectorCache::new();
        cache.write_cache(1, vec![0xAA; 512]);
        cache.write_cache(2, vec![0xBB; 512]);

        cache.clear_cache();

        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.bytes_used, 0);
        assert!(cache.read_cached(1).is_none());
    }

    #[test]
    fn test_overwrite_existing() {
        let cache = SectorCache::new();
        cache.write_cache(1, vec![0xAA; 512]);
        cache.write_cache(1, vec![0xBB; 256]);

        let data = cache.read_cached(1).unwrap();
        assert_eq!(data, vec![0xBB; 256]);

        let stats = cache.stats();
        assert_eq!(stats.bytes_used, 256);
        assert_eq!(stats.entries, 1);
    }

    #[test]
    fn test_remove() {
        let cache = SectorCache::new();
        cache.write_cache(1, vec![0xAA; 512]);

        let removed = cache.remove(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap(), vec![0xAA; 512]);
        assert!(!cache.contains(1));

        let stats = cache.stats();
        assert_eq!(stats.bytes_used, 0);
    }

    #[test]
    fn test_thread_safety() {
        let cache = Arc::new(SectorCache::new());
        let mut handles = vec![];

        for i in 0..8 {
            let c = cache.clone();
            handles.push(std::thread::spawn(move || {
                for j in 0..100 {
                    let sid = i * 100 + j;
                    c.write_cache(sid, vec![sid as u8; 64]);
                    let _ = c.read_cached(sid);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let stats = cache.stats();
        assert_eq!(stats.hits, 800);
        assert!(stats.entries > 0);
    }
}
