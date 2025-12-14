use crate::host::bic;
use crate::memory::Buffer;
use alloc::vec::Vec;

/// Get a value from storage
pub fn get(key: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let result = bic::storage_kv_get(key.as_ptr() as i32, key.len() as i32);
        let value_ptr = (result >> 32) as i32;
        let value_len = (result & 0xFFFFFFFF) as usize;

        if value_len == 0 {
            return None;
        }

        let mut value = Vec::with_capacity(value_len);
        value.set_len(value_len);
        core::ptr::copy_nonoverlapping(value_ptr as *const u8, value.as_mut_ptr(), value_len);

        Some(value)
    }
}

/// Get a value from storage as a string
pub fn get_string(key: &[u8]) -> Option<alloc::string::String> {
    get(key).and_then(|v| alloc::string::String::from_utf8(v).ok())
}

/// Get a value from storage as u64
pub fn get_u64(key: &[u8]) -> Option<u64> {
    get(key).and_then(|v| {
        if v.len() >= 8 {
            Some(u64::from_le_bytes(v[..8].try_into().ok()?))
        } else {
            core::str::from_utf8(&v).ok()?.parse().ok()
        }
    })
}

/// Get a value from storage as i64
pub fn get_i64(key: &[u8]) -> Option<i64> {
    get(key).and_then(|v| {
        if v.len() >= 8 {
            Some(i64::from_le_bytes(v[..8].try_into().ok()?))
        } else {
            core::str::from_utf8(&v).ok()?.parse().ok()
        }
    })
}

/// Get a value from storage as i128
pub fn get_i128(key: &[u8]) -> Option<i128> {
    get(key).and_then(|v| {
        if v.len() >= 16 {
            Some(i128::from_le_bytes(v[..16].try_into().ok()?))
        } else {
            core::str::from_utf8(&v).ok()?.parse().ok()
        }
    })
}

/// Put a value in storage
pub fn put(key: &[u8], value: &[u8]) -> bool {
    unsafe {
        bic::storage_kv_put(
            key.as_ptr() as i32,
            key.len() as i32,
            value.as_ptr() as i32,
            value.len() as i32,
        ) == 0
    }
}

/// Put a string value in storage
pub fn put_string(key: &[u8], value: &str) -> bool {
    put(key, value.as_bytes())
}

/// Put a u64 value in storage
pub fn put_u64(key: &[u8], value: u64) -> bool {
    put(key, &value.to_le_bytes())
}

/// Put an i64 value in storage
pub fn put_i64(key: &[u8], value: i64) -> bool {
    put(key, &value.to_le_bytes())
}

/// Put an i128 value in storage
pub fn put_i128(key: &[u8], value: i128) -> bool {
    put(key, &value.to_le_bytes())
}

/// Delete a key from storage
pub fn delete(key: &[u8]) -> bool {
    unsafe { bic::storage_kv_delete(key.as_ptr() as i32, key.len() as i32) == 0 }
}

/// Check if a key exists in storage
pub fn exists(key: &[u8]) -> bool {
    unsafe { bic::storage_kv_exists(key.as_ptr() as i32, key.len() as i32) == 1 }
}

/// Atomically increment a value in storage
pub fn increment(key: &[u8], delta: i64) -> i64 {
    unsafe { bic::storage_kv_increment(key.as_ptr() as i32, key.len() as i32, delta) }
}

/// Atomically decrement a value in storage
pub fn decrement(key: &[u8], delta: i64) -> i64 {
    increment(key, -delta)
}

/// A typed storage map with a key prefix
pub struct StorageMap<K, V> {
    prefix: &'static [u8],
    _marker: core::marker::PhantomData<(K, V)>,
}

impl<K, V> StorageMap<K, V> {
    pub const fn new(prefix: &'static [u8]) -> Self {
        Self { prefix, _marker: core::marker::PhantomData }
    }

    fn build_key(&self, key: &[u8]) -> Vec<u8> {
        let mut full_key = Vec::with_capacity(self.prefix.len() + key.len());
        full_key.extend_from_slice(self.prefix);
        full_key.extend_from_slice(key);
        full_key
    }
}

impl<K: AsRef<[u8]>> StorageMap<K, Vec<u8>> {
    pub fn get(&self, key: &K) -> Option<Vec<u8>> {
        get(&self.build_key(key.as_ref()))
    }

    pub fn insert(&self, key: &K, value: &[u8]) -> bool {
        put(&self.build_key(key.as_ref()), value)
    }

    pub fn remove(&self, key: &K) -> bool {
        delete(&self.build_key(key.as_ref()))
    }

    pub fn contains(&self, key: &K) -> bool {
        exists(&self.build_key(key.as_ref()))
    }
}

impl<K: AsRef<[u8]>> StorageMap<K, u64> {
    pub fn get(&self, key: &K) -> Option<u64> {
        get_u64(&self.build_key(key.as_ref()))
    }

    pub fn insert(&self, key: &K, value: u64) -> bool {
        put_u64(&self.build_key(key.as_ref()), value)
    }

    pub fn increment(&self, key: &K, delta: i64) -> i64 {
        increment(&self.build_key(key.as_ref()), delta)
    }

    pub fn remove(&self, key: &K) -> bool {
        delete(&self.build_key(key.as_ref()))
    }

    pub fn contains(&self, key: &K) -> bool {
        exists(&self.build_key(key.as_ref()))
    }
}

impl<K: AsRef<[u8]>> StorageMap<K, i64> {
    pub fn get(&self, key: &K) -> Option<i64> {
        get_i64(&self.build_key(key.as_ref()))
    }

    pub fn insert(&self, key: &K, value: i64) -> bool {
        put_i64(&self.build_key(key.as_ref()), value)
    }

    pub fn increment(&self, key: &K, delta: i64) -> i64 {
        increment(&self.build_key(key.as_ref()), delta)
    }

    pub fn remove(&self, key: &K) -> bool {
        delete(&self.build_key(key.as_ref()))
    }
}

impl<K: AsRef<[u8]>> StorageMap<K, alloc::string::String> {
    pub fn get(&self, key: &K) -> Option<alloc::string::String> {
        get_string(&self.build_key(key.as_ref()))
    }

    pub fn insert(&self, key: &K, value: &str) -> bool {
        put_string(&self.build_key(key.as_ref()), value)
    }

    pub fn remove(&self, key: &K) -> bool {
        delete(&self.build_key(key.as_ref()))
    }
}

/// A single storage value with a fixed key
pub struct StorageValue<V> {
    key: &'static [u8],
    _marker: core::marker::PhantomData<V>,
}

impl<V> StorageValue<V> {
    pub const fn new(key: &'static [u8]) -> Self {
        Self { key, _marker: core::marker::PhantomData }
    }
}

impl StorageValue<Vec<u8>> {
    pub fn get(&self) -> Option<Vec<u8>> {
        get(self.key)
    }

    pub fn set(&self, value: &[u8]) -> bool {
        put(self.key, value)
    }

    pub fn delete(&self) -> bool {
        delete(self.key)
    }

    pub fn exists(&self) -> bool {
        exists(self.key)
    }
}

impl StorageValue<u64> {
    pub fn get(&self) -> Option<u64> {
        get_u64(self.key)
    }

    pub fn set(&self, value: u64) -> bool {
        put_u64(self.key, value)
    }

    pub fn increment(&self, delta: i64) -> i64 {
        increment(self.key, delta)
    }

    pub fn delete(&self) -> bool {
        delete(self.key)
    }

    pub fn exists(&self) -> bool {
        exists(self.key)
    }
}

impl StorageValue<i64> {
    pub fn get(&self) -> Option<i64> {
        get_i64(self.key)
    }

    pub fn set(&self, value: i64) -> bool {
        put_i64(self.key, value)
    }

    pub fn increment(&self, delta: i64) -> i64 {
        increment(self.key, delta)
    }

    pub fn delete(&self) -> bool {
        delete(self.key)
    }
}

impl StorageValue<alloc::string::String> {
    pub fn get(&self) -> Option<alloc::string::String> {
        get_string(self.key)
    }

    pub fn set(&self, value: &str) -> bool {
        put_string(self.key, value)
    }

    pub fn delete(&self) -> bool {
        delete(self.key)
    }
}

/// Iterator over storage entries with a prefix
pub struct PrefixIterator {
    prefix: Vec<u8>,
    current_key: Vec<u8>,
    buffer: Buffer,
}

impl PrefixIterator {
    pub fn new(prefix: &[u8]) -> Self {
        Self { prefix: prefix.to_vec(), current_key: prefix.to_vec(), buffer: Buffer::new(4096) }
    }
}

impl Iterator for PrefixIterator {
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let result = bic::storage_kv_get_next(
                self.prefix.as_ptr() as i32,
                self.prefix.len() as i32,
                self.current_key.as_ptr() as i32,
                self.current_key.len() as i32,
                self.buffer.as_ptr() as i32,
                (self.buffer.as_ptr() as i32) + 2048,
            );

            if result == 0 {
                return None;
            }

            let key_len = (result >> 32) as usize;
            let value_len = (result & 0xFFFFFFFF) as usize;

            if key_len == 0 {
                return None;
            }

            let key = self.buffer.as_slice()[..key_len].to_vec();
            let value = self.buffer.as_slice()[2048..2048 + value_len].to_vec();

            self.current_key = key.clone();

            Some((key, value))
        }
    }
}

/// Iterate over all entries with a given prefix
pub fn iter_prefix(prefix: &[u8]) -> PrefixIterator {
    PrefixIterator::new(prefix)
}
