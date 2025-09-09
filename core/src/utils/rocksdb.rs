use once_cell::sync::OnceCell;
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, Direction, IteratorMode, MultiThreaded, OptimisticTransactionDB, Options, ReadOptions,
};
use tokio::fs::create_dir_all;

#[cfg(test)]
thread_local! {
    static TEST_DB: std::cell::RefCell<Option<DbHandles>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
pub struct TestDbGuard {
    base: String,
}

#[cfg(test)]
impl Drop for TestDbGuard {
    fn drop(&mut self) {
        // drop the thread-local DB so RocksDB files can be removed
        TEST_DB.with(|cell| {
            *cell.borrow_mut() = None;
        });
        // best-effort cleanup of the base directory
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[cfg(test)]
impl TestDbGuard {
    pub fn base(&self) -> &str {
        &self.base
    }
}

#[cfg(test)]
pub fn init_for_test(base: &str) -> Result<TestDbGuard, Error> {
    // create base/db path synchronously (tests are synchronous)
    let path = format!("{}/db", base);
    std::fs::create_dir_all(&path)?;

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);

    let cf_descs: Vec<_> = cf_names()
        .iter()
        .map(|&name| {
            let mut opts = Options::default();
            opts.set_target_file_size_base(2 * 1024 * 1024 * 1024);
            opts.set_target_file_size_multiplier(2);
            ColumnFamilyDescriptor::new(name, opts)
        })
        .collect();

    let db: OptimisticTransactionDB<MultiThreaded> =
        OptimisticTransactionDB::open_cf_descriptors(&db_opts, path, cf_descs)?;

    TEST_DB.with(|cell| {
        *cell.borrow_mut() = Some(DbHandles { db });
    });

    Ok(TestDbGuard { base: base.to_string() })
}

#[cfg(test)]
fn with_handles<F, R>(f: F) -> R
where
    F: FnOnce(&DbHandles) -> R,
{
    TEST_DB.with(|cell| {
        if let Some(h) = cell.borrow().as_ref() {
            f(h)
        } else {
            let h = get_handles();
            f(h)
        }
    })
}

#[cfg(not(test))]
fn with_handles<F, R>(f: F) -> R
where
    F: FnOnce(&DbHandles) -> R,
{
    let h = get_handles();
    f(h)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),
    #[error(transparent)]
    TokioIo(#[from] tokio::io::Error),
}

pub struct DbHandles {
    pub db: OptimisticTransactionDB<MultiThreaded>,
}

static GLOBAL_DB: OnceCell<DbHandles> = OnceCell::new();

fn cf_names() -> &'static [&'static str] {
    &[
        "default",
        "entry_by_height",
        "entry_by_slot",
        "tx",
        "tx_account_nonce",
        "tx_receiver_nonce",
        "my_seen_time_for_entry",
        "my_attestation_for_entry",
        // "my_mutations_hash_for_entry",
        "consensus",
        "consensus_by_entryhash",
        "contractstate",
        "muts",
        "muts_rev",
        "sysconf",
    ]
}

/// Expects path directory to exist
pub async fn init(base: &str) -> Result<(), Error> {
    if GLOBAL_DB.get().is_some() {
        return Ok(());
    }

    let path = format!("{}/db", base);
    create_dir_all(&path).await?;

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);
    
    // Set RAM limits to 10MB total
    db_opts.set_db_write_buffer_size(10 * 1024 * 1024); // 10MB total write buffer size
    db_opts.set_max_write_buffer_number(3); // Maximum 3 write buffers per CF
    
    // Set block cache to 2MB (part of the 10MB limit)
    let cache = Cache::new_lru_cache(2 * 1024 * 1024); // 2MB block cache
    let mut block_opts = BlockBasedOptions::default();
    block_opts.set_block_cache(&cache);
    db_opts.set_block_based_table_factory(&block_opts);

    let cf_descs: Vec<_> = cf_names()
        .iter()
        .map(|&name| {
            let mut opts = Options::default();
            opts.set_target_file_size_base(2 * 1024 * 1024 * 1024);
            opts.set_target_file_size_multiplier(2);
            // Set write buffer size per CF (shared from total 10MB)
            opts.set_write_buffer_size(1024 * 1024); // 1MB per CF write buffer
            opts.set_max_write_buffer_number(2); // Max 2 buffers per CF
            ColumnFamilyDescriptor::new(name, opts)
        })
        .collect();

    let db: OptimisticTransactionDB<MultiThreaded> =
        OptimisticTransactionDB::open_cf_descriptors(&db_opts, path, cf_descs)?;
    GLOBAL_DB.set(DbHandles { db }).ok();
    Ok(())
}

pub fn close() {
    // rocksdb closes on drop, we cannot drop OnceCell contents safely here
}

fn get_handles() -> &'static DbHandles {
    GLOBAL_DB.get().expect("DB not initialized")
}

pub fn get(cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    Ok(with_handles(|h| {
        let cf_h = h.db.cf_handle(cf).expect("cf name");
        h.db.get_cf(&cf_h, key)
    })?)
}

pub fn put(cf: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
    Ok(with_handles(|h| {
        let cf_h = h.db.cf_handle(cf).expect("cf name");
        h.db.put_cf(&cf_h, key, value)
    })?)
}

pub fn delete(cf: &str, key: &[u8]) -> Result<(), Error> {
    Ok(with_handles(|h| {
        let cf_h = h.db.cf_handle(cf).expect("cf name");
        h.db.delete_cf(&cf_h, key)
    })?)
}

pub fn iter_prefix(cf: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
    Ok(with_handles(|h| -> std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, rocksdb::Error> {
        let cf_h = h.db.cf_handle(cf).expect("cf name");
        let mut ro = ReadOptions::default();
        ro.set_prefix_same_as_start(true);
        let mode = IteratorMode::From(prefix, Direction::Forward);
        let it = h.db.iterator_cf_opt(&cf_h, ro, mode);
        let mut out = Vec::new();
        for kv in it {
            let (k, v) = kv?;
            if !k.starts_with(prefix) {
                break;
            }
            out.push((k.to_vec(), v.to_vec()));
        }
        Ok(out)
    })?)
}

/// Find the latest key-value under `prefix` with key <= `prefix || key_suffix`
/// Returns the raw key and value if found, otherwise None
pub fn get_prev_or_first(cf: &str, prefix: &str, key_suffix: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
    Ok(with_handles(|h| -> std::result::Result<Option<(Vec<u8>, Vec<u8>)>, rocksdb::Error> {
        let cf_h = h.db.cf_handle(cf).expect("cf name");
        let seek_key = format!("{}{}", prefix, key_suffix);
        let mut it = h.db.iterator_cf(&cf_h, IteratorMode::From(seek_key.as_bytes(), Direction::Reverse));

        if let Some(res) = it.next() {
            let (k, v) = res?;
            if k.starts_with(prefix.as_bytes()) {
                return Ok(Some((k.to_vec(), v.to_vec())));
            }
        }
        Ok(None)
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::type_name_of_val;

    fn tmp_base_for_test<F: ?Sized>(f: &F) -> String {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let fq = type_name_of_val(f);
        format!("/tmp/{}{}", fq, secs)
    }

    #[tokio::test]
    async fn rocksdb_basic_ops_and_iters() {
        let base = tmp_base_for_test(&rocksdb_basic_ops_and_iters);
        let _guard = init_for_test(&base).expect("init test db");

        // basic put/get on default CF
        put("default", b"a:1", b"v1").expect("put");
        let v = get("default", b"a:1").expect("get").unwrap();
        assert_eq!(v, b"v1");

        // insert a few keys with common prefix for iter_prefix
        for i in 0..5u8 {
            put("default", format!("p:{}", i).as_bytes(), &[i]).unwrap();
        }
        let items = iter_prefix("default", b"p:").expect("iter_prefix");
        assert!(!items.is_empty());
        for (k, _v) in &items {
            assert!(k.starts_with(b"p:"));
        }

        // test get_prev_or_first semantics
        put("default", b"h:001", b"x").unwrap();
        put("default", b"h:010", b"y").unwrap();
        put("default", b"h:020", b"z").unwrap();

        let r = get_prev_or_first("default", "h:", "015").unwrap().unwrap();
        assert_eq!(r.0, b"h:010");
        let r2 = get_prev_or_first("default", "h:", "000").unwrap();
        assert!(r2.is_none());
        let r3 = get_prev_or_first("default", "h:", "999").unwrap().unwrap();
        assert_eq!(r3.0, b"h:020");
    }
}
