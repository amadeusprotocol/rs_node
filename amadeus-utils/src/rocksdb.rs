//! Deterministic wrapper API over RocksDB v10.

// Re-export commonly used types for downstream crates
pub use rust_librocksdb_sys;
pub use rust_rocksdb::{
    AsColumnFamilyRef, BlockBasedIndexType, BlockBasedOptions, BottommostLevelCompaction, BoundColumnFamily, Cache,
    ColumnFamilyDescriptor, CompactOptions, DBCompressionType, DBRawIteratorWithThreadMode, DBRecoveryMode, Direction,
    Error as RocksDbError, IteratorMode, LruCacheOptions, MultiThreaded, Options, ReadOptions, SliceTransform,
    Transaction, TransactionDB, TransactionDBOptions, TransactionOptions, WriteOptions, statistics,
};
use tokio::fs::create_dir_all;

#[cfg(test)]
thread_local! {
    static TEST_DB: std::cell::RefCell<Option<TransactionDB<MultiThreaded>>> = std::cell::RefCell::new(None);
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rust_rocksdb::Error),
    #[error(transparent)]
    TokioIo(#[from] tokio::io::Error),
    #[error("Column family not found: {0}")]
    ColumnFamilyNotFound(String),
}

/// Instance-oriented wrapper to be used from Context
#[derive(Clone)]
pub struct RocksDb {
    pub inner: std::sync::Arc<TransactionDB<MultiThreaded>>,
}

impl std::fmt::Debug for RocksDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RocksDb").finish_non_exhaustive()
    }
}

fn cf_names() -> &'static [&'static str] {
    &[
        "default",
        "sysconf",
        "entry",
        "entry_meta",
        "attestation",
        "tx",
        "tx_account_nonce",
        "tx_receiver_nonce",
        "contractstate",
    ]
}

#[cfg(test)]
pub fn init_for_test(base: &str) -> Result<TestDbGuard, Error> {
    let path = format!("{}/db", base);
    std::fs::create_dir_all(&path)?;

    let block_cache = Cache::new_lru_cache(4 * 1024 * 1024 * 1024);

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);
    db_opts.set_max_open_files(30000);
    db_opts.increase_parallelism(4);
    db_opts.set_max_background_jobs(2);
    db_opts.set_max_total_wal_size(2 * 1024 * 1024 * 1024);
    db_opts.set_target_file_size_base(8 * 1024 * 1024 * 1024);
    db_opts.set_max_compaction_bytes(20 * 1024 * 1024 * 1024);
    db_opts.enable_statistics();
    db_opts.set_statistics_level(statistics::StatsLevel::All);
    db_opts.set_skip_stats_update_on_db_open(true);
    db_opts.set_write_buffer_size(512 * 1024 * 1024);
    db_opts.set_max_write_buffer_number(6);
    db_opts.set_min_write_buffer_number_to_merge(2);
    db_opts.set_level_zero_file_num_compaction_trigger(8);
    db_opts.set_level_zero_slowdown_writes_trigger(30);
    db_opts.set_level_zero_stop_writes_trigger(100);
    db_opts.set_max_subcompactions(2);

    let cf_descs: Vec<_> = cf_names()
        .iter()
        .map(|&name| {
            let mut cf_opts = Options::default();
            let mut block_based_options = BlockBasedOptions::default();
            block_based_options.set_block_cache(&block_cache);
            block_based_options.set_index_type(BlockBasedIndexType::TwoLevelIndexSearch);
            block_based_options.set_partition_filters(true);
            block_based_options.set_cache_index_and_filter_blocks(true);
            block_based_options.set_cache_index_and_filter_blocks_with_high_priority(true);
            block_based_options.set_pin_top_level_index_and_filter(true);
            block_based_options.set_pin_l0_filter_and_index_blocks_in_cache(false);
            cf_opts.set_block_based_table_factory(&block_based_options);
            let dict_bytes = 32 * 1024;
            cf_opts.set_compression_per_level(&[
                DBCompressionType::None,
                DBCompressionType::None,
                DBCompressionType::Zstd,
                DBCompressionType::Zstd,
                DBCompressionType::Zstd,
                DBCompressionType::Zstd,
                DBCompressionType::Zstd,
            ]);
            cf_opts.set_compression_type(DBCompressionType::Zstd);
            cf_opts.set_compression_options(-14, 2, 0, dict_bytes);
            cf_opts.set_zstd_max_train_bytes(100 * dict_bytes);
            cf_opts.set_max_total_wal_size(2 * 1024 * 1024 * 1024);
            cf_opts.set_target_file_size_base(8 * 1024 * 1024 * 1024);
            cf_opts.set_max_compaction_bytes(20 * 1024 * 1024 * 1024);
            cf_opts.set_write_buffer_size(512 * 1024 * 1024);
            cf_opts.set_max_write_buffer_number(6);
            cf_opts.set_min_write_buffer_number_to_merge(2);
            cf_opts.set_level_zero_file_num_compaction_trigger(20);
            cf_opts.set_level_zero_slowdown_writes_trigger(40);
            cf_opts.set_level_zero_stop_writes_trigger(100);
            cf_opts.set_max_subcompactions(2);
            ColumnFamilyDescriptor::new(name, cf_opts)
        })
        .collect();

    let mut txn_db_opts = TransactionDBOptions::default();
    txn_db_opts.set_default_lock_timeout(3000);
    txn_db_opts.set_txn_lock_timeout(3000);
    txn_db_opts.set_num_stripes(32);

    let db = TransactionDB::open_cf_descriptors(&db_opts, &txn_db_opts, path, cf_descs)?;

    TEST_DB.with(|cell| {
        *cell.borrow_mut() = Some(db);
    });

    Ok(TestDbGuard { base: base.to_string() })
}

/// Lightweight transaction wrapper for instance API
pub struct RocksDbTxn<'a> {
    inner: SimpleTransaction<'a>,
}

impl<'a> RocksDbTxn<'a> {
    /// Get access to the inner transaction for advanced operations
    pub fn inner(&self) -> &SimpleTransaction<'a> {
        &self.inner
    }
}

impl RocksDb {
    pub async fn open(path: String) -> Result<Self, Error> {
        create_dir_all(&path).await?;

        let block_cache = Cache::new_lru_cache(4 * 1024 * 1024 * 1024);

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_open_files(30000);
        db_opts.increase_parallelism(4);
        db_opts.set_max_background_jobs(2);

        db_opts.set_max_total_wal_size(2 * 1024 * 1024 * 1024); // 2GB
        db_opts.set_target_file_size_base(8 * 1024 * 1024 * 1024);
        db_opts.set_max_compaction_bytes(20 * 1024 * 1024 * 1024);

        db_opts.enable_statistics();
        db_opts.set_statistics_level(statistics::StatsLevel::All);
        db_opts.set_skip_stats_update_on_db_open(true);

        // Bigger L0 flushes
        db_opts.set_write_buffer_size(512 * 1024 * 1024);
        db_opts.set_max_write_buffer_number(6);
        db_opts.set_min_write_buffer_number_to_merge(2);
        // L0 thresholds
        db_opts.set_level_zero_file_num_compaction_trigger(8);
        db_opts.set_level_zero_slowdown_writes_trigger(30);
        db_opts.set_level_zero_stop_writes_trigger(100);
        db_opts.set_max_subcompactions(2);

        let cf_descs: Vec<_> = cf_names()
            .iter()
            .map(|&name| {
                let mut cf_opts = Options::default();

                let mut block_based_options = BlockBasedOptions::default();
                block_based_options.set_block_cache(&block_cache);
                block_based_options.set_index_type(BlockBasedIndexType::TwoLevelIndexSearch);
                block_based_options.set_partition_filters(true);
                block_based_options.set_cache_index_and_filter_blocks(true);
                block_based_options.set_cache_index_and_filter_blocks_with_high_priority(true);
                block_based_options.set_pin_top_level_index_and_filter(true);
                block_based_options.set_pin_l0_filter_and_index_blocks_in_cache(false);
                cf_opts.set_block_based_table_factory(&block_based_options);

                let dict_bytes = 32 * 1024;
                cf_opts.set_compression_per_level(&[
                    DBCompressionType::None, // L0
                    DBCompressionType::None, // L1
                    DBCompressionType::Zstd, // L2
                    DBCompressionType::Zstd, // L3
                    DBCompressionType::Zstd, // L4
                    DBCompressionType::Zstd, // L5
                    DBCompressionType::Zstd, // L6
                ]);

                cf_opts.set_compression_type(DBCompressionType::Zstd);
                cf_opts.set_compression_options(-14, 2, 0, dict_bytes);
                cf_opts.set_zstd_max_train_bytes(100 * dict_bytes);

                cf_opts.set_max_total_wal_size(2 * 1024 * 1024 * 1024); // 2GB
                cf_opts.set_target_file_size_base(8 * 1024 * 1024 * 1024);
                cf_opts.set_max_compaction_bytes(20 * 1024 * 1024 * 1024);

                // Bigger L0 flushes
                cf_opts.set_write_buffer_size(512 * 1024 * 1024);
                cf_opts.set_max_write_buffer_number(6);
                cf_opts.set_min_write_buffer_number_to_merge(2);
                // L0 thresholds
                cf_opts.set_level_zero_file_num_compaction_trigger(20);
                cf_opts.set_level_zero_slowdown_writes_trigger(40);
                cf_opts.set_level_zero_stop_writes_trigger(100);
                cf_opts.set_max_subcompactions(2);

                ColumnFamilyDescriptor::new(name, cf_opts)
            })
            .collect();

        let mut txn_db_opts = TransactionDBOptions::default();
        txn_db_opts.set_default_lock_timeout(3000);
        txn_db_opts.set_txn_lock_timeout(3000);
        txn_db_opts.set_num_stripes(32);

        let db: TransactionDB<MultiThreaded> =
            TransactionDB::open_cf_descriptors(&db_opts, &txn_db_opts, path.clone(), cf_descs)?;
        db.flush()?;
        db.flush_wal(true)?;

        Ok(RocksDb { inner: std::sync::Arc::new(db) })
    }

    pub fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, RocksDbError> {
        let cf_h = self.inner.cf_handle(cf).unwrap();
        Ok(self.inner.get_cf(&cf_h, key)?)
    }
    pub fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), RocksDbError> {
        let cf_h = self.inner.cf_handle(cf).unwrap();
        Ok(self.inner.put_cf(&cf_h, key, value)?)
    }
    pub fn delete(&self, cf: &str, key: &[u8]) -> Result<(), RocksDbError> {
        let cf_h = self.inner.cf_handle(cf).unwrap();
        Ok(self.inner.delete_cf(&cf_h, key)?)
    }
    pub fn iter_prefix(&self, cf: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, RocksDbError> {
        let cf_h = self.inner.cf_handle(cf).unwrap();
        let opts = ReadOptions::default();
        let it_mode = IteratorMode::From(prefix, Direction::Forward);
        let iter = self.inner.iterator_cf_opt(&cf_h, opts, it_mode);
        let mut out = Vec::new();
        for item in iter {
            let (k, v) = item?;
            if !k.starts_with(prefix) {
                break;
            }
            out.push((k.to_vec(), v.to_vec()));
        }
        Ok(out)
    }
    pub fn get_prev_or_first(
        &self,
        cf: &str,
        prefix: &str,
        key_suffix: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, RocksDbError> {
        let Some(cf_h) = self.inner.cf_handle(cf) else {
            return Ok(None);
        };
        let opts = ReadOptions::default();
        let key = format!("{}{}", prefix, key_suffix);
        let it_mode = IteratorMode::From(key.as_bytes(), Direction::Reverse);
        let mut iter = self.inner.iterator_cf_opt(&cf_h, opts, it_mode);
        if let Some(item) = iter.next() {
            let (k, v) = item?;
            if !k.starts_with(prefix.as_bytes()) {
                return Ok(None);
            }
            return Ok(Some((k.to_vec(), v.to_vec())));
        }
        // fallback: first forward
        let it_mode_f = IteratorMode::From(prefix.as_bytes(), Direction::Forward);
        let mut iter_f = self.inner.iterator_cf_opt(&cf_h, ReadOptions::default(), it_mode_f);
        if let Some(item) = iter_f.next() {
            let (k, v) = item?;
            if k.starts_with(prefix.as_bytes()) {
                return Ok(Some((k.to_vec(), v.to_vec())));
            }
        }
        Ok(None)
    }
    pub fn begin_transaction(&self) -> Transaction<'_, TransactionDB<MultiThreaded>> {
        let txn_opts = TransactionOptions::default();
        let write_opts = WriteOptions::default();
        self.inner.transaction_opt(&write_opts, &txn_opts)
    }

    /// Flush write-ahead log to disk
    pub fn flush_wal(&self, sync: bool) -> Result<(), Error> {
        self.inner.flush_wal(sync).map_err(Into::into)
    }

    /// Flush all memtables to disk
    pub fn flush(&self) -> Result<(), Error> {
        self.inner.flush().map_err(Into::into)
    }

    /// Flush a specific column family's memtable to disk
    pub fn flush_cf(&self, cf: &str) -> Result<(), Error> {
        let cf_h = self.inner.cf_handle(cf).ok_or_else(|| Error::ColumnFamilyNotFound(cf.to_string()))?;
        self.inner.flush_cf(&cf_h).map_err(Into::into)
    }

    /// Close the database gracefully by flushing pending writes
    /// Note: RocksDB will be properly closed when this struct is dropped
    pub fn close(&self) -> Result<(), Error> {
        // Flush WAL before closing
        self.flush_wal(true)?;
        // Flush all memtables
        self.flush()?;
        // Database will be closed when Arc is dropped
        Ok(())
    }

    /// Create a checkpoint (snapshot) of the database at the given path
    /// This is a native RocksDB checkpoint operation
    pub fn checkpoint(&self, path: &str) -> Result<(), Error> {
        self.inner.create_checkpoint(path).map_err(Into::into)
    }
}

impl<'a> RocksDbTxn<'a> {
    pub fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.inner.put(cf, key, value)
    }
    pub fn delete(&self, cf: &str, key: &[u8]) -> Result<(), Error> {
        self.inner.delete(cf, key)
    }
    pub fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.inner.get(cf, key)
    }
    pub fn raw_iterator_cf(
        &self,
        cf: &str,
    ) -> Result<DBRawIteratorWithThreadMode<'_, Transaction<'_, TransactionDB<MultiThreaded>>>, Error> {
        self.inner.raw_iterator_cf(cf)
    }
    pub fn commit(self) -> Result<(), Error> {
        self.inner.commit()
    }
    pub fn rollback(self) -> Result<(), Error> {
        self.inner.rollback()
    }
}

/// RocksDB transaction trait
pub trait RocksDbTransaction {
    /// Put a key-value pair in the transaction
    fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), Error>;

    /// Delete a key in the transaction
    fn delete(&self, cf: &str, key: &[u8]) -> Result<(), Error>;

    /// Get a value from the transaction
    fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    /// Commit the transaction
    fn commit(self) -> Result<(), Error>;

    /// Rollback the transaction
    fn rollback(self) -> Result<(), Error>;
}

/// RocksDB trait for database operations with transaction support
pub trait RocksDbTrait {
    type Transaction<'a>: RocksDbTransaction
    where
        Self: 'a;

    /// Create a new transaction
    fn txn(&self) -> Self::Transaction<'_>;

    /// Direct get operation without transaction (for read-only operations)
    fn get(&self, cf: &str, key: &[u8]) -> Option<Vec<u8>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cf {
    Default,
    SysConf,
    Entry,
    EntryMeta,
    Attestation,
    Tx,
    TxAccountNonce,
    TxReceiverNonce,
    ContractState,
}

impl Cf {
    pub fn as_str(&self) -> &'static str {
        match self {
            Cf::Default => "default",
            Cf::SysConf => "sysconf",
            Cf::Entry => "entry",
            Cf::EntryMeta => "entry_meta",
            Cf::Attestation => "attestation",
            Cf::Tx => "tx",
            Cf::TxAccountNonce => "tx_account_nonce",
            Cf::TxReceiverNonce => "tx_receiver_nonce",
            Cf::ContractState => "contractstate",
        }
    }
}

/// Simple transaction for TransactionDB
pub struct SimpleTransaction<'a> {
    pub txn: Transaction<'a, TransactionDB<MultiThreaded>>,
    pub db: &'a TransactionDB<MultiThreaded>,
}

impl<'a> SimpleTransaction<'a> {
    pub fn raw_iterator_cf(
        &self,
        cf: &str,
    ) -> Result<DBRawIteratorWithThreadMode<'_, Transaction<'_, TransactionDB<MultiThreaded>>>, Error> {
        let cf_handle = self.db.cf_handle(cf).ok_or_else(|| Error::ColumnFamilyNotFound(cf.to_string()))?;
        Ok(self.txn.raw_iterator_cf(&cf_handle))
    }
}

impl<'a> RocksDbTransaction for SimpleTransaction<'a> {
    fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let cf_handle = self.db.cf_handle(cf).ok_or_else(|| Error::ColumnFamilyNotFound(cf.to_string()))?;
        self.txn.put_cf(&cf_handle, key, value).map_err(Into::into)
    }

    fn delete(&self, cf: &str, key: &[u8]) -> Result<(), Error> {
        let cf_handle = self.db.cf_handle(cf).ok_or_else(|| Error::ColumnFamilyNotFound(cf.to_string()))?;
        self.txn.delete_cf(&cf_handle, key).map_err(Into::into)
    }

    fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let cf_handle = self.db.cf_handle(cf).ok_or_else(|| Error::ColumnFamilyNotFound(cf.to_string()))?;
        self.txn.get_cf(&cf_handle, key).map_err(Into::into)
    }

    fn commit(self) -> Result<(), Error> {
        self.txn.commit().map_err(Into::into)
    }

    fn rollback(self) -> Result<(), Error> {
        self.txn.rollback().map_err(Into::into)
    }
}

/// Snapshot module for deterministic export/import of column families
pub mod snapshot {
    use super::*;
    use blake3::Hasher;
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use tokio::fs::File;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};

    const MAGIC: &[u8] = b"SPK1";
    const DOMAIN_SEP: &str = "statepack-v1";

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Manifest {
        pub version: u32,
        pub algo: String,
        pub cf: String,
        pub items_total: u64,
        pub root_hex: String,
        pub snapshot_seq: Option<u64>,
        pub domain_sep: String,
    }

    /// Write a varint (unsigned LEB128) to async writer
    async fn write_varint(mut value: u64, writer: &mut (impl AsyncWrite + Unpin)) -> Result<(), Error> {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            writer.write_u8(byte).await.map_err(Error::TokioIo)?;
            if value == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Read a varint (unsigned LEB128) from async reader
    async fn read_varint(reader: &mut (impl AsyncRead + Unpin)) -> Result<u64, Error> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let byte = reader.read_u8().await.map_err(Error::TokioIo)?;
            result |= ((byte & 0x7f) as u64) << shift;
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err(Error::TokioIo(
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "varint too large").into(),
                ));
            }
        }
        Ok(result)
    }

    /// Encode a varint as bytes (for hashing)
    fn encode_varint_bytes(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                break;
            }
        }
        bytes
    }

    /// Export a column family to a deterministic snapshot file (.spk)
    pub async fn export_spk(db: &super::RocksDb, cf_name: &str, output_path: &Path) -> Result<Manifest, Error> {
        let cf_handle = db.inner.cf_handle(cf_name).ok_or_else(|| {
            Error::TokioIo(
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("column family '{}' not found", cf_name))
                    .into(),
            )
        })?;

        let snapshot = db.inner.snapshot();
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true);
        read_opts.set_snapshot(&snapshot);

        let iterator = db.inner.iterator_cf_opt(&cf_handle, read_opts, IteratorMode::From(&[], Direction::Forward));

        let mut records = Vec::new();
        let mut count = 0u64;

        for item in iterator {
            let (key, value) = item?;
            records.push((key.to_vec(), value.to_vec()));
            count += 1;
        }

        // Sort records by key for deterministic export
        records.sort_by(|a, b| a.0.cmp(&b.0));

        let file = File::create(output_path).await.map_err(Error::TokioIo)?;
        let mut writer = BufWriter::new(file);
        let mut hasher = Hasher::new();

        // Write header
        writer.write_all(MAGIC).await.map_err(Error::TokioIo)?;
        // Note: MAGIC is not included in the hash for consistency with hash_cf

        // Hash domain separator
        hasher.update(DOMAIN_SEP.as_bytes());

        // Write and hash records
        for (key, value) in records {
            // Hash key length, key, value length, value
            let key_len_bytes = encode_varint_bytes(key.len() as u64);
            let value_len_bytes = encode_varint_bytes(value.len() as u64);

            hasher.update(&key_len_bytes);
            hasher.update(&key);
            hasher.update(&value_len_bytes);
            hasher.update(&value);

            // Write to file
            write_varint(key.len() as u64, &mut writer).await?;
            writer.write_all(&key).await.map_err(Error::TokioIo)?;
            write_varint(value.len() as u64, &mut writer).await?;
            writer.write_all(&value).await.map_err(Error::TokioIo)?;
        }

        writer.flush().await.map_err(Error::TokioIo)?;
        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash.as_bytes());

        Ok(Manifest {
            version: 1,
            algo: "blake3".to_string(),
            cf: cf_name.to_string(),
            items_total: count,
            root_hex: hash_hex,
            snapshot_seq: None,
            domain_sep: DOMAIN_SEP.to_string(),
        })
    }

    /// Import a snapshot file (.spk) into a column family using streaming with batching
    pub async fn import_spk(
        db: &super::RocksDb,
        cf_name: &str,
        spk_in: &Path,
        manifest: &Manifest,
        batch_bytes: usize,
    ) -> Result<(), Error> {
        use tokio::sync::mpsc;

        // Verify manifest matches request
        if manifest.cf != cf_name {
            return Err(Error::TokioIo(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("manifest cf '{}' != requested cf '{}'", manifest.cf, cf_name),
                )
                .into(),
            ));
        }

        let file = File::open(spk_in).await.map_err(Error::TokioIo)?;
        let mut reader = BufReader::new(file);

        // Verify magic header
        let mut magic_buf = [0u8; 4];
        reader.read_exact(&mut magic_buf).await.map_err(Error::TokioIo)?;
        if &magic_buf != MAGIC {
            return Err(Error::TokioIo(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid magic header").into(),
            ));
        }

        // Create a channel for batching writes
        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, Vec<u8>)>(100);

        // Spawn task to handle batch writes
        let cf_name_owned = cf_name.to_string();
        let db_clone = db.clone();
        let write_task = tokio::spawn(async move {
            let db = db_clone;
            let mut current_batch = Vec::new();
            let mut current_size = 0;

            while let Some((key, value)) = rx.recv().await {
                let item_size = key.len() + value.len();
                if current_size + item_size > batch_bytes && !current_batch.is_empty() {
                    // Write current batch
                    write_batch(&db, &cf_name_owned, &current_batch)?;
                    current_batch.clear();
                    current_size = 0;
                }

                current_batch.push((key, value));
                current_size += item_size;
            }

            // Write final batch
            if !current_batch.is_empty() {
                write_batch(&db, &cf_name_owned, &current_batch)?;
            }

            Ok::<(), Error>(())
        });

        // Read and send records to write task
        let mut records_read = 0u64;
        while records_read < manifest.items_total {
            let key_len = read_varint(&mut reader).await?;
            let mut key = vec![0u8; key_len as usize];
            reader.read_exact(&mut key).await.map_err(Error::TokioIo)?;

            let value_len = read_varint(&mut reader).await?;
            let mut value = vec![0u8; value_len as usize];
            reader.read_exact(&mut value).await.map_err(Error::TokioIo)?;

            tx.send((key, value)).await.map_err(|_| {
                Error::TokioIo(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel closed").into())
            })?;

            records_read += 1;
        }

        drop(tx); // Close channel
        write_task.await.map_err(|e| Error::TokioIo(std::io::Error::new(std::io::ErrorKind::Other, e).into()))??;

        Ok(())
    }

    /// Write a batch of key-value pairs to the database
    fn write_batch(db: &super::RocksDb, cf_name: &str, batch: &[(Vec<u8>, Vec<u8>)]) -> Result<(), Error> {
        let cf_handle = db.inner.cf_handle(cf_name).ok_or_else(|| Error::ColumnFamilyNotFound(cf_name.to_string()))?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false); // Use async writes for better performance

        for (key, value) in batch {
            db.inner.put_cf_opt(&cf_handle, key, value, &write_opts)?;
        }

        Ok(())
    }

    /// Hash a column family in the database (for verification)
    pub async fn hash_cf(db: &super::RocksDb, cf_name: &str) -> Result<[u8; 32], Error> {
        let snapshot = db.inner.snapshot();
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true);
        read_opts.set_snapshot(&snapshot);

        let cf_handle = db.inner.cf_handle(cf_name).ok_or_else(|| {
            Error::TokioIo(
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("cf '{}' missing", cf_name)).into(),
            )
        })?;

        let iterator = db.inner.iterator_cf_opt(&cf_handle, read_opts, IteratorMode::Start);

        let mut hasher = Hasher::new();
        hasher.update(DOMAIN_SEP.as_bytes());

        let mut records = Vec::new();
        for item in iterator {
            let (key, value) = item?;
            records.push((key.to_vec(), value.to_vec()));
        }

        // Sort for deterministic hashing
        records.sort_by(|a, b| a.0.cmp(&b.0));

        for (key, value) in records {
            let key_len_bytes = encode_varint_bytes(key.len() as u64);
            let value_len_bytes = encode_varint_bytes(value.len() as u64);

            hasher.update(&key_len_bytes);
            hasher.update(&key);
            hasher.update(&value_len_bytes);
            hasher.update(&value);
        }

        let hash_result = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(hash_result.as_bytes());
        Ok(hash_array)
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
        async fn test_snapshot_export_import() {
            let base = tmp_base_for_test(&test_snapshot_export_import);
            let db = super::RocksDb::open(base.clone()).await.expect("open test db");

            // Put some test data
            db.put(crate::constants::CF_DEFAULT, b"key1", b"value1").unwrap();
            db.put(crate::constants::CF_DEFAULT, b"key2", b"value2").unwrap();
            db.put(crate::constants::CF_DEFAULT, b"key3", b"value3").unwrap();

            let spk_path = std::path::PathBuf::from(format!("{}/test.spk", base));

            // Export snapshot
            let manifest = export_spk(&db, crate::constants::CF_DEFAULT, &spk_path).await.unwrap();
            assert_eq!(manifest.items_total, 3);
            assert_eq!(manifest.cf, crate::constants::CF_DEFAULT);
            assert_eq!(manifest.version, 1);

            // Verify hash matches
            let cf_hash = hash_cf(&db, crate::constants::CF_DEFAULT).await.unwrap();
            assert_eq!(hex::encode(cf_hash), manifest.root_hex);

            // Test import on a fresh database instance
            let base2 = tmp_base_for_test(&"test_import_fresh");
            let db2 = super::RocksDb::open(base2.clone()).await.expect("open test db 2");

            // Import the snapshot to the fresh database
            import_spk(&db2, crate::constants::CF_DEFAULT, &spk_path, &manifest, 1024).await.unwrap();

            // Verify data was imported correctly
            assert_eq!(db2.get(crate::constants::CF_DEFAULT, b"key1").unwrap(), Some(b"value1".to_vec()));
            assert_eq!(db2.get(crate::constants::CF_DEFAULT, b"key2").unwrap(), Some(b"value2".to_vec()));
            assert_eq!(db2.get(crate::constants::CF_DEFAULT, b"key3").unwrap(), Some(b"value3".to_vec()));

            // Verify hash matches on imported data
            let cf_hash_after = hash_cf(&db2, crate::constants::CF_DEFAULT).await.unwrap();
            assert_eq!(hex::encode(cf_hash_after), manifest.root_hex);
        }
    }
}

// Implement Database trait for RocksDb
impl crate::database::Database for RocksDb {
    fn get(&self, column_family: &str, key: &[u8]) -> Result<Option<Vec<u8>>, crate::database::DatabaseError> {
        self.get(column_family, key).map_err(|e| crate::database::DatabaseError::Generic(e.to_string()))
    }

    fn put(&self, column_family: &str, key: &[u8], value: &[u8]) -> Result<(), crate::database::DatabaseError> {
        self.put(column_family, key, value).map_err(|e| crate::database::DatabaseError::Generic(e.to_string()))
    }

    fn delete(&self, column_family: &str, key: &[u8]) -> Result<(), crate::database::DatabaseError> {
        self.delete(column_family, key).map_err(|e| crate::database::DatabaseError::Generic(e.to_string()))
    }

    fn iter_prefix(
        &self,
        column_family: &str,
        prefix: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, crate::database::DatabaseError> {
        self.iter_prefix(column_family, prefix).map_err(|e| crate::database::DatabaseError::Generic(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[global_allocator]
    static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

    #[tokio::test]
    #[ignore]
    async fn spam_random_writes() {
        use rand::Rng;
        let db = RocksDb::open("/tmp/rocksdb_spam".to_string()).await.unwrap();
        let db_ref = &db.inner;
        std::thread::scope(|s| {
            for _ in 0..16 {
                s.spawn(|| {
                    let mut rng = rand::rng();
                    loop {
                        let cf = cf_names()[rng.random_range(0..cf_names().len())];
                        let key: Vec<u8> = (0..rng.random_range(8..64)).map(|_| rng.random()).collect();
                        let val: Vec<u8> = (0..rng.random_range(8000..12000)).map(|_| rng.random()).collect();
                        let cf_h = db_ref.cf_handle(cf).unwrap();
                        db_ref.put_cf(&cf_h, &key, &val).unwrap();
                    }
                });
            }
        });
    }

    #[test]
    #[ignore]
    fn append_to_all_keys() {
        use rand::Rng;
        let _guard = init_for_test("/tmp/rocksdb_spam").unwrap();
        TEST_DB.with(|cell| {
            let h = cell.borrow();
            let db = h.as_ref().unwrap();
            let mut rng = rand::rng();
            loop {
                for cf in cf_names() {
                    let cf_h = db.cf_handle(cf).unwrap();
                    let mut opts = ReadOptions::default();
                    opts.set_total_order_seek(true);
                    let iter = db.iterator_cf_opt(&cf_h, opts, IteratorMode::Start);
                    for item in iter {
                        let (key, val) = item.unwrap();
                        let mut new_val = val.to_vec();
                        let append: Vec<u8> = (0..rng.random_range(16..100)).map(|_| rng.random()).collect();
                        new_val.extend_from_slice(&append);
                        db.put_cf(&cf_h, &key, &new_val).unwrap();
                    }
                }
            }
        });
    }

    #[test]
    #[ignore]
    fn delete_all_keys() {
        let _guard = init_for_test("/tmp/rocksdb_spam").unwrap();
        TEST_DB.with(|cell| {
            let h = cell.borrow();
            let db = h.as_ref().unwrap();
            loop {
                for cf in cf_names() {
                    let cf_h = db.cf_handle(cf).unwrap();
                    let mut opts = ReadOptions::default();
                    opts.set_total_order_seek(true);
                    let iter = db.iterator_cf_opt(&cf_h, opts, IteratorMode::Start);
                    for item in iter {
                        let (key, _val) = item.unwrap();
                        db.delete_cf(&cf_h, &key).unwrap();
                    }
                }
            }
        });
    }
}
