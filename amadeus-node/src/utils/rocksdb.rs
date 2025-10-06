//! Deterministic wrapper API over RocksDB v10.
use rust_rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, DBRecoveryMode, Direction, FlushOptions,
    IteratorMode, MultiThreaded, OptimisticTransactionDB, OptimisticTransactionOptions, Options, ReadOptions,
    SliceTransform, Transaction, WriteOptions,
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rust_rocksdb::Error),
    #[error(transparent)]
    TokioIo(#[from] tokio::io::Error),
    #[error("Column family not found: {0}")]
    ColumnFamilyNotFound(String),
}

#[derive(Debug)]
pub struct DbHandles {
    pub db: OptimisticTransactionDB<MultiThreaded>,
}

/// Instance-oriented wrapper to be used from Context
#[derive(Clone, Debug)]
pub struct RocksDb {
    handles: std::sync::Arc<DbHandles>,
}

fn cf_names() -> &'static [&'static str] {
    &[
        "default",
        "entry_by_height|height:entryhash",
        "entry_by_slot|slot:entryhash",
        "tx|txhash:entryhash",
        "tx_account_nonce|account:nonce->txhash",
        "tx_receiver_nonce|receiver:nonce->txhash",
        "my_seen_time_entry|entryhash",
        "my_attestation_for_entry|entryhash",
        // "my_mutations_hash_for_entry|entryhash",
        "consensus",
        "consensus_by_entryhash|Map<mutationshash,consensus>",
        "contractstate",
        "muts",
        "muts_rev",
        "sysconf",
    ]
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

/// Lightweight transaction wrapper for instance API
pub struct RocksDbTxn<'a> {
    inner: SimpleTransaction<'a>,
}

impl RocksDb {
    pub async fn open(base: String) -> Result<Self, Error> {
        let path = format!("{}/db", base);
        create_dir_all(&path).await?;

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        #[cfg(debug_assertions)]
        db_opts.set_use_fsync(false);

        db_opts.set_write_buffer_size(64 * 1024 * 1024);
        db_opts.set_db_write_buffer_size(1024 * 1024 * 1024);
        db_opts.set_max_write_buffer_number(3);
        db_opts.set_min_write_buffer_number_to_merge(1);
        db_opts.set_max_open_files(1024);
        db_opts.set_max_file_opening_threads(8);
        db_opts.increase_parallelism(4);
        db_opts.set_max_total_wal_size(1 * 1024 * 1024 * 1024);
        db_opts.set_recycle_log_file_num(8);
        db_opts.set_wal_bytes_per_sync(1 << 20);
        db_opts.set_bytes_per_sync(1 << 20);
        db_opts.set_wal_recovery_mode(DBRecoveryMode::TolerateCorruptedTailRecords);
        db_opts.set_max_background_jobs(6);

        let mut block_opts = BlockBasedOptions::default();
        let cache = Cache::new_lru_cache(128 * 1024 * 1024);
        block_opts.set_block_cache(&cache);
        db_opts.set_block_based_table_factory(&block_opts);

        let cf_descs: Vec<_> = cf_names()
            .iter()
            .map(|&name| {
                let mut opts = Options::default();
                opts.set_target_file_size_base(64 * 1024 * 1024);
                opts.set_target_file_size_multiplier(2);
                opts.set_write_buffer_size(64 * 1024 * 1024);
                opts.set_max_write_buffer_number(2);
                opts.set_level_zero_file_num_compaction_trigger(4);
                opts.set_compression_type(DBCompressionType::Lz4);
                opts.set_level_compaction_dynamic_level_bytes(true);
                opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(8));
                let mut block_opts = BlockBasedOptions::default();
                block_opts.set_bloom_filter(10.0, true);
                block_opts.set_block_size(16 * 1024);
                opts.set_block_based_table_factory(&block_opts);
                ColumnFamilyDescriptor::new(name, opts)
            })
            .collect();

        let db: OptimisticTransactionDB<MultiThreaded> =
            OptimisticTransactionDB::open_cf_descriptors(&db_opts, path.clone(), cf_descs)?;
        db.flush_opt(&FlushOptions::default())?;
        db.flush_wal(true)?;

        Ok(RocksDb { handles: std::sync::Arc::new(DbHandles { db }) })
    }

    pub fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let h = &self.handles;
        let cf_h = h.db.cf_handle(cf).ok_or_else(|| Error::ColumnFamilyNotFound(cf.to_string()))?;
        Ok(h.db.get_cf(&cf_h, key)?)
    }
    pub fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let h = &self.handles;
        let cf_h = h.db.cf_handle(cf).ok_or_else(|| Error::ColumnFamilyNotFound(cf.to_string()))?;
        Ok(h.db.put_cf(&cf_h, key, value)?)
    }
    pub fn delete(&self, cf: &str, key: &[u8]) -> Result<(), Error> {
        let h = &self.handles;
        let cf_h = h.db.cf_handle(cf).ok_or_else(|| Error::ColumnFamilyNotFound(cf.to_string()))?;
        Ok(h.db.delete_cf(&cf_h, key)?)
    }
    pub fn iter_prefix(&self, cf: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
        let h = &self.handles;
        let cf_h = h.db.cf_handle(cf).ok_or_else(|| Error::ColumnFamilyNotFound(cf.to_string()))?;
        let opts = ReadOptions::default();
        let it_mode = IteratorMode::From(prefix, Direction::Forward);
        let iter = h.db.iterator_cf_opt(&cf_h, opts, it_mode);
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
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
        let h = &self.handles;
        let cf_h = h.db.cf_handle(cf).ok_or_else(|| Error::ColumnFamilyNotFound(cf.to_string()))?;
        let opts = ReadOptions::default();
        let key = format!("{}{}", prefix, key_suffix);
        let it_mode = IteratorMode::From(key.as_bytes(), Direction::Reverse);
        let mut iter = h.db.iterator_cf_opt(&cf_h, opts, it_mode);
        if let Some(item) = iter.next() {
            let (k, v) = item?;
            if !k.starts_with(prefix.as_bytes()) {
                return Ok(None);
            }
            return Ok(Some((k.to_vec(), v.to_vec())));
        }
        // fallback: first forward
        let it_mode_f = IteratorMode::From(prefix.as_bytes(), Direction::Forward);
        let mut iter_f = h.db.iterator_cf_opt(&cf_h, ReadOptions::default(), it_mode_f);
        if let Some(item) = iter_f.next() {
            let (k, v) = item?;
            if k.starts_with(prefix.as_bytes()) {
                return Ok(Some((k.to_vec(), v.to_vec())));
            }
        }
        Ok(None)
    }
    pub fn begin_transaction(&self) -> Result<RocksDbTxn<'_>, Error> {
        let h = &self.handles;
        let txn_opts = OptimisticTransactionOptions::default();
        let write_opts = WriteOptions::default();
        let txn = h.db.transaction_opt(&write_opts, &txn_opts);
        Ok(RocksDbTxn { inner: SimpleTransaction { txn, db: &h.db } })
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
    EntryByHeight,
    EntryBySlot,
    Tx,
    TxAccountNonce,
    TxReceiverNonce,
    MySeenTimeEntry,
    MyAttestationForEntry,
    Consensus,
    ConsensusByEntryhash,
    ContractState,
    Muts,
    MutsRev,
    SysConf,
}

impl Cf {
    pub fn as_str(&self) -> &'static str {
        match self {
            Cf::Default => "default",
            Cf::EntryByHeight => "entry_by_height|height:entryhash",
            Cf::EntryBySlot => "entry_by_slot|slot:entryhash",
            Cf::Tx => "tx|txhash:entryhash",
            Cf::TxAccountNonce => "tx_account_nonce|account:nonce->txhash",
            Cf::TxReceiverNonce => "tx_receiver_nonce|receiver:nonce->txhash",
            Cf::MySeenTimeEntry => "my_seen_time_entry|entryhash",
            Cf::MyAttestationForEntry => "my_attestation_for_entry|entryhash",
            Cf::Consensus => "consensus",
            Cf::ConsensusByEntryhash => "consensus_by_entryhash|Map<mutationshash,consensus>",
            Cf::ContractState => "contractstate",
            Cf::Muts => "muts",
            Cf::MutsRev => "muts_rev",
            Cf::SysConf => "sysconf",
        }
    }
}

/// Simple transaction for OptimisticTransactionDB
pub struct SimpleTransaction<'a> {
    txn: Transaction<'a, OptimisticTransactionDB<MultiThreaded>>,
    db: &'a OptimisticTransactionDB<MultiThreaded>,
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
        let handles = db.handles.as_ref();
        let cf_handle = handles.db.cf_handle(cf_name).ok_or_else(|| {
            Error::TokioIo(
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("column family '{}' not found", cf_name))
                    .into(),
            )
        })?;

        let snapshot = handles.db.snapshot();
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true);
        read_opts.set_snapshot(&snapshot);

        let iterator = handles.db.iterator_cf_opt(&cf_handle, read_opts, IteratorMode::From(&[], Direction::Forward));

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
        let handles = db.handles.as_ref();
        let cf_handle =
            handles.db.cf_handle(cf_name).ok_or_else(|| Error::ColumnFamilyNotFound(cf_name.to_string()))?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false); // Use async writes for better performance

        for (key, value) in batch {
            handles.db.put_cf_opt(&cf_handle, key, value, &write_opts)?;
        }

        Ok(())
    }

    /// Hash a column family in the database (for verification)
    pub async fn hash_cf(db: &super::RocksDb, cf_name: &str) -> Result<[u8; 32], Error> {
        let handles = db.handles.as_ref();
        let snapshot = handles.db.snapshot();
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true);
        read_opts.set_snapshot(&snapshot);

        let cf_handle = handles.db.cf_handle(cf_name).ok_or_else(|| {
            Error::TokioIo(
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("cf '{}' missing", cf_name)).into(),
            )
        })?;

        let iterator = handles.db.iterator_cf_opt(&cf_handle, read_opts, IteratorMode::Start);

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
            db.put("default", b"key1", b"value1").unwrap();
            db.put("default", b"key2", b"value2").unwrap();
            db.put("default", b"key3", b"value3").unwrap();

            let spk_path = std::path::PathBuf::from(format!("{}/test.spk", base));

            // Export snapshot
            let manifest = export_spk(&db, "default", &spk_path).await.unwrap();
            assert_eq!(manifest.items_total, 3);
            assert_eq!(manifest.cf, "default");
            assert_eq!(manifest.version, 1);

            // Verify hash matches
            let cf_hash = hash_cf(&db, "default").await.unwrap();
            assert_eq!(hex::encode(cf_hash), manifest.root_hex);

            // Test import on a fresh database instance
            let base2 = tmp_base_for_test(&"test_import_fresh");
            let db2 = super::RocksDb::open(base2.clone()).await.expect("open test db 2");

            // Import the snapshot to the fresh database
            import_spk(&db2, "default", &spk_path, &manifest, 1024).await.unwrap();

            // Verify data was imported correctly
            assert_eq!(db2.get("default", b"key1").unwrap(), Some(b"value1".to_vec()));
            assert_eq!(db2.get("default", b"key2").unwrap(), Some(b"value2".to_vec()));
            assert_eq!(db2.get("default", b"key3").unwrap(), Some(b"value3".to_vec()));

            // Verify hash matches on imported data
            let cf_hash_after = hash_cf(&db2, "default").await.unwrap();
            assert_eq!(hex::encode(cf_hash_after), manifest.root_hex);
        }
    }
}
