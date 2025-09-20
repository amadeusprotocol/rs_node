use crate::consensus::chain_epoch;
use crate::utils::rocksdb::{self, RocksDbTransaction};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};
use tracing::{debug, info};

pub struct FabricCleaner {
    stop_signal: Arc<RwLock<bool>>,
}

impl FabricCleaner {
    pub fn new() -> Self {
        Self { stop_signal: Arc::new(RwLock::new(false)) }
    }

    pub async fn start(self: Arc<Self>) {
        let cleaner = self.clone();
        tokio::spawn(async move {
            cleaner.run().await;
        });
    }

    async fn run(&self) {
        loop {
            if *self.stop_signal.read().await {
                break;
            }

            self.check_and_clean_finality().await;

            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn check_and_clean_finality(&self) {
        let finality_clean_next_epoch = self.get_finality_clean_next_epoch().unwrap_or(0);
        let epoch = chain_epoch();

        if finality_clean_next_epoch < epoch.saturating_sub(1) {
            self.clean_finality(finality_clean_next_epoch).await;
        }
    }

    async fn clean_finality(&self, epoch: u32) {
        info!("Cleaning finality for epoch: {}", epoch);

        let start_height = epoch * 100_000;
        let _end_height = start_height + 99_999;

        // Process in parallel batches of 10k heights
        let mut handles = vec![];
        for idx in 0..10 {
            let start_index = start_height + idx as u32 * 10_000;
            let end_index = start_index + 9_999;

            let handle = tokio::spawn(async move {
                clean_muts_rev(epoch, start_index, end_index).await;
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }

        // Update the next epoch to clean
        self.set_finality_clean_next_epoch(epoch + 1);
    }

    fn get_finality_clean_next_epoch(&self) -> Option<u32> {
        match rocksdb::get("sysconf", b"finality_clean_next_epoch") {
            Ok(Some(bytes)) => match bincode::decode_from_slice::<u32, _>(&bytes, bincode::config::standard()) {
                Ok((epoch, _)) => Some(epoch),
                Err(_) => None,
            },
            _ => None,
        }
    }

    fn set_finality_clean_next_epoch(&self, epoch: u32) {
        let bytes = bincode::encode_to_vec(&epoch, bincode::config::standard()).unwrap();
        let _ = rocksdb::put("sysconf", b"finality_clean_next_epoch", &bytes);
    }

    pub async fn stop(&self) {
        *self.stop_signal.write().await = true;
    }
}

async fn clean_muts_rev(_epoch: u32, start: u32, end: u32) {
    // Create a transaction for batch operations
    let txn = match rocksdb::begin_transaction() {
        Ok(txn) => txn,
        Err(e) => {
            debug!("Failed to create transaction: {}", e);
            return;
        }
    };

    let mut operations = 0;
    for height in start..=end {
        if height % 1000 == 0 {
            debug!("Cleaning muts_rev at height: {}", height);
        }

        // Get entry hashes at this height - we need the hashes for muts_rev keys
        let height_prefix = format!("{:016}:", height);
        let kvs = match crate::utils::rocksdb::iter_prefix("entry_by_height|height:entryhash", height_prefix.as_bytes())
        {
            Ok(kvs) => kvs,
            Err(_) => continue,
        };

        // Delete muts_rev for each entry hash
        for (_k, entry_hash) in kvs {
            if let Err(e) = txn.delete("muts_rev", &entry_hash) {
                debug!("Failed to delete entry hash: {}", e);
                continue;
            }
            operations += 1;
        }
    }

    // Commit the transaction
    if operations > 0 {
        if let Err(e) = txn.commit() {
            debug!("Failed to commit transaction: {}", e);
        } else {
            debug!("Committed {} delete operations", operations);
        }
    }
}

// TODO: Need to add proper transaction support for batch deletions
// The Elixir version uses RocksDB transactions which we don't have fully implemented yet
