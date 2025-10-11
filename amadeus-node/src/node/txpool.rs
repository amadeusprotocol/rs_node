use crate::bic::base;
use crate::bic::coin;
use crate::bic::sol;
use crate::consensus::doms::tx::{TxU, pack, validate};
use crate::consensus::{chain_balance, chain_diff_bits, chain_epoch, chain_nonce, chain_segment_vr_hash};
use crate::utils::rocksdb::RocksDb;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ValidateTxArgs {
    pub epoch: u32,
    pub segment_vr_hash: [u8; 32],
    pub diff_bits: u32,
    pub batch_state: BatchState,
}

#[derive(Debug, Clone, Default)]
pub struct BatchState {
    chain_nonces: HashMap<Vec<u8>, i128>,
    balances: HashMap<Vec<u8>, u64>,
}

#[derive(Debug)]
pub enum TxPoolError {
    InvalidNonce { nonce: i128, hash: [u8; 32] },
    InsufficientBalance { nonce: i128, hash: [u8; 32] },
    InvalidSol { nonce: i128, hash: [u8; 32] },
    ValidationError(String),
}

pub struct TxPool {
    db: Arc<RocksDb>,
    pool: Arc<RwLock<HashMap<Vec<u8>, TxU>>>,
    gifted_sol_cache: Arc<RwLock<HashMap<Vec<u8>, u64>>>,
}

impl TxPool {
    pub fn new(db: Arc<RocksDb>) -> Self {
        Self {
            db,
            pool: Arc::new(RwLock::new(HashMap::new())),
            gifted_sol_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, tx_packed: &[u8]) -> Result<(), TxPoolError> {
        match validate(tx_packed, false) {
            Ok(txu) => {
                let mut pool = self.pool.write().await;
                let key = vec![txu.tx.nonce.to_le_bytes().to_vec(), txu.hash.to_vec()].concat();
                pool.insert(key, txu);
                Ok(())
            }
            Err(e) => Err(TxPoolError::ValidationError(e.to_string())),
        }
    }

    pub async fn insert_and_broadcast(&self, tx_packed: &[u8]) -> Result<(), TxPoolError> {
        self.insert(tx_packed).await?;
        // TODO: Implement broadcast via NodeGen
        Ok(())
    }

    pub async fn purge_stale(&self) {
        let _cur_epoch = chain_epoch(self.db.as_ref());
        let mut pool = self.pool.write().await;

        // Remove transactions older than 1 epoch
        // TODO: TX doesn't have epoch field, need to implement proper epoch tracking
        pool.retain(|_key, _txu| {
            // For now, keep all transactions until we implement proper epoch tracking
            true
        });
    }

    pub fn validate_tx(&self, txu: &TxU, args: &mut ValidateTxArgs) -> Result<(), TxPoolError> {
        // Check nonce validity
        let signer_vec = txu.tx.signer.to_vec();
        let chain_nonce = args
            .batch_state
            .chain_nonces
            .get(&signer_vec)
            .cloned()
            .unwrap_or_else(|| chain_nonce(self.db.as_ref(), &txu.tx.signer).unwrap_or(0));

        if chain_nonce != 0 && txu.tx.nonce <= chain_nonce {
            return Err(TxPoolError::InvalidNonce { nonce: txu.tx.nonce, hash: txu.hash });
        }
        args.batch_state.chain_nonces.insert(signer_vec.clone(), txu.tx.nonce);

        // Check balance
        let balance = args
            .batch_state
            .balances
            .get(&signer_vec)
            .cloned()
            .unwrap_or_else(|| chain_balance(self.db.as_ref(), &txu.tx.signer));

        let exec_cost = base::exec_cost(args.epoch, txu);
        let fee = coin::to_cents(1);

        let new_balance = balance.saturating_sub(exec_cost).saturating_sub(fee);
        if balance < exec_cost + fee {
            return Err(TxPoolError::InsufficientBalance { nonce: txu.tx.nonce, hash: txu.hash });
        }
        args.batch_state.balances.insert(signer_vec, new_balance);

        // Validate solution if present
        for action in &txu.tx.actions {
            if action.function == "submit_sol" && !action.args.is_empty() {
                let sol_bytes = &action.args[0];
                if sol_bytes.len() >= 36 {
                    let sol_epoch = u32::from_le_bytes([sol_bytes[0], sol_bytes[1], sol_bytes[2], sol_bytes[3]]);
                    let sol_svrh = &sol_bytes[4..36];

                    if sol_epoch != args.epoch
                        || sol_svrh != &args.segment_vr_hash[..]
                        || sol_bytes.len() != sol::SOL_SIZE
                    {
                        return Err(TxPoolError::InvalidSol { nonce: txu.tx.nonce, hash: txu.hash });
                    }
                }
            }
        }

        Ok(())
    }

    pub fn validate_tx_batch(&self, txs_packed: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let chain_epoch = chain_epoch(self.db.as_ref());
        let segment_vr_hash = chain_segment_vr_hash();
        let diff_bits = chain_diff_bits();

        let mut args =
            ValidateTxArgs { epoch: chain_epoch, segment_vr_hash, diff_bits, batch_state: BatchState::default() };

        let mut good = Vec::new();
        for tx_packed in txs_packed {
            match validate(tx_packed, false) {
                Ok(txu) => {
                    if self.validate_tx(&txu, &mut args).is_ok() {
                        good.push(tx_packed.clone());
                    }
                }
                Err(_) => continue,
            }
        }

        good
    }

    pub async fn grab_next_valid(&self, amt: usize) -> Vec<Vec<u8>> {
        let chain_epoch = chain_epoch(self.db.as_ref());
        let segment_vr_hash = chain_segment_vr_hash();
        let diff_bits = chain_diff_bits();

        let mut args =
            ValidateTxArgs { epoch: chain_epoch, segment_vr_hash, diff_bits, batch_state: BatchState::default() };

        let mut result = Vec::new();
        let mut to_delete = Vec::new();

        let pool = self.pool.read().await;
        for (key, txu) in pool.iter() {
            if result.len() >= amt {
                break;
            }

            match self.validate_tx(txu, &mut args) {
                Ok(()) => {
                    result.push(pack(txu));
                }
                Err(_) => {
                    to_delete.push(key.clone());
                }
            }
        }
        drop(pool);

        // Delete stale transactions
        if !to_delete.is_empty() {
            let mut pool = self.pool.write().await;
            for key in to_delete {
                pool.remove(&key);
            }
        }

        result
    }

    pub async fn size(&self) -> usize {
        self.pool.read().await.len()
    }

    /// Delete transactions from pool by their packed representation
    /// Matches Elixir TXPool.delete_packed - removes transactions that were included in an entry
    pub async fn delete_packed(&self, txs_packed: &[Vec<u8>]) {
        if txs_packed.is_empty() {
            return;
        }

        let mut pool = self.pool.write().await;
        let mut removed_count = 0;

        for tx_packed in txs_packed {
            // try to unpack and validate to get the TxU structure
            if let Ok(txu) = validate(tx_packed, false) {
                // construct the key used for storage (nonce || hash)
                let key = vec![txu.tx.nonce.to_le_bytes().to_vec(), txu.hash.to_vec()].concat();
                if pool.remove(&key).is_some() {
                    removed_count += 1;
                }
            }
        }

        if removed_count > 0 {
            tracing::debug!("removed {} transactions from pool", removed_count);
        }
    }
}

// TODO: Need to implement proper segment_vr_hash and diff_bits accessors
// TODO: Need to implement broadcast functionality
// TODO: Need to implement proper TX packing/unpacking
