use crate::Result;
use crate::consensus::bic::coin;
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv;

pub const FORKHEIGHT: u64 = 435_00000;

pub const AMA_1_DOLLAR: i128 = 1_000_000_000;
pub const AMA_10_CENT: i128 = 100_000_000;
pub const AMA_1_CENT: i128 = 10_000_000;
pub const AMA_01_CENT: i128 = 1_000_000;

pub const RESERVE_AMA_PER_TX_EXEC: i128 = AMA_10_CENT;
pub const RESERVE_AMA_PER_TX_STORAGE: i128 = AMA_1_DOLLAR;

pub const COST_PER_BYTE_HISTORICAL: i128 = 6_666;
pub const COST_PER_BYTE_STATE: i128 = 16_666;
pub const COST_PER_OP_WASM: i128 = 1;

pub const COST_PER_DB_READ_BASE: i128 = 5_000 * 10;
pub const COST_PER_DB_READ_BYTE: i128 = 50 * 10;
pub const COST_PER_DB_WRITE_BASE: i128 = 25_000 * 10;
pub const COST_PER_DB_WRITE_BYTE: i128 = 250 * 10;

pub const COST_PER_CALL: i128 = AMA_01_CENT;
pub const COST_PER_DEPLOY: i128 = AMA_1_CENT;
pub const COST_PER_SOL: i128 = AMA_1_CENT;
pub const COST_PER_NEW_LEAF_MERKLE: i128 = COST_PER_BYTE_STATE * 128;

pub const LOG_MSG_SIZE: usize = 4096;
pub const LOG_TOTAL_SIZE: usize = 16384;
pub const LOG_TOTAL_ELEMENTS: usize = 32;
pub const WASM_MAX_PTR_LEN: usize = 1048576;
pub const WASM_MAX_PANIC_MSG_SIZE: usize = 128;

pub const MAX_DB_KEY_SIZE: usize = 512;
pub const MAX_DB_VALUE_SIZE: usize = 1048576;

pub const WASM_MAX_BINARY_SIZE: usize = 1048576;
pub const WASM_MAX_FUNCTIONS: u32 = 1000;
pub const WASM_MAX_GLOBALS: u32 = 100;
pub const WASM_MAX_EXPORTS: u32 = 50;
pub const WASM_MAX_IMPORTS: u32 = 50;

pub fn tx_cost_per_byte(_epoch: u64, tx_encoded_len: usize) -> i128 {
    let bytes = tx_encoded_len + 32 + 96;
    let cost_units = 1 + (bytes / 1024) * 1;
    coin::to_cents(cost_units as i128)
}

pub fn pay_cost(env: &mut ApplyEnv, cost: i128) -> Result<()> {
    // Deduct tx cost
    consensus_kv::kv_increment(
        env,
        &crate::bcat(&[b"account:", env.caller_env.account_origin.as_slice(), b":balance:AMA"]),
        -cost,
    )?;
    // Increment validator / burn
    consensus_kv::kv_increment(
        env,
        &crate::bcat(&[b"account:", env.caller_env.entry_signer.as_slice(), b":balance:AMA"]),
        cost / 2,
    )?;
    consensus_kv::kv_increment(
        env,
        &crate::bcat(&[b"account:", &coin::BURN_ADDRESS, b":balance:AMA"]),
        cost / 2,
    )?;
    Ok(())
}
