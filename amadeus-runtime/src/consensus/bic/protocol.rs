use crate::consensus::bic::coin;
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv;

//1 cent AMA per 1kb
pub fn tx_cost_per_byte(_epoch: u64, tx_encoded_len: usize) -> i128 {
    let bytes = tx_encoded_len + 32 + 96;
    // integer division
    let cost_units = 1 + (bytes / 1024) * 1;
    coin::to_cents(cost_units as i128)
}

pub fn pay_cost(env: &mut ApplyEnv, cost: i128) -> Result<(), &'static str> {
    // Deduct tx cost
    consensus_kv::kv_increment(
        env,
        &crate::bcat(&[b"bic:coin:balance:", env.caller_env.account_origin.as_slice(), b":AMA"]),
        -cost,
    )?;
    // Increment validator / burn
    consensus_kv::kv_increment(
        env,
        &crate::bcat(&[b"bic:coin:balance:", env.caller_env.entry_signer.as_slice(), b":AMA"]),
        cost / 2,
    )?;
    consensus_kv::kv_increment(env, &crate::bcat(&[b"bic:coin:balance:", &coin::BURN_ADDRESS, b":AMA"]), cost / 2)?;
    Ok(())
}
