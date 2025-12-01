use crate::consensus::bic::coin::{balance, to_flat};
use crate::consensus::bic::epoch::TREASURY_DONATION_ADDRESS;
use crate::consensus::bic::lockup::create_lock;
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{kv_delete, kv_get, kv_increment, kv_put};
use crate::{Result, bcat};
use amadeus_utils::misc::list_of_binaries_to_vecpak;

/// Initialize PRIME token if it doesn't exist (called by call_lock)
fn init_prime_if_needed(env: &mut ApplyEnv) -> Result<()> {
    use crate::consensus::bic::coin::exists;
    if !exists(env, b"PRIME")? {
        kv_increment(env, b"coin:PRIME:totalSupply", 0)?;

        // Admin public key
        let v0: &[u8; 48] = &[
            149, 216, 55, 255, 29, 8, 239, 251, 139, 112, 30, 29, 199, 57, 90, 67, 198, 220, 101, 18, 228, 100, 100,
            241, 43, 213, 221, 230, 253, 58, 231, 1, 102, 166, 54, 66, 245, 148, 140, 44, 78, 56, 84, 12, 222, 205, 57,
            210,
        ];
        let admin = vec![v0.to_vec()];
        let term_admins = list_of_binaries_to_vecpak(admin);
        kv_put(env, b"coin:PRIME:permission", &term_admins)?;

        kv_put(env, b"coin:PRIME:mintable", b"true")?;
        kv_put(env, b"coin:PRIME:pausable", b"true")?;
        kv_put(env, b"coin:PRIME:soulbound", b"true")?;
    }
    Ok(())
}

/// Mint PRIME tokens to a receiver
fn mint_prime(env: &mut ApplyEnv, amount: i128, receiver: &[u8]) -> Result<()> {
    if amount <= 0 {
        return Err("invalid_amount");
    }
    kv_increment(env, &bcat(&[b"account:", receiver, b":balance:PRIME"]), amount)?;
    kv_increment(env, b"coin:PRIME:totalSupply", amount)?;
    Ok(())
}

/// Lock AMA tokens to receive PRIME points upon unlock
pub fn call_lock(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<()> {
    init_prime_if_needed(env)?;

    if args.len() != 2 {
        return Err("invalid_args");
    }
    let amount = args[0].as_slice();
    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).ok_or("invalid_amount")?;
    let tier = args[1].as_slice();

    let (tier_epochs, multiplier) = match tier {
        b"magic" => (0, 1),
        b"magic2" => (1, 1),
        b"7d" => (10, 13),
        b"30d" => (45, 17),
        b"90d" => (135, 27),
        b"180d" => (270, 35),
        b"365d" => (547, 54),
        _ => return Err("invalid_tier"),
    };

    if amount <= to_flat(1) {
        return Err("invalid_amount");
    }
    if amount > balance(env, env.caller_env.account_caller.as_slice(), b"AMA")? {
        return Err("insufficient_funds");
    }
    kv_increment(env, &bcat(&[b"account:", &env.caller_env.account_caller, b":balance:AMA"]), -amount)?;

    let vault_index = kv_increment(env, b"bic:lockup_prime:unique_index", 1)?;
    let vault_value = bcat(&[
        tier,
        b"-",
        multiplier.to_string().as_bytes(),
        b"-",
        (env.caller_env.entry_epoch.saturating_add(tier_epochs)).to_string().as_bytes(),
        b"-",
        amount.to_string().as_bytes(),
    ]);
    kv_put(
        env,
        &bcat(&[b"bic:lockup_prime:vault:", &env.caller_env.account_caller, b":", vault_index.to_string().as_bytes()]),
        &vault_value,
    )?;
    Ok(())
}

/// Unlock a PRIME vault - early unlock incurs 25% penalty
pub fn call_unlock(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<()> {
    if args.len() != 1 {
        return Err("invalid_args");
    }
    let vault_index = args[0].as_slice();

    let vault_key = bcat(&[b"bic:lockup_prime:vault:", &env.caller_env.account_caller, b":", vault_index]);

    let vault = kv_get(env, &vault_key)?.ok_or("invalid_vault")?;

    let vault_parts: Vec<Vec<u8>> = vault.split(|&b| b == b'-').map(|seg| seg.to_vec()).collect();
    if vault_parts.len() < 4 {
        return Err("invalid_vault_format");
    }

    // vault format: tier-multiplier-unlock_epoch-amount
    let multiplier =
        std::str::from_utf8(&vault_parts[1]).ok().and_then(|s| s.parse::<u64>().ok()).ok_or("invalid_multiplier")?;
    let unlock_epoch =
        std::str::from_utf8(&vault_parts[2]).ok().and_then(|s| s.parse::<u64>().ok()).ok_or("invalid_unlock_epoch")?;
    let unlock_amount =
        std::str::from_utf8(&vault_parts[3]).ok().and_then(|s| s.parse::<u64>().ok()).ok_or("invalid_unlock_amount")?;

    if env.caller_env.entry_epoch < unlock_epoch {
        // Early unlock: 25% penalty
        let penalty = unlock_amount / 4;
        let disbursement = unlock_amount - penalty;

        kv_increment(
            env,
            &bcat(&[b"account:", TREASURY_DONATION_ADDRESS.as_slice(), b":balance:AMA"]),
            penalty as i128,
        )?;
        // Lockup for 5 epochs
        create_lock(
            env,
            env.caller_env.account_caller.to_vec().as_slice(),
            b"AMA",
            disbursement as i128,
            env.caller_env.entry_epoch.saturating_add(5),
        )?;
    } else {
        // Normal unlock: receive PRIME points and original AMA
        let prime_points = unlock_amount * multiplier;
        mint_prime(env, prime_points as i128, env.caller_env.account_caller.to_vec().as_slice())?;
        kv_increment(
            env,
            &bcat(&[b"account:", &env.caller_env.account_caller, b":balance:AMA"]),
            unlock_amount as i128,
        )?;
    }

    kv_delete(env, &vault_key)?;
    Ok(())
}

/// Daily check-in for PRIME vaults - earn 1% bonus daily with streak bonuses
pub fn call_daily_checkin(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<()> {
    if args.len() != 1 {
        return Err("invalid_args");
    }
    let vault_index = args[0].as_slice();

    let vault_key = bcat(&[b"bic:lockup_prime:vault:", &env.caller_env.account_caller, b":", vault_index]);
    let vault = kv_get(env, &vault_key)?.ok_or("invalid_vault")?;
    let vault_parts: Vec<Vec<u8>> = vault.split(|&b| b == b'-').map(|seg| seg.to_vec()).collect();
    if vault_parts.len() < 4 {
        return Err("invalid_vault_format");
    }

    let unlock_amount =
        std::str::from_utf8(&vault_parts[3]).ok().and_then(|s| s.parse::<u64>().ok()).ok_or("invalid_unlock_amount")?;

    let next_checkin_key = bcat(&[b"bic:lockup_prime:next_checkin_epoch:", &env.caller_env.account_caller]);
    let next_checkin_epoch: u64 = kv_get(env, &next_checkin_key)?
        .map(|bytes| {
            std::str::from_utf8(&bytes).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(env.caller_env.entry_epoch)
        })
        .unwrap_or(env.caller_env.entry_epoch);

    let delta = (env.caller_env.entry_epoch as i64) - (next_checkin_epoch as i64);
    if delta == 0 || delta == 1 {
        kv_put(env, &next_checkin_key, env.caller_env.entry_epoch.saturating_add(2).to_string().as_bytes())?;

        let daily_bonus = unlock_amount / 100;
        mint_prime(env, daily_bonus as i128, env.caller_env.account_caller.to_vec().as_slice())?;

        let streak_key = bcat(&[b"bic:lockup_prime:daily_streak:", &env.caller_env.account_caller]);
        let streak = kv_increment(env, &streak_key, 1)?;
        if streak >= 30 {
            kv_put(env, &streak_key, b"0")?;
            let streak_bonus = daily_bonus * 30;
            mint_prime(env, streak_bonus as i128, env.caller_env.account_caller.to_vec().as_slice())?;
        }
    } else if delta > 2 {
        // Missed check-in, reset streak
        kv_put(env, &next_checkin_key, env.caller_env.entry_epoch.saturating_add(2).to_string().as_bytes())?;
        let streak_key = bcat(&[b"bic:lockup_prime:daily_streak:", &env.caller_env.account_caller]);
        kv_put(env, &streak_key, b"0")?;
    }
    // else: already checked in for the day (2 epoch window), do nothing

    Ok(())
}
