#![no_std]
#![no_main]

extern crate alloc;

use amadeus_sdk::prelude::*;
use amadeus_sdk::storage::StorageMap;
use amadeus_sdk::{env, storage};

const TOTAL_SUPPLY_KEY: &[u8] = b"total_supply";
const NAME_KEY: &[u8] = b"name";
const SYMBOL_KEY: &[u8] = b"symbol";
const OWNER_KEY: &[u8] = b"owner";

static BALANCES: StorageMap<[u8; 48], u64> = StorageMap::new(b"balance:");

#[unsafe(no_mangle)]
pub extern "C" fn init() {
    let caller = env::tx_signer();

    storage::put_string(NAME_KEY, "Example Token");
    storage::put_string(SYMBOL_KEY, "EXT");
    storage::put(OWNER_KEY, caller.as_bytes());

    let initial_supply: u64 = 1_000_000;
    storage::put_u64(TOTAL_SUPPLY_KEY, initial_supply);
    BALANCES.insert(&caller.0, initial_supply);

    env::emit_event_str("TokenCreated", "Example Token created");
    env::log(&format!("Token initialized with {} supply to {}", initial_supply, caller));
}

#[unsafe(no_mangle)]
pub extern "C" fn name() {
    if let Some(name) = storage::get_string(NAME_KEY) {
        env::return_string(&name);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn symbol() {
    if let Some(symbol) = storage::get_string(SYMBOL_KEY) {
        env::return_string(&symbol);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn total_supply() -> u64 {
    storage::get_u64(TOTAL_SUPPLY_KEY).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn balance_of(account_ptr: *const u8) -> u64 {
    let account = unsafe {
        let mut arr = [0u8; 48];
        core::ptr::copy_nonoverlapping(account_ptr, arr.as_mut_ptr(), 48);
        arr
    };
    BALANCES.get(&account).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn transfer(to_ptr: *const u8, amount: u64) -> i32 {
    let caller = env::tx_signer();
    let to = unsafe {
        let mut arr = [0u8; 48];
        core::ptr::copy_nonoverlapping(to_ptr, arr.as_mut_ptr(), 48);
        arr
    };

    let from_balance = BALANCES.get(&caller.0).unwrap_or(0);
    if from_balance < amount {
        env::log_error("Insufficient balance");
        return -1;
    }

    BALANCES.insert(&caller.0, from_balance - amount);
    let to_balance = BALANCES.get(&to).unwrap_or(0);
    BALANCES.insert(&to, to_balance + amount);

    env::emit_event("Transfer", &[caller.as_bytes(), &to, &amount.to_le_bytes()].concat());
    env::log(&format!("Transferred {} tokens", amount));

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn mint(to_ptr: *const u8, amount: u64) -> i32 {
    let caller = env::tx_signer();

    if let Some(owner_bytes) = storage::get(OWNER_KEY) {
        let owner = Address::from_bytes(&owner_bytes).unwrap_or_default();
        if caller != owner {
            env::log_error("Only owner can mint");
            return -1;
        }
    } else {
        env::log_error("Contract not initialized");
        return -1;
    }

    let to = unsafe {
        let mut arr = [0u8; 48];
        core::ptr::copy_nonoverlapping(to_ptr, arr.as_mut_ptr(), 48);
        arr
    };

    let current_supply = storage::get_u64(TOTAL_SUPPLY_KEY).unwrap_or(0);
    storage::put_u64(TOTAL_SUPPLY_KEY, current_supply + amount);

    let balance = BALANCES.get(&to).unwrap_or(0);
    BALANCES.insert(&to, balance + amount);

    env::emit_event("Mint", &[to.as_slice(), amount.to_le_bytes().as_slice()].concat());
    env::log(&format!("Minted {} tokens", amount));

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn burn(amount: u64) -> i32 {
    let caller = env::tx_signer();

    let balance = BALANCES.get(&caller.0).unwrap_or(0);
    if balance < amount {
        env::log_error("Insufficient balance to burn");
        return -1;
    }

    BALANCES.insert(&caller.0, balance - amount);

    let current_supply = storage::get_u64(TOTAL_SUPPLY_KEY).unwrap_or(0);
    storage::put_u64(TOTAL_SUPPLY_KEY, current_supply - amount);

    env::emit_event("Burn", &[caller.as_bytes(), &amount.to_le_bytes()].concat());
    env::log(&format!("Burned {} tokens", amount));

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn owner() {
    if let Some(owner_bytes) = storage::get(OWNER_KEY) {
        env::return_data(&owner_bytes);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn transfer_ownership(new_owner_ptr: *const u8) -> i32 {
    let caller = env::tx_signer();

    if let Some(owner_bytes) = storage::get(OWNER_KEY) {
        let owner = Address::from_bytes(&owner_bytes).unwrap_or_default();
        if caller != owner {
            env::log_error("Only owner can transfer ownership");
            return -1;
        }
    } else {
        env::log_error("Contract not initialized");
        return -1;
    }

    let new_owner = unsafe {
        let mut arr = [0u8; 48];
        core::ptr::copy_nonoverlapping(new_owner_ptr, arr.as_mut_ptr(), 48);
        arr
    };

    storage::put(OWNER_KEY, &new_owner);
    env::emit_event("OwnershipTransferred", &[caller.as_bytes(), &new_owner].concat());
    env::log("Ownership transferred");

    0
}
