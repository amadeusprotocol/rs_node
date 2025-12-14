use crate::Result;
use crate::bcat;
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{kv_get, kv_put};

/// Validate WASM bytecode - basic validation of magic number and version
pub fn validate(wasm: &[u8]) -> Result<()> {
    // Check WASM magic number (0x00, 0x61, 0x73, 0x6d)
    if wasm.len() < 8 {
        return Err("wasm_too_small");
    }
    if &wasm[0..4] != b"\x00asm" {
        return Err("invalid_wasm_magic");
    }
    // Check version (0x01, 0x00, 0x00, 0x00)
    if &wasm[4..8] != b"\x01\x00\x00\x00" {
        return Err("invalid_wasm_version");
    }
    Ok(())
}

pub fn call_deploy(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<()> {
    if args.len() != 1 {
        return Err("invalid_args");
    }
    let wasmbytes = args[0].as_slice();

    // Validate WASM before storing
    validate(wasmbytes)?;

    kv_put(env, &bcat(&[b"account:", env.caller_env.account_caller.as_slice(), b":attribute:bytecode"]), wasmbytes)?;
    Ok(())
}

pub fn bytecode(env: &mut ApplyEnv, account: &[u8]) -> Result<Option<Vec<u8>>> {
    kv_get(env, &bcat(&[b"account:", &account, b":attribute:bytecode"]))
}

/// Dispatch contract module calls
pub fn call(env: &mut ApplyEnv, function: &str, args: &[Vec<u8>]) -> Result<()> {
    match function {
        "deploy" => call_deploy(env, args.to_vec()),
        _ => Err("invalid_function"),
    }
}
