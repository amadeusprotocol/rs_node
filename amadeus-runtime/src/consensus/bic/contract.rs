use crate::bcat;
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{kv_get, kv_put};

pub fn call_deploy(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<(), &'static str> {
    if args.len() != 1 {
        return Err("invalid_args");
    }
    let wasmbytes = args[0].as_slice();
    kv_put(env, &bcat(&[b"bic:contract:account:", env.caller_env.account_caller.as_slice(), b":bytecode"]), wasmbytes)?;
    Ok(())
}

pub fn bytecode(env: &mut ApplyEnv, account: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
    kv_get(env, &bcat(&[b"bic:contract:account:", &account, b":bytecode"]))
}
