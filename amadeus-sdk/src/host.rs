pub mod bic {
    #[link(wasm_import_module = "bic")]
    unsafe extern "C" {
        #[link_name = "storage_kv_get"]
        pub fn storage_kv_get(key_ptr: i32, key_len: i32) -> u64;

        #[link_name = "storage_kv_put"]
        pub fn storage_kv_put(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32;

        #[link_name = "storage_kv_delete"]
        pub fn storage_kv_delete(key_ptr: i32, key_len: i32) -> i32;

        #[link_name = "storage_kv_exists"]
        pub fn storage_kv_exists(key_ptr: i32, key_len: i32) -> i32;

        #[link_name = "storage_kv_increment"]
        pub fn storage_kv_increment(key_ptr: i32, key_len: i32, delta: i64) -> i64;

        #[link_name = "storage_kv_get_next"]
        pub fn storage_kv_get_next(
            prefix_ptr: i32,
            prefix_len: i32,
            key_ptr: i32,
            key_len: i32,
            out_key_ptr: i32,
            out_value_ptr: i32,
        ) -> u64;

        #[link_name = "coin_get_balance"]
        pub fn coin_get_balance(
            account_ptr: i32,
            account_len: i32,
            symbol_ptr: i32,
            symbol_len: i32,
        ) -> i64;

        #[link_name = "coin_transfer"]
        pub fn coin_transfer(
            to_ptr: i32,
            to_len: i32,
            symbol_ptr: i32,
            symbol_len: i32,
            amount: i64,
        ) -> i32;
    }
}

pub mod env {
    #[link(wasm_import_module = "env")]
    unsafe extern "C" {
        #[link_name = "env_get_block_height"]
        pub fn env_get_block_height() -> u64;

        #[link_name = "env_get_block_timestamp"]
        pub fn env_get_block_timestamp() -> u64;

        #[link_name = "env_get_epoch"]
        pub fn env_get_epoch() -> u64;

        #[link_name = "env_get_slot"]
        pub fn env_get_slot() -> u64;

        #[link_name = "env_get_tx_signer"]
        pub fn env_get_tx_signer(out_ptr: i32) -> i32;

        #[link_name = "env_get_tx_hash"]
        pub fn env_get_tx_hash(out_ptr: i32) -> i32;

        #[link_name = "env_get_caller"]
        pub fn env_get_caller(out_ptr: i32) -> i32;

        #[link_name = "env_get_self"]
        pub fn env_get_self(out_ptr: i32) -> i32;

        #[link_name = "env_get_attached_amount"]
        pub fn env_get_attached_amount() -> i64;

        #[link_name = "env_get_attached_symbol"]
        pub fn env_get_attached_symbol(out_ptr: i32) -> i32;

        #[link_name = "env_get_random_seed"]
        pub fn env_get_random_seed(out_ptr: i32) -> i32;

        #[link_name = "env_get_random_f64"]
        pub fn env_get_random_f64() -> f64;

        #[link_name = "env_get_remaining_gas"]
        pub fn env_get_remaining_gas() -> u64;

        #[link_name = "log_info"]
        pub fn log_info(msg_ptr: i32, msg_len: i32);

        #[link_name = "log_warn"]
        pub fn log_warn(msg_ptr: i32, msg_len: i32);

        #[link_name = "log_error"]
        pub fn log_error(msg_ptr: i32, msg_len: i32);

        #[link_name = "system_return"]
        pub fn system_return(data_ptr: i32, data_len: i32);

        #[link_name = "system_revert"]
        pub fn system_revert(msg_ptr: i32, msg_len: i32) -> !;

        #[link_name = "emit_event"]
        pub fn emit_event(name_ptr: i32, name_len: i32, data_ptr: i32, data_len: i32);

        #[link_name = "hash_blake3"]
        pub fn hash_blake3(data_ptr: i32, data_len: i32, out_ptr: i32);

        #[link_name = "verify_bls_signature"]
        pub fn verify_bls_signature(
            msg_ptr: i32,
            msg_len: i32,
            sig_ptr: i32,
            pubkey_ptr: i32,
        ) -> i32;

        #[link_name = "call_contract"]
        pub fn call_contract(
            contract_ptr: i32,
            function_ptr: i32,
            function_len: i32,
            args_ptr: i32,
            args_len: i32,
            out_ptr: i32,
        ) -> i32;
    }
}
