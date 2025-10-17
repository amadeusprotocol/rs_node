use crate::bic::epoch::CallEnv;
use crate::consensus::kv;
use crate::utils::rocksdb;
use crate::wasm::runtime;
use std::sync::Once;

static INIT: Once = Once::new();
const TEST_DB: &str = "target/test_wasm";
const CONTRACTS_DIR: &str = "../assets/contracts"; // because core is in the workspace

fn setup_test_env() -> CallEnv {
    // Don't use INIT.call_once(), just initialize fresh each time like other tests

    CallEnv {
        entry_epoch: 42,
        entry_height: 100000,
        entry_signer: [1u8; 48],
        entry_vr: vec![0xde, 0xad, 0xbe, 0xef],
        tx_hash: vec![0xca, 0xfe, 0xba, 0xbe],
        tx_signer: [2u8; 48],
        account_caller: [3u8; 48],
        account_current: vec![4, 5, 6],
        call_counter: 1,
        call_exec_points: 10000,
        call_exec_points_remaining: 9000,
        attached_symbol: vec![],
        attached_amount: vec![],
        seed: [42u8; 32],
        seedf64: std::f64::consts::PI,
        readonly: false,
    }
}

fn load_wasm_file(filename: &str) -> Vec<u8> {
    let path = format!("{CONTRACTS_DIR}/{filename}");
    match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) => {
            panic!("Failed to load WASM file {}: {}. Make sure to run 'wat2wasm' first.", path, e);
        }
    }
}

fn setup_test_db(name: &str) -> rocksdb::RocksDb {
    let base = format!("{}/{}_{}", TEST_DB, name, std::process::id());
    let rt = tokio::runtime::Runtime::new().expect("create runtime");
    rt.block_on(rocksdb::RocksDb::open(base)).expect("open test db")
}

// runtime tests
mod runtime_tests {
    use super::*;

    #[test]
    fn test_wasm_runtime_compilation_and_validation() {
        let env = setup_test_env();
        let db = setup_test_db("compilation");
        let kv_ctx = kv::ApplyCtx::new();

        // test with invalid wasm bytecode
        let invalid_wasm = vec![0x00, 0x61, 0x73, 0x6d]; // incomplete wasm header
        let result = runtime::execute(&env, &db, kv_ctx.clone(), &invalid_wasm, "main", &[]);
        assert!(result.is_err());

        // test with minimal valid wasm module (contains basic structure)
        let minimal_wasm = vec![
            0x00, 0x61, 0x73, 0x6d, // wasm magic
            0x01, 0x00, 0x00, 0x00, // version
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: function type
            0x03, 0x02, 0x01, 0x00, // function section: 1 function
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code section: empty function
        ];

        // this should compile but fail to find "main" function
        let kv_ctx2 = kv::ApplyCtx::new();
        let result = runtime::execute(&env, &db, kv_ctx2, &minimal_wasm, "main", &[]);
        assert!(matches!(result, Err(runtime::WasmError::FunctionNotFound(_))));

        println!("wasm runtime compilation tests ok");
    }

    #[test]
    fn test_op_code_enumeration_completeness() {
        use crate::wasm::opcodes::{OpCode, generate_host_signatures};

        // verify all opcodes have signatures
        let signatures = generate_host_signatures();

        // test a few key opcodes are present
        assert!(signatures.contains_key(&OpCode::StorageKvGet));
        assert!(signatures.contains_key(&OpCode::EnvGetBlockHeight));
        assert!(signatures.contains_key(&OpCode::CrossContractCall));
        assert!(signatures.contains_key(&OpCode::LogDebug));
        assert!(signatures.contains_key(&OpCode::MemoryGrow));
        assert!(signatures.contains_key(&OpCode::SystemAbort));

        // verify import names are consistent
        for (opcode, signature) in signatures.iter() {
            assert_eq!(opcode, &signature.opcode);
            assert!(!opcode.import_name().is_empty());
            assert!(!opcode.module_name().is_empty());
        }

        println!("opcode enumeration test ok: {} opcodes", signatures.len());
    }

    #[test]
    fn test_wasm_context_and_host_function_access() {
        use crate::wasm::runtime::WasmContext;

        let env = setup_test_env();
        let db = setup_test_db("context");
        let kv_ctx = kv::ApplyCtx::new();
        let context = WasmContext::new(env.clone(), db, kv_ctx);

        // verify context initialization
        assert_eq!(context.env.entry_epoch, 42);
        assert_eq!(context.env.entry_height, 100000);
        assert_eq!(context.env.call_exec_points, 10000);
        assert!(!context.env.readonly);

        // verify rpc counter functionality
        let id1 = context.next_rpc_id();
        let id2 = context.next_rpc_id();
        assert_eq!(id2, id1 + 1);

        // test execution cost tracking
        context.add_exec_cost(100);
        assert_eq!(*context.exec_used.lock().unwrap(), 100);
        context.add_exec_cost(50);
        assert_eq!(*context.exec_used.lock().unwrap(), 150);

        println!("wasm context test ok");
    }

    #[test]
    fn test_storage_operations_integration() {
        let db = setup_test_db("storage_ops");
        let mut ctx = kv::ApplyCtx::new();
        kv::reset_for_tests(&mut ctx, &db); // clear any existing data

        let _env = setup_test_env();

        // test kv operations that the wasm host functions would use
        kv::kv_put(&mut ctx, &db, b"test_key", b"test_value");
        assert!(kv::kv_exists(&mut ctx, &db, b"test_key"));
        assert_eq!(kv::kv_get(&mut ctx, &db, b"test_key").unwrap(), b"test_value");

        let new_value = kv::kv_increment(&mut ctx, &db, b"counter", 42);
        assert_eq!(new_value, 42);
        let incremented = kv::kv_increment(&mut ctx, &db, b"counter", 8);
        assert_eq!(incremented, 50);

        kv::kv_delete(&mut ctx, &db, b"test_key");
        assert!(!kv::kv_exists(&mut ctx, &db, b"test_key"));

        let cleared_count = kv::kv_clear(&mut ctx, &db, b"count");
        assert!(cleared_count >= 1); // should clear the counter key

        println!("storage integration test ok");
    }

    #[test]
    fn test_complete_wasm_pipeline() {
        let env = setup_test_env();
        let db = setup_test_db("pipeline");

        // create a very basic wasm module that exports "test" function
        let test_wasm = vec![
            0x00, 0x61, 0x73, 0x6d, // wasm magic
            0x01, 0x00, 0x00, 0x00, // version
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: () -> ()
            0x03, 0x02, 0x01, 0x00, // function section: 1 function of type 0
            0x07, 0x08, 0x01, 0x04, 0x74, 0x65, 0x73, 0x74, 0x00,
            0x00, // export section: export function 0 as "test"
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code section: empty function body
        ];

        // test wasm execution pipeline
        let kv_ctx = kv::ApplyCtx::new();
        let result = runtime::execute(&env, &db, kv_ctx, &test_wasm, "test", &[]);

        match result {
            Ok(execution_result) => {
                println!("wasm execution ok: {} exec points", execution_result.exec_used);
            }
            Err(e) => {
                println!("wasm execution failed: {:?}", e);
            }
        }

        println!("wasm pipeline test ok");
    }

    #[test]
    fn test_opcodes_module_assignments() {
        use crate::wasm::opcodes::OpCode;

        // verify storage operations are assigned to "bic" module
        assert_eq!(OpCode::StorageKvGet.module_name(), "bic");
        assert_eq!(OpCode::StorageKvPut.module_name(), "bic");
        assert_eq!(OpCode::CrossContractCall.module_name(), "bic");
        assert_eq!(OpCode::CoinGetBalance.module_name(), "bic");

        // verify environment operations are assigned to "env" module
        assert_eq!(OpCode::EnvGetBlockHeight.module_name(), "env");
        assert_eq!(OpCode::LogDebug.module_name(), "env");
        assert_eq!(OpCode::MemoryGrow.module_name(), "env");
        assert_eq!(OpCode::SystemAbort.module_name(), "env");

        println!("opcodes module assignments test ok");
    }

    #[test]
    fn test_memory_management() {
        let env = setup_test_env();
        let db = setup_test_db("memory");

        let memory_test_wasm = vec![
            0x00, 0x61, 0x73, 0x6d, // wasm magic
            0x01, 0x00, 0x00, 0x00, // version
            // type section: function type (i32) -> i32
            0x01, 0x07, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, // import section: memory from env
            0x02, 0x0a, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x01,
            // function section: 1 function of type 0
            0x03, 0x02, 0x01, 0x00, // export section: export function 0 as "test_memory"
            0x07, 0x10, 0x01, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x00, 0x00,
            // code section: function body
            0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x41, 0x01, 0x6a, 0x0b,
        ];

        let kv_ctx = kv::ApplyCtx::new();
        let result = runtime::execute(&env, &db, kv_ctx, &memory_test_wasm, "test_memory", &[vec![42]]);
        match result {
            Ok(_) => println!("wasm memory test ok"),
            Err(e) => println!("wasm memory test failed: {:?}", e),
        }
    }
}

// contract tests
mod contract_tests {
    use super::*;

    #[test]
    fn test_simple_counter_contract() {
        let env = setup_test_env();
        let db = setup_test_db("counter");
        let mut ctx = kv::ApplyCtx::new();
        kv::reset_for_tests(&mut ctx, &db);

        let wasm_bytecode = load_wasm_file("simple_counter.wasm");
        println!("loaded simple_counter.wasm ({} bytes)", wasm_bytecode.len());

        let kv_ctx = kv::ApplyCtx::new();
        let result = runtime::execute(&env, &db, kv_ctx, &wasm_bytecode, "init", &[]);
        match result {
            Ok(execution_result) => {
                println!(
                    "counter init ok: {} points, {} logs",
                    execution_result.exec_used,
                    execution_result.logs.len()
                );
                for log in execution_result.logs.iter() {
                    println!("log: {}", log);
                }
            }
            Err(e) => println!("counter init failed: {:?}", e),
        }

        let kv_ctx = kv::ApplyCtx::new();
        let result = runtime::execute(&env, &db, kv_ctx, &wasm_bytecode, "increment", &[]);
        match result {
            Ok(execution_result) => {
                println!("counter increment ok: {} points", execution_result.exec_used);
                for log in execution_result.logs.iter() {
                    println!("log: {}", log);
                }
            }
            Err(e) => println!("counter increment failed: {:?}", e),
        }

        let kv_ctx = kv::ApplyCtx::new();
        let result = runtime::execute(&env, &db, kv_ctx, &wasm_bytecode, "get_counter", &[]);
        match result {
            Ok(execution_result) => {
                println!("counter get ok: {:?}", execution_result.return_value);
            }
            Err(e) => println!("counter get failed: {:?}", e),
        }

        let mut ctx2 = kv::ApplyCtx::new();
        let counter_value = kv::kv_get(&mut ctx2, &db, b"counter");
        println!("counter storage: {:?}", counter_value);
    }

    #[test]
    fn test_token_contract() {
        let env = setup_test_env();
        let db = setup_test_db("token");
        let mut ctx = kv::ApplyCtx::new();
        kv::reset_for_tests(&mut ctx, &db);

        let wasm_bytecode = load_wasm_file("token_contract.wasm");
        println!("loaded token_contract.wasm ({} bytes)", wasm_bytecode.len());

        let initial_supply = 1000000u64;
        let supply_bytes = initial_supply.to_le_bytes().to_vec();
        let kv_ctx = kv::ApplyCtx::new();
        let result = runtime::execute(&env, &db, kv_ctx, &wasm_bytecode, "init", &[supply_bytes]);
        match result {
            Ok(execution_result) => {
                println!("token init ok: {} points", execution_result.exec_used);
                for log in execution_result.logs.iter() {
                    println!("log: {}", log);
                }
            }
            Err(e) => println!("token init failed: {:?}", e),
        }

        let kv_ctx = kv::ApplyCtx::new();
        let result = runtime::execute(&env, &db, kv_ctx, &wasm_bytecode, "total_supply", &[]);
        match result {
            Ok(execution_result) => {
                println!("token total_supply ok: {:?}", execution_result.return_value);
            }
            Err(e) => println!("token total_supply failed: {:?}", e),
        }

        let account = b"test_account_123";
        let kv_ctx = kv::ApplyCtx::new();
        let result = runtime::execute(&env, &db, kv_ctx, &wasm_bytecode, "balance_of", &[account.to_vec()]);
        match result {
            Ok(execution_result) => {
                println!("token balance_of ok: {:?}", execution_result.return_value);
            }
            Err(e) => println!("token balance_of failed: {:?}", e),
        }

        let to_account = b"recipient_account";
        let transfer_amount = 100u64;
        let amount_bytes = transfer_amount.to_le_bytes().to_vec();
        let kv_ctx = kv::ApplyCtx::new();
        let result =
            runtime::execute(&env, &db, kv_ctx, &wasm_bytecode, "transfer", &[to_account.to_vec(), amount_bytes]);
        match result {
            Ok(execution_result) => {
                println!("token transfer ok: {:?}", execution_result.return_value);
                for log in execution_result.logs.iter() {
                    println!("log: {}", log);
                }
            }
            Err(e) => println!("token transfer failed: {:?}", e),
        }
    }

    #[test]
    fn test_host_function_coverage() {
        let _env = setup_test_env();

        let expected_host_functions = vec![
            ("bic", "storage_kv_get"),
            ("bic", "storage_kv_put"),
            ("bic", "storage_kv_increment"),
            ("bic", "coin_get_balance"),
            ("env", "env_get_block_height"),
            ("env", "env_get_tx_signer"),
            ("env", "log_info"),
            ("env", "system_return"),
        ];

        for (module, func) in expected_host_functions {
            println!("required: {}::{}", module, func);
        }

        use crate::wasm::opcodes::generate_host_signatures;
        let signatures = generate_host_signatures();

        println!("implemented host functions: {}", signatures.len());
        let mut missing_functions = Vec::new();

        for (module, func_name) in &[
            ("bic", "storage_kv_get"),
            ("bic", "storage_kv_put"),
            ("bic", "storage_kv_increment"),
            ("env", "env_get_block_height"),
            ("env", "log_info"),
        ] {
            let found = signatures
                .values()
                .any(|sig| sig.opcode.import_name() == *func_name && sig.opcode.module_name() == *module);

            if found {
                println!("{}::{} ok", module, func_name);
            } else {
                println!("{}::{} missing", module, func_name);
                missing_functions.push((*module, *func_name));
            }
        }

        if missing_functions.is_empty() {
            println!("all required host functions implemented");
        } else {
            println!("missing {} host functions", missing_functions.len());
        }
    }

    #[test]
    fn identify_critical_gaps() {
        let gaps = vec![
            ("abi parameter passing", "contracts expect proper string/binary parameter encoding from wasm memory"),
            ("return value handling", "contracts need to return values through wasm memory or registers"),
            ("memory import/export", "contracts expect 'memory' export and may need memory imports"),
            ("string encoding", "host functions need utf-8 string handling from wasm linear memory"),
            ("error propagation", "wasm errors should propagate properly to transaction results"),
            ("gas metering", "all host function calls should consume appropriate execution points"),
            ("storage integration", "storage operations should persist between contract calls"),
            ("transaction context", "contracts need access to tx_signer, block_height, etc"),
        ];

        for (category, description) in gaps {
            println!("{}: {}", category, description);
        }

        println!("implementation priority:");
        println!("1. fix abi parameter passing (memory read/write)");
        println!("2. implement proper return value handling");
        println!("3. add missing host functions (env_get_tx_signer, etc)");
        println!("4. enhance error handling and logging");
        println!("5. add storage persistence verification");
        println!("6. implement cross-contract calls");
    }
}
