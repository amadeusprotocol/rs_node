use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// WASM Host Function OP-codes matching Elixir BIC.Base.WASM.Safe implementation
/// These opcodes represent the bridge between WASM and host environment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum OpCode {
    // Storage operations (0x1000 range)
    StorageKvGet = 0x1000,
    StorageKvExists = 0x1001,
    StorageKvPut = 0x1002,
    StorageKvIncrement = 0x1003,
    StorageKvDelete = 0x1004,
    StorageKvClear = 0x1005,
    StorageKvGetPrev = 0x1006,
    StorageKvGetNext = 0x1007,
    StorageKvGetRange = 0x1008,

    // Environment operations (0x2000 range)
    EnvGetBlockHeight = 0x2000,
    EnvGetBlockEpoch = 0x2001,
    EnvGetBlockVr = 0x2002,
    EnvGetTxHash = 0x2003,
    EnvGetTxSigner = 0x2004,
    EnvGetEntrySigner = 0x2005,
    EnvGetAccountCurrent = 0x2006,
    EnvGetAccountCaller = 0x2007,
    EnvGetCallCounter = 0x2008,
    EnvGetExecPoints = 0x2009,
    EnvGetExecRemaining = 0x200A,
    EnvGetAttachedSymbol = 0x200B,
    EnvGetAttachedAmount = 0x200C,
    EnvGetSeed = 0x200D,
    EnvGetSeedF64 = 0x200E,
    EnvIsReadOnly = 0x200F,

    // Cross-contract operations (0x3000 range)
    CrossContractCall = 0x3000,
    CrossContractCallReadOnly = 0x3001,
    CrossContractDeploy = 0x3002,
    CrossContractGetBytecode = 0x3003,

    // Coin/Balance operations (0x4000 range)
    CoinGetBalance = 0x4000,
    CoinTransfer = 0x4001,
    CoinBurn = 0x4002,
    CoinMint = 0x4003,
    CoinGetSymbol = 0x4004,
    CoinGetTotalSupply = 0x4005,

    // Logging and debugging (0x5000 range)
    LogDebug = 0x5000,
    LogInfo = 0x5001,
    LogWarn = 0x5002,
    LogError = 0x5003,

    // Memory operations (0x6000 range)
    MemoryGrow = 0x6000,
    MemorySize = 0x6001,
    MemoryRead = 0x6002,
    MemoryWrite = 0x6003,

    // Cryptographic operations (0x7000 range)
    CryptoBlake3Hash = 0x7000,
    CryptoBlsVerify = 0x7001,
    CryptoBlsAggregate = 0x7002,
    CryptoAesEncrypt = 0x7003,
    CryptoAesDecrypt = 0x7004,

    // System operations (0x8000 range)
    SystemAbort = 0x8000,
    SystemReturn = 0x8001,
    SystemPanic = 0x8002,
    SystemGetGasUsed = 0x8003,
    SystemGetGasLimit = 0x8004,
}

impl OpCode {
    /// Get the name of the host function to import
    pub fn import_name(&self) -> &'static str {
        match self {
            // Storage
            OpCode::StorageKvGet => "storage_kv_get",
            OpCode::StorageKvExists => "storage_kv_exists",
            OpCode::StorageKvPut => "storage_kv_put",
            OpCode::StorageKvIncrement => "storage_kv_increment",
            OpCode::StorageKvDelete => "storage_kv_delete",
            OpCode::StorageKvClear => "storage_kv_clear",
            OpCode::StorageKvGetPrev => "storage_kv_get_prev",
            OpCode::StorageKvGetNext => "storage_kv_get_next",
            OpCode::StorageKvGetRange => "storage_kv_get_range",

            // Environment
            OpCode::EnvGetBlockHeight => "env_get_block_height",
            OpCode::EnvGetBlockEpoch => "env_get_block_epoch",
            OpCode::EnvGetBlockVr => "env_get_block_vr",
            OpCode::EnvGetTxHash => "env_get_tx_hash",
            OpCode::EnvGetTxSigner => "env_get_tx_signer",
            OpCode::EnvGetEntrySigner => "env_get_entry_signer",
            OpCode::EnvGetAccountCurrent => "env_get_account_current",
            OpCode::EnvGetAccountCaller => "env_get_account_caller",
            OpCode::EnvGetCallCounter => "env_get_call_counter",
            OpCode::EnvGetExecPoints => "env_get_exec_points",
            OpCode::EnvGetExecRemaining => "env_get_exec_remaining",
            OpCode::EnvGetAttachedSymbol => "env_get_attached_symbol",
            OpCode::EnvGetAttachedAmount => "env_get_attached_amount",
            OpCode::EnvGetSeed => "env_get_seed",
            OpCode::EnvGetSeedF64 => "env_get_seed_f64",
            OpCode::EnvIsReadOnly => "env_is_readonly",

            // Cross-contract
            OpCode::CrossContractCall => "cross_contract_call",
            OpCode::CrossContractCallReadOnly => "cross_contract_call_readonly",
            OpCode::CrossContractDeploy => "cross_contract_deploy",
            OpCode::CrossContractGetBytecode => "cross_contract_get_bytecode",

            // Coin
            OpCode::CoinGetBalance => "coin_get_balance",
            OpCode::CoinTransfer => "coin_transfer",
            OpCode::CoinBurn => "coin_burn",
            OpCode::CoinMint => "coin_mint",
            OpCode::CoinGetSymbol => "coin_get_symbol",
            OpCode::CoinGetTotalSupply => "coin_get_total_supply",

            // Logging
            OpCode::LogDebug => "log_debug",
            OpCode::LogInfo => "log_info",
            OpCode::LogWarn => "log_warn",
            OpCode::LogError => "log_error",

            // Memory
            OpCode::MemoryGrow => "memory_grow",
            OpCode::MemorySize => "memory_size",
            OpCode::MemoryRead => "memory_read",
            OpCode::MemoryWrite => "memory_write",

            // Crypto
            OpCode::CryptoBlake3Hash => "crypto_blake3_hash",
            OpCode::CryptoBlsVerify => "crypto_bls_verify",
            OpCode::CryptoBlsAggregate => "crypto_bls_aggregate",
            OpCode::CryptoAesEncrypt => "crypto_aes_encrypt",
            OpCode::CryptoAesDecrypt => "crypto_aes_decrypt",

            // System
            OpCode::SystemAbort => "system_abort",
            OpCode::SystemReturn => "system_return",
            OpCode::SystemPanic => "system_panic",
            OpCode::SystemGetGasUsed => "system_get_gas_used",
            OpCode::SystemGetGasLimit => "system_get_gas_limit",
        }
    }

    /// Get the module name for imports (matching Elixir "env" module)
    pub fn module_name(&self) -> &'static str {
        match self {
            OpCode::StorageKvGet
            | OpCode::StorageKvExists
            | OpCode::StorageKvPut
            | OpCode::StorageKvIncrement
            | OpCode::StorageKvDelete
            | OpCode::StorageKvClear
            | OpCode::StorageKvGetPrev
            | OpCode::StorageKvGetNext
            | OpCode::StorageKvGetRange => "bic",

            OpCode::EnvGetBlockHeight
            | OpCode::EnvGetBlockEpoch
            | OpCode::EnvGetBlockVr
            | OpCode::EnvGetTxHash
            | OpCode::EnvGetTxSigner
            | OpCode::EnvGetEntrySigner
            | OpCode::EnvGetAccountCurrent
            | OpCode::EnvGetAccountCaller
            | OpCode::EnvGetCallCounter
            | OpCode::EnvGetExecPoints
            | OpCode::EnvGetExecRemaining
            | OpCode::EnvGetAttachedSymbol
            | OpCode::EnvGetAttachedAmount
            | OpCode::EnvGetSeed
            | OpCode::EnvGetSeedF64
            | OpCode::EnvIsReadOnly => "env",

            OpCode::CrossContractCall
            | OpCode::CrossContractCallReadOnly
            | OpCode::CrossContractDeploy
            | OpCode::CrossContractGetBytecode => "bic",

            OpCode::CoinGetBalance
            | OpCode::CoinTransfer
            | OpCode::CoinBurn
            | OpCode::CoinMint
            | OpCode::CoinGetSymbol
            | OpCode::CoinGetTotalSupply => "bic",

            OpCode::LogDebug | OpCode::LogInfo | OpCode::LogWarn | OpCode::LogError => "env",

            OpCode::MemoryGrow | OpCode::MemorySize | OpCode::MemoryRead | OpCode::MemoryWrite => "env",

            OpCode::CryptoBlake3Hash
            | OpCode::CryptoBlsVerify
            | OpCode::CryptoBlsAggregate
            | OpCode::CryptoAesEncrypt
            | OpCode::CryptoAesDecrypt => "bic",

            OpCode::SystemAbort
            | OpCode::SystemReturn
            | OpCode::SystemPanic
            | OpCode::SystemGetGasUsed
            | OpCode::SystemGetGasLimit => "env",
        }
    }
}

/// RPC message for bidirectional communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcMessage {
    pub id: u64,
    pub opcode: OpCode,
    pub payload: RpcPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcPayload {
    // Storage operations
    StorageGet {
        key: String,
    },
    StorageExists {
        key: String,
    },
    StoragePut {
        key: String,
        value: Vec<u8>,
    },
    StorageIncrement {
        key: String,
        delta: i64,
    },
    StorageDelete {
        key: String,
    },
    StorageClear {
        prefix: String,
    },
    StorageGetPrev {
        suffix: String,
        key: String,
    },
    StorageGetNext {
        suffix: String,
        key: String,
    },
    StorageGetRange {
        prefix: String,
        limit: u32,
    },

    // Environment queries
    EnvQuery,

    // Cross-contract calls
    CrossCall {
        contract: Vec<u8>,
        function: String,
        args: Vec<Vec<u8>>,
        attached_symbol: Option<String>,
        attached_amount: Option<String>,
        exec_points: u64,
    },

    // Coin operations
    CoinQuery {
        account: Vec<u8>,
        symbol: String,
    },
    CoinTransfer {
        to: Vec<u8>,
        symbol: String,
        amount: String,
    },

    // Logging
    Log {
        level: String,
        message: String,
    },

    // Memory operations
    MemoryOp {
        operation: String,
        offset: u32,
        length: u32,
        data: Option<Vec<u8>>,
    },

    // Crypto operations
    CryptoOp {
        operation: String,
        data: Vec<u8>,
        extra: Option<Vec<u8>>,
    },

    // System operations
    SystemOp {
        operation: String,
        code: Option<i32>,
        message: Option<String>,
    },
}

/// RPC response from host to WASM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub id: u64,
    pub result: RpcResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcResult {
    Success(Vec<u8>),
    Error(String),
    Value(i64),
    Boolean(bool),
    Bytes(Vec<u8>),
    None,
}

/// WASM ABI types matching wasmer Value types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmType {
    I32,
    I64,
    F32,
    F64,
}

/// Host function signature
#[derive(Debug, Clone)]
pub struct HostFunctionSignature {
    pub opcode: OpCode,
    pub params: Vec<WasmType>,
    pub results: Vec<WasmType>,
}

impl HostFunctionSignature {
    pub fn new(opcode: OpCode, params: Vec<WasmType>, results: Vec<WasmType>) -> Self {
        Self { opcode, params, results }
    }
}

/// Generate all host function signatures
pub fn generate_host_signatures() -> HashMap<OpCode, HostFunctionSignature> {
    use WasmType::*;
    let mut signatures = HashMap::new();

    // Storage operations - most take pointer+len for key, return pointer+len for value
    signatures
        .insert(OpCode::StorageKvGet, HostFunctionSignature::new(OpCode::StorageKvGet, vec![I32, I32], vec![I32, I32]));
    signatures.insert(
        OpCode::StorageKvExists,
        HostFunctionSignature::new(OpCode::StorageKvExists, vec![I32, I32], vec![I32]),
    );
    signatures.insert(
        OpCode::StorageKvPut,
        HostFunctionSignature::new(OpCode::StorageKvPut, vec![I32, I32, I32, I32], vec![I32]),
    );
    signatures.insert(
        OpCode::StorageKvIncrement,
        HostFunctionSignature::new(OpCode::StorageKvIncrement, vec![I32, I32, I64], vec![I64]),
    );
    signatures.insert(
        OpCode::StorageKvDelete,
        HostFunctionSignature::new(OpCode::StorageKvDelete, vec![I32, I32], vec![I32]),
    );
    signatures
        .insert(OpCode::StorageKvClear, HostFunctionSignature::new(OpCode::StorageKvClear, vec![I32, I32], vec![I32]));

    // Environment operations - return various types
    signatures
        .insert(OpCode::EnvGetBlockHeight, HostFunctionSignature::new(OpCode::EnvGetBlockHeight, vec![], vec![I64]));
    signatures
        .insert(OpCode::EnvGetBlockEpoch, HostFunctionSignature::new(OpCode::EnvGetBlockEpoch, vec![], vec![I64]));
    signatures.insert(OpCode::EnvGetBlockVr, HostFunctionSignature::new(OpCode::EnvGetBlockVr, vec![I32], vec![I32]));
    signatures.insert(OpCode::EnvGetTxHash, HostFunctionSignature::new(OpCode::EnvGetTxHash, vec![I32], vec![I32]));
    signatures.insert(OpCode::EnvGetSeedF64, HostFunctionSignature::new(OpCode::EnvGetSeedF64, vec![], vec![F64]));
    signatures.insert(OpCode::EnvIsReadOnly, HostFunctionSignature::new(OpCode::EnvIsReadOnly, vec![], vec![I32]));

    // Cross-contract operations
    signatures.insert(
        OpCode::CrossContractCall,
        HostFunctionSignature::new(
            OpCode::CrossContractCall,
            vec![I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I64],
            vec![I32, I32],
        ),
    );

    // Logging operations
    signatures.insert(OpCode::LogDebug, HostFunctionSignature::new(OpCode::LogDebug, vec![I32, I32], vec![]));
    signatures.insert(OpCode::LogInfo, HostFunctionSignature::new(OpCode::LogInfo, vec![I32, I32], vec![]));

    // Memory operations
    signatures.insert(OpCode::MemoryGrow, HostFunctionSignature::new(OpCode::MemoryGrow, vec![I32], vec![I32]));
    signatures.insert(OpCode::MemorySize, HostFunctionSignature::new(OpCode::MemorySize, vec![], vec![I32]));

    // System operations
    signatures.insert(OpCode::SystemAbort, HostFunctionSignature::new(OpCode::SystemAbort, vec![I32, I32], vec![]));
    signatures.insert(OpCode::SystemReturn, HostFunctionSignature::new(OpCode::SystemReturn, vec![I32, I32], vec![]));

    signatures
}
