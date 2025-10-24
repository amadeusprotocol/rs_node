use crate::config::Config;
use crate::consensus::DST_TX;
use crate::utils::blake3;
use crate::utils::bls12_381;
use crate::utils::vanilla_ser::{self, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct TxAction {
    pub op: String,
    pub contract: Vec<u8>,
    pub function: String,
    pub args: Vec<Vec<u8>>,
    pub attached_symbol: Option<Vec<u8>>,
    pub attached_amount: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Tx {
    pub signer: [u8; 48],
    pub nonce: i128,
    pub actions: Vec<TxAction>,
}

#[derive(Debug, Clone)]
pub struct TxU {
    pub tx_encoded: Vec<u8>,
    pub hash: [u8; 32],
    pub signature: [u8; 96],
    pub tx: Tx,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong term type: {0}")]
    WrongType(&'static str),
    #[error("missing field: {0}")]
    Missing(&'static str),
    #[error("invalid hash")]
    InvalidHash,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("nonce not integer")]
    NonceNotInteger,
    #[error("nonce too high")]
    NonceTooHigh,
    #[error("actions must be list")]
    ActionsNotList,
    #[error("actions length must be 1")]
    ActionsLenNot1,
    #[error("op must be call")]
    OpMustBeCall,
    #[error("contract must be binary")]
    ContractMustBeBinary,
    #[error("function must be binary")]
    FunctionMustBeBinary,
    #[error("args must be list")]
    ArgsMustBeList,
    #[error("arg must be binary")]
    ArgMustBeBinary,
    #[error("invalid contract or function")]
    InvalidContractOrFunction,
    #[error("invalid module for special meeting")]
    InvalidModuleForSpecial,
    #[error("invalid function for special meeting")]
    InvalidFunctionForSpecial,
    #[error("attached_symbol must be binary")]
    AttachedSymbolMustBeBinary,
    #[error("attached_symbol wrong size")]
    AttachedSymbolWrongSize,
    #[error("attached_amount must be binary")]
    AttachedAmountMustBeBinary,
    #[error("attached_amount must be included")]
    AttachedAmountMustBeIncluded,
    #[error("attached_symbol must be included")]
    AttachedSymbolMustBeIncluded,
    #[error("tx not canonical")]
    TxNotCanonical,
    #[error("too large")]
    TooLarge,
    #[error(transparent)]
    VanillaSer(#[from] vanilla_ser::Error),
}

impl TxU {
    pub fn normalize_atoms(self) -> Self {
        self
    }

    pub fn exec_cost_from_len(&self) -> i128 {
        let bytes = self.tx_encoded.len() + 32 + 96;
        crate::bic::coin::to_cents((1 + bytes / 1024) as i128)
    }

    pub fn exec_cost(&self, _epoch: u32) -> i128 {
        self.exec_cost_from_len()
    }

    pub fn from_vanilla(tx_packed: &[u8]) -> Result<TxU, Error> {
        let outer_val = vanilla_ser::decode_all(tx_packed)?;
        let outer = match &outer_val {
            Value::Map(m) => m,
            _ => return Err(Error::WrongType("outer_map")),
        };
        let get_bytes = |m: &BTreeMap<Value, Value>, key: &'static str| -> Result<Vec<u8>, Error> {
            match m.get(&Value::Bytes(key.as_bytes().to_vec())) {
                Some(Value::Bytes(b)) => Ok(b.clone()),
                Some(_) => Err(Error::WrongType(key)),
                None => Err(Error::Missing(key)),
            }
        };
        let tx_encoded = get_bytes(outer, "tx_encoded")?;
        let hash = get_bytes(outer, "hash")?.try_into().map_err(|_| Error::WrongType("hash:32"))?;
        let signature = get_bytes(outer, "signature")?.try_into().map_err(|_| Error::WrongType("signature:96"))?;

        let inner_val = vanilla_ser::decode_all(&tx_encoded)?;
        let inner = match &inner_val {
            Value::Map(m) => m,
            _ => return Err(Error::WrongType("tx_map")),
        };

        let signer = get_bytes(inner, "signer")?.try_into().map_err(|_| Error::WrongType("signer:48"))?;
        let nonce = match inner.get(&Value::Bytes(b"nonce".to_vec())) {
            Some(Value::Int(i)) => *i,
            Some(_) => return Err(Error::NonceNotInteger),
            None => return Err(Error::Missing("nonce")),
        };

        let actions_val = match inner.get(&Value::Bytes(b"actions".to_vec())) {
            Some(v) => v,
            None => return Err(Error::Missing("actions")),
        };
        let actions_list = match actions_val {
            Value::List(list) => list,
            _ => return Err(Error::ActionsNotList),
        };

        let mut actions: Vec<TxAction> = Vec::with_capacity(actions_list.len());
        for a_val in actions_list {
            let amap = match a_val {
                Value::Map(m) => m,
                _ => return Err(Error::WrongType("action_map")),
            };
            let op_bytes = get_bytes(amap, "op")?;
            let op = String::from_utf8(op_bytes).map_err(|_| Error::WrongType("op_string"))?;
            let contract = get_bytes(amap, "contract")?;
            let function_bytes = get_bytes(amap, "function")?;
            let function = String::from_utf8(function_bytes).map_err(|_| Error::WrongType("function_string"))?;

            let args_v = amap.get(&Value::Bytes(b"args".to_vec())).ok_or(Error::Missing("args"))?;
            let args_l = match args_v {
                Value::List(l) => l,
                _ => return Err(Error::ArgsMustBeList),
            };
            let mut args: Vec<Vec<u8>> = Vec::with_capacity(args_l.len());
            for t in args_l {
                match t {
                    Value::Bytes(b) => args.push(b.clone()),
                    _ => return Err(Error::ArgMustBeBinary),
                }
            }

            let attached_symbol = match amap.get(&Value::Bytes(b"attached_symbol".to_vec())) {
                Some(Value::Bytes(b)) => Some(b.clone()),
                Some(_) => return Err(Error::AttachedSymbolMustBeBinary),
                None => None,
            };
            let attached_amount = match amap.get(&Value::Bytes(b"attached_amount".to_vec())) {
                Some(Value::Bytes(b)) => Some(b.clone()),
                Some(_) => return Err(Error::AttachedAmountMustBeBinary),
                None => None,
            };

            actions.push(TxAction { op, contract, function, args, attached_symbol, attached_amount });
        }

        let tx = Tx { signer, nonce, actions };
        Ok(TxU { tx_encoded, hash, signature, tx })
    }
}

fn is_ascii_eq(bytes: &[u8], s: &str) -> bool {
    std::str::from_utf8(bytes).map(|v| v == s).unwrap_or(false)
}

pub fn valid_pk(pk: &[u8]) -> bool {
    // accept burn address or any valid BLS public key
    if pk.len() == 48
        && let Ok(arr) = <&[u8; 48]>::try_from(pk)
        && arr == &crate::bic::coin::burn_address()
    {
        return true;
    }
    bls12_381::validate_public_key(pk).is_ok()
}

pub fn known_receivers(txu: &TxU) -> Vec<Vec<u8>> {
    if txu.tx.actions.is_empty() {
        return vec![];
    }
    let a = &txu.tx.actions[0];
    let c_is_coin = is_ascii_eq(&a.contract, "Coin");
    let f_is_transfer = a.function == "transfer";

    if c_is_coin && f_is_transfer {
        // cases:
        // [receiver, _amount]
        // ["AMA", receiver, _amount]
        // [receiver, _amount, _symbol]
        match a.args.as_slice() {
            [receiver, _amount] => {
                if valid_pk(receiver) {
                    return vec![receiver.clone()];
                }
            }
            [ama, receiver, _amount] if is_ascii_eq(ama, "AMA") => {
                if valid_pk(receiver) {
                    return vec![receiver.clone()];
                }
            }
            [receiver, _amount, _symbol] => {
                if valid_pk(receiver) {
                    return vec![receiver.clone()];
                }
            }
            _ => {}
        }
    }

    if is_ascii_eq(&a.contract, "Epoch") && a.function == "slash_trainer" && a.args.len() >= 2 {
        let malicious_pk = &a.args[1];
        if valid_pk(malicious_pk) {
            return vec![malicious_pk.clone()];
        }
    }

    vec![]
}

pub fn validate_basic(tx_packed: &[u8], is_special_meeting_block: bool) -> Result<TxU, Error> {
    // Size check - match Elixir's tx_size application config (default reasonable limit)
    const DEFAULT_TX_SIZE: usize = 100_000; // Can be made configurable later
    if tx_packed.len() >= DEFAULT_TX_SIZE {
        return Err(Error::TooLarge);
    }

    let txu = TxU::from_vanilla(tx_packed)?;

    // Canonical validation - reconstruct and compare
    let canonical = pack(&txu);
    if tx_packed != canonical.as_slice() {
        return Err(Error::TxNotCanonical);
    }

    // compute canonical hash of tx_encoded
    let h = blake3::hash(&txu.tx_encoded);
    if txu.hash.as_slice() != h.as_ref() {
        return Err(Error::InvalidHash);
    }

    // verify signature over hash with DST_TX
    bls12_381::verify(&txu.tx.signer, &txu.signature, &h, DST_TX).map_err(|_| Error::InvalidSignature)?;

    // nonce validation to match Elixir reference
    if txu.tx.nonce > 99_999_999_999_999_999_999_i128 {
        return Err(Error::NonceTooHigh);
    }

    // actions checks
    if txu.tx.actions.is_empty() {
        return Err(Error::ActionsNotList);
    }
    if txu.tx.actions.len() != 1 {
        return Err(Error::ActionsLenNot1);
    }
    let a = &txu.tx.actions[0];

    if a.op != "call" {
        return Err(Error::OpMustBeCall);
    }
    if a.contract.is_empty() {
        return Err(Error::ContractMustBeBinary);
    }
    if a.function.is_empty() {
        return Err(Error::FunctionMustBeBinary);
    }

    // args already validated as binaries during unpack

    // contract/function validity
    let allowed_contract =
        is_ascii_eq(&a.contract, "Epoch") || is_ascii_eq(&a.contract, "Coin") || is_ascii_eq(&a.contract, "Contract");
    let allowed_function = a.function == "submit_sol"
        || a.function == "transfer"
        || a.function == "set_emission_address"
        || a.function == "slash_trainer"
        || a.function == "deploy";

    let valid_contract_fn =
        if allowed_contract { allowed_function } else { bls12_381::validate_public_key(&a.contract).is_ok() };
    if !valid_contract_fn {
        return Err(Error::InvalidContractOrFunction);
    }

    if is_special_meeting_block {
        if !is_ascii_eq(&a.contract, "Epoch") {
            return Err(Error::InvalidModuleForSpecial);
        }
        if a.function != "slash_trainer" {
            return Err(Error::InvalidFunctionForSpecial);
        }
    }

    // attachments
    if let Some(sym) = &a.attached_symbol {
        // must be binary and 1..32
        if sym.is_empty() || sym.len() > 32 {
            return Err(Error::AttachedSymbolWrongSize);
        }
        if a.attached_amount.is_none() {
            return Err(Error::AttachedAmountMustBeIncluded);
        }
    }
    if a.attached_amount.is_some() && a.attached_symbol.is_none() {
        return Err(Error::AttachedSymbolMustBeIncluded);
    }

    Ok(txu)
}

/// Validate wrapper delegating to validate_basic
pub fn validate(tx_packed: &[u8], is_special_meeting_block: bool) -> Result<TxU, Error> {
    validate_basic(tx_packed, is_special_meeting_block)
}

/// Pack a parsed TxU back into a binary (ETF). Uses VanillaSer-compatible encoder.
pub fn pack(txu: &TxU) -> Vec<u8> {
    // Build action maps
    let actions_list = txu
        .tx
        .actions
        .iter()
        .map(|action| {
            let mut action_map = BTreeMap::new();
            action_map.insert(Value::Bytes(b"op".to_vec()), Value::Bytes(action.op.as_bytes().to_vec()));
            action_map.insert(Value::Bytes(b"contract".to_vec()), Value::Bytes(action.contract.clone()));
            action_map.insert(Value::Bytes(b"function".to_vec()), Value::Bytes(action.function.as_bytes().to_vec()));
            let args_list = Value::List(action.args.iter().map(|a| Value::Bytes(a.clone())).collect());
            action_map.insert(Value::Bytes(b"args".to_vec()), args_list);

            if let Some(sym) = &action.attached_symbol {
                action_map.insert(Value::Bytes(b"attached_symbol".to_vec()), Value::Bytes(sym.clone()));
            }
            if let Some(amt) = &action.attached_amount {
                action_map.insert(Value::Bytes(b"attached_amount".to_vec()), Value::Bytes(amt.clone()));
            }

            Value::Map(action_map)
        })
        .collect();

    // Build inner tx map
    let mut tx_map = BTreeMap::new();
    tx_map.insert(Value::Bytes(b"signer".to_vec()), Value::Bytes(txu.tx.signer.to_vec()));
    tx_map.insert(Value::Bytes(b"nonce".to_vec()), Value::Int(txu.tx.nonce as i128));
    tx_map.insert(Value::Bytes(b"actions".to_vec()), Value::List(actions_list));

    let tx_encoded = vanilla_ser::encode(&Value::Map(tx_map));

    // Build outer map
    let mut outer_map = BTreeMap::new();
    outer_map.insert(Value::Bytes(b"tx_encoded".to_vec()), Value::Bytes(tx_encoded));
    outer_map.insert(Value::Bytes(b"hash".to_vec()), Value::Bytes(txu.hash.to_vec()));
    outer_map.insert(Value::Bytes(b"signature".to_vec()), Value::Bytes(txu.signature.to_vec()));

    vanilla_ser::encode(&Value::Map(outer_map))
}

/// Build and sign a transaction like Elixir TX.build/7. TODO: needs VanillaSer and BLS signing.
pub fn build(
    config: &Config,
    contract: &[u8],
    function: &str,
    args: &[Vec<u8>],
    nonce: Option<i64>,
    attached_symbol: Option<&[u8]>,
    attached_amount: Option<&[u8]>,
) -> Vec<u8> {
    // choose nonce: Elixir uses :os.system_time(:nanosecond)
    let nonce_val: i128 = match nonce {
        Some(n) => n as i128,
        None => crate::utils::misc::get_unix_nanos_now() as i128,
    };

    // Build action map
    let mut action_map = BTreeMap::new();
    action_map.insert(Value::Bytes(b"op".to_vec()), Value::Bytes(b"call".to_vec()));
    action_map.insert(Value::Bytes(b"contract".to_vec()), Value::Bytes(contract.to_vec()));
    action_map.insert(Value::Bytes(b"function".to_vec()), Value::Bytes(function.as_bytes().to_vec()));
    let args_list = Value::List(args.iter().map(|a| Value::Bytes(a.clone())).collect());
    action_map.insert(Value::Bytes(b"args".to_vec()), args_list);
    if let (Some(sym), Some(amt)) = (attached_symbol, attached_amount) {
        action_map.insert(Value::Bytes(b"attached_symbol".to_vec()), Value::Bytes(sym.to_vec()));
        action_map.insert(Value::Bytes(b"attached_amount".to_vec()), Value::Bytes(amt.to_vec()));
    }

    // Build inner tx map
    let mut tx_map = BTreeMap::new();
    tx_map.insert(Value::Bytes(b"signer".to_vec()), Value::Bytes(config.get_pk().to_vec()));
    tx_map.insert(Value::Bytes(b"nonce".to_vec()), Value::Int(nonce_val));
    tx_map.insert(Value::Bytes(b"actions".to_vec()), Value::List(vec![Value::Map(action_map)]));

    let tx_encoded = vanilla_ser::encode(&Value::Map(tx_map));
    let hash = blake3::hash(&tx_encoded);

    // Sign hash with DST_TX
    let signature = bls12_381::sign(&config.get_sk(), &hash, DST_TX).expect("failed to sign tx");

    // Build outer map
    let mut outer_map = BTreeMap::new();
    outer_map.insert(Value::Bytes(b"tx_encoded".to_vec()), Value::Bytes(tx_encoded));
    outer_map.insert(Value::Bytes(b"hash".to_vec()), Value::Bytes(hash.to_vec()));
    outer_map.insert(Value::Bytes(b"signature".to_vec()), Value::Bytes(signature.to_vec()));

    vanilla_ser::encode(&Value::Map(outer_map))
}

/// Chain-level validity checks (nonce, balance, epoch) - matches Elixir TX.chain_valid/1
pub fn chain_valid_txu(db: &crate::utils::rocksdb::RocksDb, txu: &TxU) -> bool {
    // elixir logic:
    // chainNonce = Consensus.chain_nonce(txu.tx.signer)
    // nonceValid = !chainNonce or txu.tx.nonce > chainNonce
    let chain_nonce = crate::consensus::chain_nonce(db, &txu.tx.signer);
    let nonce_valid = match chain_nonce {
        None => true,
        Some(n) => txu.tx.nonce > n,
    };

    // hasBalance = BIC.Base.exec_cost(txu) <= Consensus.chain_balance(txu.tx.signer)
    let has_balance =
        txu.exec_cost(crate::consensus::chain_epoch(db)) as i128 <= crate::consensus::chain_balance(db, &txu.tx.signer);

    // hasSol / epochSolValid
    let mut epoch_sol_valid = true;
    if let Some(action) = txu.tx.actions.first()
        && action.function == "submit_sol"
        && let Some(first_arg) = action.args.first()
        && first_arg.len() >= 4
    {
        let sol_epoch = u32::from_le_bytes([first_arg[0], first_arg[1], first_arg[2], first_arg[3]]);
        epoch_sol_valid = crate::consensus::chain_epoch(db) as u32 == sol_epoch;
    }

    epoch_sol_valid && nonce_valid && has_balance
}

/// Chain-level validity checks - equivalent to Elixir TX.chain_valid/1
/// Can accept either packed transaction bytes or unpacked TxU
pub fn chain_valid(db: &crate::utils::rocksdb::RocksDb, tx_input: &[u8]) -> bool {
    match unpack(tx_input) {
        Ok(txu) => chain_valid_txu(db, &txu),
        Err(_) => false,
    }
}

/// Unpack a transaction from binary format - equivalent to Elixir TX.unpack/1
pub fn unpack(tx_packed: &[u8]) -> Result<TxU, Error> {
    let txu = TxU::from_vanilla(tx_packed)?;
    Ok(txu.normalize_atoms())
}
