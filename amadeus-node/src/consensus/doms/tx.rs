use crate::config::Config;
use crate::consensus::DST_TX;
use crate::utils::bls12_381;
use crate::utils::{Hash, PublicKey, Signature};
use amadeus_utils::vecpak;
use sha2::{Digest, Sha256};

mod args_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(args: &[Vec<u8>], ser: S) -> Result<S::Ok, S::Error> {
        let v: Vec<serde_bytes::ByteBuf> = args.iter().map(|a| serde_bytes::ByteBuf::from(a.clone())).collect();
        v.serialize(ser)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let v: Vec<serde_bytes::ByteBuf> = Deserialize::deserialize(de)?;
        Ok(v.into_iter().map(|b| b.into_vec()).collect())
    }
}

mod serde_bytes_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(opt: &Option<Vec<u8>>, ser: S) -> Result<S::Ok, S::Error> {
        match opt {
            Some(v) => serde_bytes::ByteBuf::from(v.clone()).serialize(ser),
            None => ser.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<serde_bytes::ByteBuf> = Deserialize::deserialize(de)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxAction {
    #[serde(with = "args_serde")]
    pub args: Vec<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub contract: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub function: Vec<u8>,
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes_option", default)]
    pub attached_symbol: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes_option", default)]
    pub attached_amount: Option<Vec<u8>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Tx {
    pub action: TxAction,
    pub nonce: i128,
    pub signer: PublicKey,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxU {
    pub hash: Hash,
    pub signature: Signature,
    pub tx: Tx,
}

pub type EntryTxAction = TxAction;
pub type EntryTxInner = Tx;
pub type EntryTx = TxU;

impl TxU {
    pub fn tx_encoded(&self) -> Vec<u8> {
        vecpak::to_vec(&self.tx).unwrap_or_default()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong term type: {0}")]
    WrongType(&'static str),
    #[error("invalid hash")]
    InvalidHash,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("nonce too high")]
    NonceTooHigh,
    #[error("op must be call")]
    OpMustBeCall,
    #[error("contract must be binary")]
    ContractMustBeBinary,
    #[error("function must be binary")]
    FunctionMustBeBinary,
    #[error("invalid module for special meeting")]
    InvalidModuleForSpecial,
    #[error("invalid function for special meeting")]
    InvalidFunctionForSpecial,
    #[error("attached_symbol wrong size")]
    AttachedSymbolWrongSize,
    #[error("attached_amount must be included")]
    AttachedAmountMustBeIncluded,
    #[error("attached_symbol must be included")]
    AttachedSymbolMustBeIncluded,
    #[error("too large")]
    TooLarge,
}

impl TxU {
    pub fn exec_cost_from_len(&self) -> i128 {
        let bytes = self.tx_encoded().len() + 32 + 96;
        amadeus_runtime::consensus::bic::coin::to_cents((1 + bytes / 1024) as i128)
    }

    pub fn exec_cost(&self, _epoch: u32) -> i128 {
        self.exec_cost_from_len()
    }

    pub fn contract_bytes(&self) -> Vec<u8> {
        self.tx.action.contract.clone()
    }
}

pub fn valid_pk(pk: &[u8]) -> bool {
    if pk.len() == 48 && pk == amadeus_runtime::consensus::bic::coin::BURN_ADDRESS {
        return true;
    }
    bls12_381::validate_public_key(pk).is_ok()
}

pub fn known_receivers(txu: &TxU) -> Vec<Vec<u8>> {
    let a = &txu.tx.action;
    let c = a.contract.as_slice();
    let f = a.function.as_slice();
    match (c, f, a.args.as_slice()) {
        (b"Coin", b"transfer", [receiver, _amount, _symbol]) if valid_pk(receiver) => vec![receiver.clone()],
        (b"Epoch", b"slash_trainer", [_epoch, malicious_pk, _sig, _mask_size, _mask]) if valid_pk(malicious_pk) => {
            vec![malicious_pk.clone()]
        }
        _ => vec![],
    }
}

pub fn validate_basic(tx_packed: &[u8], is_special_meeting_block: bool) -> Result<TxU, Error> {
    const DEFAULT_TX_SIZE: usize = 100_000;
    if tx_packed.len() >= DEFAULT_TX_SIZE {
        return Err(Error::TooLarge);
    }

    let txu: TxU = vecpak::from_slice(tx_packed).map_err(|_| Error::WrongType("vecpak_decode"))?;
    let tx_encoded = txu.tx_encoded();

    let h: [u8; 32] = Sha256::digest(&tx_encoded).into();
    if txu.hash.as_slice() != h.as_ref() {
        return Err(Error::InvalidHash);
    }

    bls12_381::verify(&txu.tx.signer, &txu.signature, &h, DST_TX).map_err(|_| Error::InvalidSignature)?;

    if txu.tx.nonce > 99_999_999_999_999_999_999_i128 {
        return Err(Error::NonceTooHigh);
    }

    let a = &txu.tx.action;

    if a.op != "call" {
        return Err(Error::OpMustBeCall);
    }
    if a.contract.is_empty() {
        return Err(Error::ContractMustBeBinary);
    }
    if a.function.is_empty() {
        return Err(Error::FunctionMustBeBinary);
    }

    if is_special_meeting_block {
        if a.contract.as_slice() != b"Epoch" {
            return Err(Error::InvalidModuleForSpecial);
        }
        if a.function.as_slice() != b"slash_trainer" {
            return Err(Error::InvalidFunctionForSpecial);
        }
    }

    if let Some(sym) = &a.attached_symbol {
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

pub fn validate(tx_packed: &[u8], is_special_meeting_block: bool) -> Result<TxU, Error> {
    validate_basic(tx_packed, is_special_meeting_block)
}

pub fn pack(txu: &TxU) -> Vec<u8> {
    vecpak::to_vec(txu).unwrap_or_default()
}

pub fn build(
    config: &Config,
    contract: &[u8],
    function: &str,
    args: &[Vec<u8>],
    nonce: Option<i64>,
    attached_symbol: Option<&[u8]>,
    attached_amount: Option<&[u8]>,
) -> Vec<u8> {
    let nonce_val: i128 = match nonce {
        Some(n) => n as i128,
        None => crate::utils::misc::get_unix_nanos_now() as i128,
    };

    let action = TxAction {
        op: "call".to_string(),
        contract: contract.to_vec(),
        function: function.as_bytes().to_vec(),
        args: args.to_vec(),
        attached_symbol: attached_symbol.map(|s| s.to_vec()),
        attached_amount: attached_amount.map(|a| a.to_vec()),
    };

    let tx = Tx { signer: config.get_pk(), nonce: nonce_val, action };
    let tx_encoded = vecpak::to_vec(&tx).expect("failed to encode tx");
    let hash: [u8; 32] = Sha256::digest(&tx_encoded).into();
    let signature = bls12_381::sign(&config.get_sk(), &hash, DST_TX).expect("failed to sign tx");

    let txu = TxU { hash: Hash::from(hash), signature, tx };
    pack(&txu)
}

pub fn chain_valid_txu(fabric: &crate::consensus::fabric::Fabric, txu: &TxU) -> bool {
    let chain_nonce = fabric.chain_nonce(txu.tx.signer.as_ref());
    let nonce_valid = match chain_nonce {
        None => true,
        Some(n) => txu.tx.nonce > n as i128,
    };

    let has_balance = txu.exec_cost(crate::consensus::chain_epoch(fabric.db())) as i128
        <= fabric.chain_balance(txu.tx.signer.as_ref());

    let action = &txu.tx.action;
    let mut epoch_sol_valid = true;
    if action.function.as_slice() == b"submit_sol" {
        if let Some(first_arg) = action.args.first() {
            if first_arg.len() >= 4 {
                let sol_epoch = u32::from_le_bytes([first_arg[0], first_arg[1], first_arg[2], first_arg[3]]);
                epoch_sol_valid = crate::consensus::chain_epoch(fabric.db()) as u32 == sol_epoch;
            }
        }
    }

    epoch_sol_valid && nonce_valid && has_balance
}

pub fn chain_valid(fabric: &crate::consensus::fabric::Fabric, tx_input: &[u8]) -> bool {
    match unpack(tx_input) {
        Ok(txu) => chain_valid_txu(fabric, &txu),
        Err(_) => false,
    }
}

pub fn unpack(tx_packed: &[u8]) -> Result<TxU, Error> {
    vecpak::from_slice(tx_packed).map_err(|_| Error::WrongType("vecpak_decode"))
}

pub mod db {
    use amadeus_utils::database::pad_integer_20;
    use amadeus_utils::rocksdb::RocksDb;
    use amadeus_utils::vecpak::{self, Term as VTerm};

    #[derive(Debug, Clone)]
    pub struct TxPointer {
        pub entry_hash: Vec<u8>,
        pub index_start: usize,
        pub index_size: usize,
    }

    impl TxPointer {
        pub fn pack(&self) -> Vec<u8> {
            let term = VTerm::PropList(vec![
                (VTerm::Binary(b"entry_hash".to_vec()), VTerm::Binary(self.entry_hash.clone())),
                (VTerm::Binary(b"index_start".to_vec()), VTerm::VarInt(self.index_start as i128)),
                (VTerm::Binary(b"index_size".to_vec()), VTerm::VarInt(self.index_size as i128)),
            ]);
            vecpak::encode(term)
        }
    }

    pub fn store_tx_pointer(
        tx_hash: &[u8],
        tx_packed: &[u8],
        entry_hash: &[u8],
        entry_packed: &[u8],
        db: &RocksDb,
    ) -> Result<(), amadeus_utils::rocksdb::Error> {
        if let Some(index_start) = entry_packed.windows(tx_packed.len()).position(|window| window == tx_packed) {
            let tx_ptr = TxPointer { entry_hash: entry_hash.to_vec(), index_start, index_size: tx_packed.len() };

            db.put("tx", tx_hash, &tx_ptr.pack())?;
        }

        Ok(())
    }

    pub fn store_tx_nonce_index(
        tx_hash: &[u8],
        signer: &[u8],
        nonce: u64,
        db: &RocksDb,
    ) -> Result<(), amadeus_utils::rocksdb::Error> {
        let key = format!("{}:{}", hex::encode(signer), pad_integer_20(nonce));
        db.put("tx_account_nonce", key.as_bytes(), tx_hash)?;
        Ok(())
    }

    pub fn store_tx_receiver_nonce_index(
        tx_hash: &[u8],
        receiver: &[u8],
        nonce: u64,
        db: &RocksDb,
    ) -> Result<(), amadeus_utils::rocksdb::Error> {
        let key = format!("{}:{}", hex::encode(receiver), pad_integer_20(nonce));
        db.put("tx_receiver_nonce", key.as_bytes(), tx_hash)?;
        Ok(())
    }
}
