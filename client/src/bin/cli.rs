use ama_core::bic::contract;
use ama_core::config::{Config, gen_sk, get_pk, read_sk, write_sk};
use ama_core::consensus::tx;
use bs58;
use clap::{Parser, Subcommand};
use client::UdpSocketWrapper;
use serde_json::Value as JsonValue;
use std::fs;
use tokio::net::UdpSocket;

#[derive(Parser)]
#[command(author, version, about = "Amadeus blockchain CLI tool")]
#[command(long_about = r#"CLI tool for Amadeus blockchain operations.

Notes:
  - args_json must be a JSON array. Each element can be:
      • a string => UTF-8 bytes
      • {"b58": "..."} => Base58-decoded bytes
      • {"hex": "..."} => hex-decoded bytes (with or without 0x)
      • {"utf8": "..."} => UTF-8 bytes
  - Secret key: use --sk env variable for secret key.
  - deploytx validates the WASM by compiling it with wasmer before building the tx."#)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new random secret secret key (64 bytes) and save to a file as Base58; prints derived pk
    GenSk {
        /// Output path to write the secret key bytes
        out_file: String,
    },
    /// Get public key from secret key file (Base58-encoded 64-byte secret key)
    GetPk {
        /// Path to the secret key file
        #[arg(long = "sk")]
        sk: String,
    },
    /// Build a transaction for contract function call
    Tx {
        /// Path to the secret key file
        #[arg(long = "sk")]
        sk: String,
        /// Contract address (Base58) or name
        contract: String,
        /// Function name to call
        function: String,
        /// Arguments as JSON array
        args_json: String,
        /// Optional attachment symbol
        attach_symbol: Option<String>,
        /// Optional attachment amount (required if attach_symbol is provided)
        attach_amount: Option<String>,
        /// Send the transaction to the network instead of just printing it
        #[arg(long = "send")]
        send: bool,
    },
    /// Build a transaction to deploy WASM contract
    ContractTx {
        /// Path to the secret key file
        #[arg(long = "sk")]
        sk: String,
        /// Path to WASM file
        wasm_path: String,
        /// Send the transaction to the network instead of just printing it
        #[arg(long = "send")]
        send: bool,
    },
}

fn parse_json_arg_elem(v: &JsonValue) -> Result<Vec<u8>, String> {
    match v {
        JsonValue::String(s) => Ok(s.as_bytes().to_vec()),
        JsonValue::Object(map) => {
            if let Some(b58) = map.get("b58") {
                if let Some(s) = b58.as_str() {
                    return bs58::decode(s).into_vec().map_err(|e| format!("invalid base58: {}", e));
                }
            }
            if let Some(hex) = map.get("hex") {
                if let Some(s) = hex.as_str() {
                    let s = s.strip_prefix("0x").unwrap_or(s);
                    return hex::decode(s).map_err(|e| format!("invalid hex: {}", e));
                }
            }
            if let Some(utf8) = map.get("utf8") {
                if let Some(s) = utf8.as_str() {
                    return Ok(s.as_bytes().to_vec());
                }
            }
            Err("unsupported JSON object for arg; expected {b58|hex|utf8}".to_string())
        }
        _ => Err("unsupported JSON value for arg; expected string or object".to_string()),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenSk { out_file } => handle_gen_sk(&out_file).await,
        Commands::GetPk { sk } => handle_get_pk(&config_from_sk(&sk).await),
        Commands::Tx { sk, contract, function, args_json, attach_symbol, attach_amount, send } => {
            if attach_symbol.is_some() != attach_amount.is_some() {
                eprintln!("Error: attach_amount and attach_symbol must go together");
                std::process::exit(2);
            }

            handle_build_tx(
                &config_from_sk(&sk).await,
                &contract,
                &function,
                &args_json,
                attach_symbol.as_deref(),
                attach_amount.as_deref(),
                send,
            )
            .await;
        }
        Commands::ContractTx { sk, wasm_path, send } => {
            handle_deploy_tx(&config_from_sk(&sk).await, &wasm_path, send).await;
        }
    }
}

async fn handle_gen_sk(path: &str) {
    let sk = gen_sk();
    write_sk(path, sk).await.expect("write sk");
    println!("created {path}, pk {}", bs58::encode(get_pk(&sk)).into_string());
    std::process::exit(0);
}

fn handle_get_pk(config: &Config) {
    println!("{}", bs58::encode(config.get_pk()).into_string());
    std::process::exit(0);
}

async fn handle_build_tx(
    config: &Config,
    contract: &str,
    function: &str,
    args_json: &str,
    attach_symbol: Option<&str>,
    attach_amount: Option<&str>,
    send: bool,
) {
    // contract: if Base58 decodes successfully, use decoded bytes, else use raw bytes
    let contract_bytes = match bs58::decode(contract).into_vec() {
        Ok(b) => b,
        Err(_) => contract.as_bytes().to_vec(),
    };

    // Parse args_json into Vec<Vec<u8>>
    let json: JsonValue = match serde_json::from_str(args_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid args_json: {}", e);
            std::process::exit(2);
        }
    };
    let arr = match json.as_array() {
        Some(a) => a,
        None => {
            eprintln!("args_json must be a JSON array");
            std::process::exit(2);
        }
    };
    let mut args_vec: Vec<Vec<u8>> = Vec::with_capacity(arr.len());
    for v in arr {
        match parse_json_arg_elem(v) {
            Ok(b) => args_vec.push(b),
            Err(msg) => {
                eprintln!("{}", msg);
                std::process::exit(2);
            }
        }
    }

    // Handle attachments
    let (attach_symbol_bytes, attach_amount_bytes): (Option<Vec<u8>>, Option<Vec<u8>>) =
        match (attach_symbol, attach_amount) {
            (Some(symbol), Some(amount)) => (Some(symbol.as_bytes().to_vec()), Some(amount.as_bytes().to_vec())),
            _ => (None, None),
        };

    let tx_packed = tx::build(
        config,
        &contract_bytes,
        function,
        &args_vec,
        None,
        attach_symbol_bytes.as_deref(),
        attach_amount_bytes.as_deref(),
    );

    send_or_print(config, tx_packed, send).await;
}

async fn handle_deploy_tx(config: &Config, wasm_path: &str, send: bool) {
    let wasm_bytes = match fs::read(wasm_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read wasm file: {}", e);
            std::process::exit(2);
        }
    };

    // Validate WASM
    if let Err(e) = contract::validate(&wasm_bytes) {
        eprintln!("{}", e);
        std::process::exit(2);
    }

    let args_vec = vec![wasm_bytes];
    let tx_packed = tx::build(config, b"Contract", "deploy", &args_vec, None, None, None);
    send_or_print(config, tx_packed, send).await;
}

async fn send_or_print(config: &Config, tx_packed: Vec<u8>, send: bool) {
    if send {
        let socket = UdpSocketWrapper(UdpSocket::bind("0.0.0.0").await.expect("bind udp socket"));
        let code = client::send_transaction(config, socket, tx_packed)
            .await
            .inspect_err(|e| eprintln!("failed to send transaction: {}", e))
            .map(|_| 0)
            .unwrap_or(2);
        std::process::exit(code);
    } else {
        println!("{}", bs58::encode(tx_packed).into_string());
        std::process::exit(0);
    }
}

pub async fn config_from_sk(sk: &str) -> Config {
    let sk = read_sk(sk).await.expect("valid sk");
    Config::from_sk(sk)
}
