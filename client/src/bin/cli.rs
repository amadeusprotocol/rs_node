use ama_core::bic::contract;
use ama_core::config::{Config, gen_sk, get_pk, read_sk, write_sk};
use ama_core::consensus::doms::tx;
use anyhow::{Error, Result};
use bs58;
use clap::{Parser, Subcommand};
use reqwest;
use serde_json::Value as JsonValue;
use std::fs;

#[derive(Parser)]
#[command(author, version, about = "Amadeus CLI tool")]
#[command(long_about = r#"CLI tool for Amadeus blockchain operations.

Notes:
  - args_json must be a JSON array. Each element can be:
      • a string => UTF-8 bytes
      • {"b58": "..."} => Base58-decoded bytes
      • {"hex": "..."} => hex-decoded bytes (with or without 0x)
      • {"utf8": "..."} => UTF-8 bytes
  - Secret key: use --sk parameter for path to secret key file
  - Transactions: provide --url to send via HTTP, otherwise prints base58-encoded tx
  - Contract deployment validates WASM before building the tx"#)]
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
        /// HTTP endpoint URL for sending transaction (if not provided, prints base58-encoded tx)
        #[arg(long = "url")]
        url: Option<String>,
    },
    /// Build a transaction to deploy WASM contract
    ContractTx {
        /// Path to the secret key file
        #[arg(long = "sk")]
        sk: String,
        /// Path to WASM file
        wasm_path: String,
        /// HTTP endpoint URL for sending transaction (if not provided, prints base58-encoded tx)
        #[arg(long = "url")]
        url: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenSk { out_file } => handle_gen_sk(&out_file).await?,
        Commands::GetPk { sk } => handle_get_pk(&config_from_sk(&sk).await?),
        Commands::Tx { sk, contract, function, args_json, attach_symbol, attach_amount, url } => {
            if attach_symbol.is_some() != attach_amount.is_some() {
                return Err(Error::msg("attach_amount and attach_symbol must go together"));
            }

            handle_tx(
                &config_from_sk(&sk).await?,
                &contract,
                &function,
                &args_json,
                attach_symbol.as_deref(),
                attach_amount.as_deref(),
                url.as_deref(),
            )
            .await?;
        }
        Commands::ContractTx { sk, wasm_path, url } => {
            handle_contract_tx(&config_from_sk(&sk).await?, &wasm_path, url.as_deref()).await?;
        }
    }

    Ok(())
}

pub async fn config_from_sk(path: &str) -> Result<Config> {
    let sk = read_sk(path).await?;
    Ok(Config::new_daemonless(sk))
}

async fn handle_gen_sk(path: &str) -> Result<()> {
    let sk = gen_sk();
    write_sk(path, sk).await?;
    println!("created {path}, pk {}", bs58::encode(get_pk(&sk)).into_string());
    Ok(())
}

fn handle_get_pk(config: &Config) {
    println!("{}", bs58::encode(config.get_pk()).into_string());
}

async fn handle_tx(
    config: &Config,
    contract: &str,
    function: &str,
    args_json: &str,
    attach_symbol: Option<&str>,
    attach_amount: Option<&str>,
    url: Option<&str>,
) -> Result<()> {
    // contract: if Base58 decodes successfully, use decoded bytes, else use raw bytes
    let contract_bytes = match bs58::decode(contract).into_vec() {
        Ok(b) => b,
        Err(_) => contract.as_bytes().to_vec(),
    };

    // Parse args_json into Vec<Vec<u8>>
    let json: JsonValue = serde_json::from_str(args_json)?;
    let arr = json.as_array().ok_or(Error::msg("arguments is not an array"))?;

    let mut args_vec: Vec<Vec<u8>> = Vec::with_capacity(arr.len());
    for v in arr {
        let b = parse_json_arg_elem(v)?;
        args_vec.push(b);
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

    match url {
        Some(url) => send_transaction(tx_packed, url).await,
        None => {
            println!("{}", bs58::encode(&tx_packed).into_string());
            Ok(())
        }
    }
}

fn parse_json_arg_elem(v: &JsonValue) -> Result<Vec<u8>> {
    match v {
        JsonValue::String(s) => Ok(s.as_bytes().to_vec()),
        JsonValue::Object(map) => {
            if let Some(b58) = map.get("b58")
                && let Some(s) = b58.as_str()
            {
                Ok(bs58::decode(s).into_vec()?)
            } else if let Some(hex) = map.get("hex")
                && let Some(s) = hex.as_str()
            {
                let s = s.strip_prefix("0x").unwrap_or(s);
                Ok(hex::decode(s)?)
            } else if let Some(utf8) = map.get("utf8")
                && let Some(s) = utf8.as_str()
            {
                Ok(s.as_bytes().to_vec())
            } else {
                Err(Error::msg("unsupported JSON object for arg; expected {b58|hex|utf8}"))
            }
        }
        _ => Err(Error::msg("unsupported JSON value for arg; expected string or object")),
    }
}

async fn handle_contract_tx(config: &Config, wasm_path: &str, url: Option<&str>) -> Result<()> {
    let wasm_bytes = fs::read(wasm_path)?;

    // Validate WASM
    contract::validate(&wasm_bytes)?;
    let args_vec = vec![wasm_bytes];
    let tx_packed = tx::build(config, b"Contract", "deploy", &args_vec, None, None, None);

    match url {
        Some(url) => send_transaction(tx_packed, url).await,
        None => {
            println!("{}", bs58::encode(&tx_packed).into_string());
            Ok(())
        }
    }
}

pub async fn send_transaction(tx_packed: Vec<u8>, url: &str) -> Result<()> {
    // encode transaction as base58
    let tx_base58 = bs58::encode(&tx_packed).into_string();

    // build the HTTP client
    let client = reqwest::Client::new();

    // send POST request to /api/tx/submit with base58-encoded transaction as text/plain body
    let endpoint = format!("{}/api/tx/submit", url.trim_end_matches('/'));

    let response = client.post(&endpoint).header("Content-Type", "text/plain").body(tx_base58).send().await?;

    if response.status().is_success() {
        let result: JsonValue = response.json().await?;

        // check if there's an error field
        if let Some(error) = result.get("error") {
            if error == "ok" {
                if let Some(tx_hash) = result.get("tx_hash") {
                    println!("Transaction submitted successfully. Hash: {}", tx_hash);
                } else {
                    println!("Transaction submitted successfully.");
                }
            } else {
                return Err(Error::msg(format!("Transaction failed: {:?}", error)));
            }
        } else {
            return Err(Error::msg(format!("Unexpected response: {}", result)));
        }
    } else {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return Err(Error::msg(format!("HTTP error {}: {}", status, error_text)));
    }

    Ok(())
}
