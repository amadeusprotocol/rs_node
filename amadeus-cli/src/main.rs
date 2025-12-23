use amadeus_node::config::{Config, gen_sk, get_pk, read_sk, write_sk};
use amadeus_node::consensus::doms::tx;
use amadeus_node::runtime_bic::contract;
use amadeus_utils::vecpak;
use anyhow::{Error, Result};
use clap::{Parser, Subcommand};
use serde_json::Value as JsonValue;
use std::env;
use std::fs;

#[derive(Parser)]
#[command(author, version, about = "Amadeus CLI tool")]
#[command(long_about = r#"CLI tool for Amadeus blockchain operations.

WORKFLOW - Deploy and Call a Contract:
  1. Generate a wallet:     cli gen-sk wallet.sk
  2. Get your public key:   cli get-pk --sk wallet.sk
  3. Deploy contract:       cli deploy-tx --sk wallet.sk contract.wasm --url https://node.url
  4. Call your contract:    cli tx --sk wallet.sk <YOUR_PK> <function> '[args]' --url https://node.url

ARGUMENT FORMAT (args_json):
  JSON array where each element is:
    * A string          => UTF-8 bytes (e.g., "hello")
    * A number          => String bytes (e.g., 100 becomes "100")
    * {"b58": "..."}    => Base58-decoded bytes (for addresses)
    * {"hex": "..."}    => Hex-decoded bytes (with or without 0x)
    * {"utf8": "..."}   => Explicit UTF-8 bytes

EXAMPLES:
  # Transfer 100 AMA (flat units = 100 * 10^9)
  cli tx --sk wallet.sk Coin transfer '[{"b58": "RECIPIENT_PK"}, "100000000000", "AMA"]' --url URL

  # Call deployed contract function
  cli tx --sk wallet.sk YOUR_PK my_function '["arg1", 42]' --url URL

  # Call contract with token attachment
  cli tx --sk wallet.sk YOUR_PK deposit '[]' AMA 1000000000 --url URL

BUILT-IN CONTRACTS:
  Coin      - transfer, create_and_mint, mint, pause
  Contract  - deploy
  Epoch     - submit_sol, set_emission_address, slash_trainer

Environment variables:
  AMADEUS_URL - Default node URL (e.g., https://testnet.ama.one)"#)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new random secret key (64 bytes) and save to a file as Base58; prints derived pk
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
        /// Contract: built-in name (Coin, Contract, Epoch) or Base58 public key for user contracts
        contract: String,
        /// Function name to call
        function: String,
        /// Arguments as JSON array (see --help for format details)
        args_json: String,
        /// Token symbol to attach (e.g., AMA)
        attach_symbol: Option<String>,
        /// Token amount to attach in flat units (requires attach_symbol)
        attach_amount: Option<String>,
        /// HTTP endpoint URL for sending transaction (falls back to AMADEUS_URL env var)
        #[arg(long = "url")]
        url: Option<String>,
    },
    /// Build a transaction to deploy a WASM smart contract
    DeployTx {
        /// Path to the secret key file
        #[arg(long = "sk")]
        sk: String,
        /// Path to WASM file (compiled AssemblyScript or Rust contract)
        wasm_path: String,
        /// HTTP endpoint URL for sending transaction (falls back to AMADEUS_URL env var)
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
                get_url(url.as_deref()).as_deref(),
            )
            .await?;
        }
        Commands::DeployTx { sk, wasm_path, url } => {
            handle_deploy_tx(
                &config_from_sk(&sk).await?,
                &wasm_path,
                get_url(url.as_deref()).as_deref(),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn config_from_sk(path: &str) -> Result<Config> {
    let sk = read_sk(path).await?;
    Ok(Config::new_daemonless(sk))
}

fn get_url(url_arg: Option<&str>) -> Option<String> {
    url_arg.map(|s| s.to_string()).or_else(|| env::var("AMADEUS_URL").ok())
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
    let contract_bytes = parse_contract(contract);
    let args_vec = parse_args(args_json)?;
    let (attach_symbol_bytes, attach_amount_bytes) = match (attach_symbol, attach_amount) {
        (Some(sym), Some(amt)) => (Some(sym.as_bytes().to_vec()), Some(amt.as_bytes().to_vec())),
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

    submit_or_print(tx_packed, url).await
}

async fn handle_deploy_tx(config: &Config, wasm_path: &str, url: Option<&str>) -> Result<()> {
    let wasm_bytes = fs::read(wasm_path)?;
    contract::validate(&wasm_bytes).map_err(|e| anyhow::anyhow!(e))?;

    let tx_packed = tx::build(config, b"Contract", "deploy", &[wasm_bytes], None, None, None);
    submit_or_print(tx_packed, url).await
}

fn parse_contract(contract: &str) -> Vec<u8> {
    match bs58::decode(contract).into_vec() {
        Ok(b) if b.len() == 48 => b,
        _ => contract.as_bytes().to_vec(),
    }
}

fn parse_args(args_json: &str) -> Result<Vec<Vec<u8>>> {
    let json: JsonValue = serde_json::from_str(args_json)?;
    let arr = json.as_array().ok_or(Error::msg("arguments must be a JSON array"))?;
    arr.iter().map(parse_arg_elem).collect()
}

fn parse_arg_elem(v: &JsonValue) -> Result<Vec<u8>> {
    match v {
        JsonValue::String(s) => Ok(s.as_bytes().to_vec()),
        JsonValue::Number(n) => Ok(n.to_string().as_bytes().to_vec()),
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
        _ => Err(Error::msg("unsupported JSON value; expected string, number, or {b58|hex|utf8} object")),
    }
}

fn extract_tx_hash(tx_packed: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    struct TxUPartial {
        #[serde(with = "serde_bytes")]
        hash: Vec<u8>,
    }
    vecpak::from_slice::<TxUPartial>(tx_packed)
        .map(|txu| bs58::encode(&txu.hash).into_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

async fn submit_or_print(tx_packed: Vec<u8>, url: Option<&str>) -> Result<()> {
    println!("tx_hash: {}", extract_tx_hash(&tx_packed));

    match url {
        Some(url) => send_transaction(tx_packed, url).await,
        None => {
            println!("{}", bs58::encode(&tx_packed).into_string());
            Ok(())
        }
    }
}

pub async fn send_transaction(tx_packed: Vec<u8>, url: &str) -> Result<()> {
    let tx_hash = extract_tx_hash(&tx_packed);
    let tx_base58 = bs58::encode(&tx_packed).into_string();
    let base_url = url.trim_end_matches('/');
    let endpoint = format!("{}/api/tx/submit", base_url);

    let response = reqwest::Client::new()
        .post(&endpoint)
        .header("Content-Type", "text/plain")
        .body(tx_base58)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return Err(Error::msg(format!("HTTP error {}: {}", status, error_text)));
    }

    let result: JsonValue = response.json().await?;
    match result.get("error") {
        Some(e) if e == "ok" => {
            println!("Transaction submitted successfully.");

            // Wait a bit for the transaction to be processed
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Fetch and display transaction result
            let tx_url = format!("{}/api/chain/tx/{}", base_url, tx_hash);
            match reqwest::get(&tx_url).await {
                Ok(tx_response) => {
                    if let Ok(tx_data) = tx_response.json::<JsonValue>().await {
                        println!("\n{}", serde_json::to_string_pretty(&tx_data).unwrap_or_else(|_| format!("{:?}", tx_data)));
                    }
                }
                Err(_) => {
                    println!("\nCouldn't fetch transaction result. Check manually:");
                    println!("  {}", tx_url);
                }
            }

            Ok(())
        }
        Some(e) => Err(Error::msg(format!("Transaction failed: {:?}", e))),
        None => Err(Error::msg(format!("Unexpected response: {}", result))),
    }
}
