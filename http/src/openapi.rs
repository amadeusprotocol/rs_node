use axum::{Router, http::header, response::Response, routing::get};
use utoipa::OpenApi;

use crate::models::*;
use crate::routes::api::{chain, contract, epoch, peer, transaction, wallet};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Amadeus Node HTTP API",
        version = env!("CARGO_PKG_VERSION"),
        description = "REST API for the Amadeus blockchain node, providing access to blockchain data, peer information, wallet operations, and smart contract interactions.",
        contact(
            name = "Amadeus Project",
            url = "https://github.com/amadeus-robot/node"
        ),
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    servers(
        (url = "http://72.9.144.110", description = "Amadeus seed node (primary)"),
        (url = "http://167.235.169.185", description = "Amadeus seed node (secondary)"),
        (url = "http://37.27.238.30", description = "Amadeus seed node (tertiary)"),
        (url = "http://localhost", description = "Local development server (HTTP_PORT=80)")
    ),
    paths(
        peer::get_peer_anr,
        peer::get_validator_anrs,
        peer::get_all_anrs,
        peer::get_all_nodes,
        peer::get_trainers,
        peer::get_removed_trainers,
        chain::get_chain_stats,
        chain::get_chain_tip,
        chain::get_entries_by_height,
        chain::get_entries_by_height_with_txs,
        chain::get_transaction_by_id,
        chain::get_transaction_events_by_account,
        chain::get_transactions_in_entry,
        wallet::get_wallet_balance,
        wallet::get_wallet_balance_by_symbol,
        wallet::get_all_wallet_balances,
        transaction::submit_transaction,
        transaction::submit_transaction_via_url,
        contract::validate_contract_bytecode,
        contract::get_contract_state,
        contract::get_token_richlist,
        epoch::get_current_epoch_score,
        epoch::get_epoch_score_by_validator,
        epoch::get_emission_address,
    ),
    components(schemas(
        ErrorResponse,
        AnrResponse,
        AnrsResponse,
        Anr,
        NodeInfo,
        TrainersResponse,
        ChainStats,
        ChainStatsResponse,
        ChainTipResponse,
        EntriesResponse,
        EntriesWithTxsResponse,
        TransactionResponse,
        TransactionEventsResponse,
        TransactionsInEntryResponse,
        BlockEntry,
        BlockEntryWithTxs,
        Transaction,
        Balance,
        RichlistEntry,
        RichlistResponse,
        BalanceResponse,
        AllBalancesResponse,
        TransactionSubmitResponse,
        BytecodeValidationResponse,
        EpochScoreResponse,
        EmissionAddressResponse,
    )),
    tags(
        (name = "peer", description = "Peer and ANR management operations"),
        (name = "chain", description = "Blockchain data operations"),
        (name = "wallet", description = "Wallet balance operations"),
        (name = "transaction", description = "Transaction operations"),
        (name = "contract", description = "Smart contract operations"),
        (name = "epoch", description = "Epoch and validator operations")
    )
)]
pub struct ApiDoc;

async fn get_openapi_yaml() -> Response {
    let yaml_content = serde_yaml::to_string(&ApiDoc::openapi()).unwrap_or_else(|e| {
        eprintln!("Failed to generate OpenAPI YAML: {}", e);
        String::new()
    });

    Response::builder().header(header::CONTENT_TYPE, "application/x-yaml").body(yaml_content.into()).unwrap()
}

pub fn openapi_route<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new().route("/openapi.yaml", get(get_openapi_yaml))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_openapi_yaml_generation() {
        let openapi = ApiDoc::openapi();
        let yaml = serde_yaml::to_string(&openapi).unwrap();
        assert!(!yaml.is_empty());
        assert!(yaml.contains("openapi:"));
        assert!(yaml.contains("Amadeus Node HTTP API"));
    }

    #[tokio::test]
    async fn test_openapi_struct() {
        let openapi = ApiDoc::openapi();
        assert_eq!(openapi.info.title, "Amadeus Node HTTP API");
        assert_eq!(openapi.info.version, env!("CARGO_PKG_VERSION"));
        assert!(!openapi.paths.paths.is_empty());
    }
}
