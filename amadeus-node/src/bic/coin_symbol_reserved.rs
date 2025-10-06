//! Stub for Coin Symbol reservation checks
//! In Elixir: BIC.CoinSymbolReserved.is_free(symbol, caller)
//! TODO: Implement reservation logic backed by KV or other state when available

/// Returns true if the symbol is not reserved by someone else
/// Currently a stub that always returns true
pub fn is_free(_symbol: &str, _caller: &[u8; 48]) -> bool {
    // TODO: implement reservation checks based on project rules
    true
}
