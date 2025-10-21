pub const DECIMALS: u32 = 9;
pub const BURN_ADDRESS: [u8; 48] = [0u8; 48];

pub fn to_cents(coins: i128) -> i128 {
    coins.saturating_mul(10_000_000)
}
