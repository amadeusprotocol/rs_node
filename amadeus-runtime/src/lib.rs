#![allow(unused_imports, unreachable_patterns, unused_variables, dead_code)]

pub mod consensus;

pub type Result<T> = std::result::Result<T, &'static str>;

// re-export bcat from amadeus-utils
pub use amadeus_utils::misc::bcat;
