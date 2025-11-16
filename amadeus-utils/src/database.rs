use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Database error: {0}")]
    Generic(String),
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Database trait for abstracting storage operations
/// Implementations can use RocksDB, in-memory storage, or other backends
#[async_trait]
pub trait Database: Send + Sync {
    /// Get a value from the database
    fn get(&self, column_family: &str, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError>;

    /// Put a key-value pair into the database
    fn put(&self, column_family: &str, key: &[u8], value: &[u8]) -> Result<(), DatabaseError>;

    /// Delete a key from the database
    fn delete(&self, column_family: &str, key: &[u8]) -> Result<(), DatabaseError>;

    /// Iterate over keys with a given prefix
    fn iter_prefix(&self, column_family: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, DatabaseError>;
}

pub fn pad_integer(key: u64) -> String {
    format!("{:012}", key)
}

pub fn pad_integer_20(key: u64) -> String {
    format!("{:020}", key)
}
