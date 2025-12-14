use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// A 48-byte BLS public key / address
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 48]);

impl Address {
    pub const SIZE: usize = 48;

    pub const fn zero() -> Self {
        Self([0u8; 48])
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 48 {
            return None;
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 48]
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(96);
        for byte in &self.0 {
            s.push_str(&alloc::format!("{:02x}", byte));
        }
        s
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 96 {
            return None;
        }

        let mut arr = [0u8; 48];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            if i >= 48 {
                return None;
            }
            let high = hex_char_to_nibble(chunk[0])?;
            let low = hex_char_to_nibble(chunk[1])?;
            arr[i] = (high << 4) | low;
        }
        Some(Self(arr))
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::zero()
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_hex())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "{}...{}", &hex[..8], &hex[88..])
    }
}

/// A 32-byte hash (Blake3)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const SIZE: usize = 32;

    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            s.push_str(&alloc::format!("{:02x}", byte));
        }
        s
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }

        let mut arr = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            if i >= 32 {
                return None;
            }
            let high = hex_char_to_nibble(chunk[0])?;
            let low = hex_char_to_nibble(chunk[1])?;
            arr[i] = (high << 4) | low;
        }
        Some(Self(arr))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::zero()
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "{}...{}", &hex[..8], &hex[56..])
    }
}

/// A 96-byte BLS signature
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 96]);

impl Signature {
    pub const SIZE: usize = 96;

    pub const fn zero() -> Self {
        Self([0u8; 96])
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 96 {
            return None;
        }
        let mut arr = [0u8; 96];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::zero()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature(...)")
    }
}

fn hex_char_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub type ContractResult<T> = Result<T, ContractError>;

#[derive(Debug, Clone)]
pub enum ContractError {
    StorageError,
    InvalidArgument(String),
    InsufficientBalance,
    Unauthorized,
    CallFailed(String),
    Overflow,
    Custom(String),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractError::StorageError => write!(f, "Storage operation failed"),
            ContractError::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            ContractError::InsufficientBalance => write!(f, "Insufficient balance"),
            ContractError::Unauthorized => write!(f, "Unauthorized"),
            ContractError::CallFailed(msg) => write!(f, "Contract call failed: {}", msg),
            ContractError::Overflow => write!(f, "Arithmetic overflow"),
            ContractError::Custom(msg) => write!(f, "{}", msg),
        }
    }
}

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
}

impl ToBytes for u64 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl FromBytes for u64 {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(u64::from_le_bytes)
    }
}

impl ToBytes for i64 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl FromBytes for i64 {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(i64::from_le_bytes)
    }
}

impl ToBytes for i128 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl FromBytes for i128 {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(i128::from_le_bytes)
    }
}

impl ToBytes for Address {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl FromBytes for Address {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes(bytes)
    }
}

impl ToBytes for Hash {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl FromBytes for Hash {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes(bytes)
    }
}
