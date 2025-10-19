use serde::{Deserialize, Serialize};
use std::fmt;

/// Version struct that represents a semantic version as three bytes [major, minor, patch]
#[derive(
    Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, bincode::Encode, bincode::Decode,
)]
pub struct Ver([u8; 3]);

impl Ver {
    /// Create a new version from three individual version components
    pub const fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self([major, minor, patch])
    }

    /// Create a version from a byte array
    pub const fn from_bytes(bytes: [u8; 3]) -> Self {
        Self(bytes)
    }

    /// Get the raw byte array representation
    pub const fn as_bytes(&self) -> [u8; 3] {
        self.0
    }

    /// Get the major version component
    pub const fn major(&self) -> u8 {
        self.0[0]
    }

    /// Get the minor version component
    pub const fn minor(&self) -> u8 {
        self.0[1]
    }

    /// Get the patch version component
    pub const fn patch(&self) -> u8 {
        self.0[2]
    }
}

impl fmt::Display for Ver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0[0], self.0[1], self.0[2])
    }
}

impl From<[u8; 3]> for Ver {
    fn from(bytes: [u8; 3]) -> Self {
        Self(bytes)
    }
}

impl From<Ver> for [u8; 3] {
    fn from(ver: Ver) -> Self {
        ver.0
    }
}

impl From<Ver> for String {
    fn from(ver: Ver) -> Self {
        ver.to_string()
    }
}

impl TryFrom<&str> for Ver {
    type Error = ParseVersionError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(ParseVersionError::InvalidFormat);
        }

        let major = parts[0].parse::<u8>().map_err(|_| ParseVersionError::InvalidNumber)?;
        let minor = parts[1].parse::<u8>().map_err(|_| ParseVersionError::InvalidNumber)?;
        let patch = parts[2].parse::<u8>().map_err(|_| ParseVersionError::InvalidNumber)?;

        Ok(Self::new(major, minor, patch))
    }
}

impl TryFrom<String> for Ver {
    type Error = ParseVersionError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ver::try_from(s.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseVersionError {
    #[error("Invalid version format, expected 'major.minor.patch'")]
    InvalidFormat,
    #[error("Invalid version number")]
    InvalidNumber,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ver_creation() {
        let ver = Ver::new(1, 2, 3);
        assert_eq!(ver.major(), 1);
        assert_eq!(ver.minor(), 2);
        assert_eq!(ver.patch(), 3);
    }

    #[test]
    fn test_ver_display() {
        let ver = Ver::new(1, 1, 8);
        assert_eq!(ver.to_string(), "1.1.8");
    }

    #[test]
    fn test_ver_from_bytes() {
        let bytes = [1, 1, 7];
        let ver = Ver::from_bytes(bytes);
        assert_eq!(ver.as_bytes(), bytes);
    }

    #[test]
    fn test_ver_parse_from_string() {
        let ver = Ver::try_from("1.1.8").unwrap();
        assert_eq!(ver.major(), 1);
        assert_eq!(ver.minor(), 1);
        assert_eq!(ver.patch(), 8);
    }

    #[test]
    fn test_ver_parse_invalid_format() {
        assert!(Ver::try_from("1.1").is_err());
        assert!(Ver::try_from("1.1.2.3").is_err());
        assert!(Ver::try_from("a.b.c").is_err());
    }

    #[test]
    fn test_ver_ordering() {
        let v1 = Ver::new(1, 1, 7);
        let v2 = Ver::new(1, 1, 8);
        let v3 = Ver::new(1, 2, 0);
        let v4 = Ver::new(2, 0, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
    }

    #[test]
    fn test_ver_conversions() {
        let ver = Ver::new(1, 1, 8);

        // Test conversion to bytes
        let bytes: [u8; 3] = ver.into();
        assert_eq!(bytes, [1, 1, 8]);

        // Test conversion to string
        let string: String = ver.into();
        assert_eq!(string, "1.1.8");

        // Test conversion from bytes
        let ver2 = Ver::from([1, 1, 8]);
        assert_eq!(ver, ver2);
    }
}
