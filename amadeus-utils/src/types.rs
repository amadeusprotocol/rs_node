/// Primitive types used in Amadeus

/// First 4 bytes of the BLAKE3 hash (for optimisation purposes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bincode::Encode, bincode::Decode)]
pub struct B3f4(pub [u8; 4]);

impl B3f4 {
    pub fn new(b3: &[u8; 32]) -> Self {
        B3f4([b3[0], b3[1], b3[2], b3[3]])
    }
}

impl serde::Serialize for B3f4 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::Bytes::new(&self.0).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for B3f4 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        let array: [u8; 4] = bytes.into_vec().try_into().map_err(|_| serde::de::Error::custom("expected 4 bytes"))?;
        Ok(B3f4(array))
    }
}

impl From<[u8; 4]> for B3f4 {
    fn from(bytes: [u8; 4]) -> Self {
        B3f4(bytes)
    }
}

impl From<B3f4> for [u8; 4] {
    fn from(b3f4: B3f4) -> Self {
        b3f4.0
    }
}

impl AsRef<[u8; 4]> for B3f4 {
    fn as_ref(&self) -> &[u8; 4] {
        &self.0
    }
}

impl std::ops::Deref for B3f4 {
    type Target = [u8; 4];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// BLS12-381 signature
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bincode::Encode, bincode::Decode)]
pub struct Signature(pub [u8; 96]);

impl Signature {
    pub fn new(bytes: [u8; 96]) -> Self {
        Signature(bytes)
    }
}

impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::Bytes::new(&self.0).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        let array: [u8; 96] = bytes.into_vec().try_into().map_err(|_| serde::de::Error::custom("expected 96 bytes"))?;
        Ok(Signature(array))
    }
}

impl From<[u8; 96]> for Signature {
    fn from(bytes: [u8; 96]) -> Self {
        Signature(bytes)
    }
}

impl From<Signature> for [u8; 96] {
    fn from(sig: Signature) -> Self {
        sig.0
    }
}

impl AsRef<[u8; 96]> for Signature {
    fn as_ref(&self) -> &[u8; 96] {
        &self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for Signature {
    type Target = [u8; 96];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = std::array::TryFromSliceError;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Ok(Signature(<[u8; 96]>::try_from(slice)?))
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = Vec<u8>;
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Signature(vec.try_into()?))
    }
}

impl PartialEq<[u8]> for Signature {
    fn eq(&self, other: &[u8]) -> bool {
        &self.0[..] == other
    }
}

impl PartialEq<Signature> for [u8] {
    fn eq(&self, other: &Signature) -> bool {
        self == &other.0[..]
    }
}

impl PartialEq<&[u8]> for Signature {
    fn eq(&self, other: &&[u8]) -> bool {
        &self.0[..] == *other
    }
}

impl std::borrow::Borrow<[u8]> for Signature {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl std::borrow::Borrow<[u8; 96]> for Signature {
    fn borrow(&self) -> &[u8; 96] {
        &self.0
    }
}

/// Blake3/SHA256 32byte hash
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, bincode::Encode, bincode::Decode)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn new(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

impl serde::Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::Bytes::new(&self.0).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        let array: [u8; 32] = bytes.into_vec().try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        Ok(Hash(array))
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

impl From<Hash> for [u8; 32] {
    fn from(hash: Hash) -> Self {
        hash.0
    }
}

impl AsRef<[u8; 32]> for Hash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for Hash {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for Hash {
    type Error = std::array::TryFromSliceError;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Ok(Hash(<[u8; 32]>::try_from(slice)?))
    }
}

impl TryFrom<Vec<u8>> for Hash {
    type Error = Vec<u8>;
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Hash(vec.try_into()?))
    }
}

impl PartialEq<[u8]> for Hash {
    fn eq(&self, other: &[u8]) -> bool {
        &self.0[..] == other
    }
}

impl PartialEq<Hash> for [u8] {
    fn eq(&self, other: &Hash) -> bool {
        self == &other.0[..]
    }
}

impl PartialEq<&[u8]> for Hash {
    fn eq(&self, other: &&[u8]) -> bool {
        &self.0[..] == *other
    }
}

impl PartialEq<[u8; 32]> for Hash {
    fn eq(&self, other: &[u8; 32]) -> bool {
        &self.0 == other
    }
}

impl PartialEq<Hash> for [u8; 32] {
    fn eq(&self, other: &Hash) -> bool {
        self == &other.0
    }
}

impl std::borrow::Borrow<[u8]> for Hash {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl std::borrow::Borrow<[u8; 32]> for Hash {
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

/// BLS12-381 public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bincode::Encode, bincode::Decode)]
pub struct PublicKey(pub [u8; 48]);

impl PublicKey {
    pub fn new(bytes: [u8; 48]) -> Self {
        PublicKey(bytes)
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::Bytes::new(&self.0).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        let array: [u8; 48] = bytes.into_vec().try_into().map_err(|_| serde::de::Error::custom("expected 48 bytes"))?;
        Ok(PublicKey(array))
    }
}

impl From<[u8; 48]> for PublicKey {
    fn from(bytes: [u8; 48]) -> Self {
        PublicKey(bytes)
    }
}

impl From<PublicKey> for [u8; 48] {
    fn from(pk: PublicKey) -> Self {
        pk.0
    }
}

impl AsRef<[u8; 48]> for PublicKey {
    fn as_ref(&self) -> &[u8; 48] {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for PublicKey {
    type Target = [u8; 48];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = std::array::TryFromSliceError;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Ok(PublicKey(<[u8; 48]>::try_from(slice)?))
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = Vec<u8>;
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(PublicKey(vec.try_into()?))
    }
}

impl PartialEq<[u8]> for PublicKey {
    fn eq(&self, other: &[u8]) -> bool {
        &self.0[..] == other
    }
}

impl PartialEq<PublicKey> for [u8] {
    fn eq(&self, other: &PublicKey) -> bool {
        self == &other.0[..]
    }
}

impl PartialEq<&[u8]> for PublicKey {
    fn eq(&self, other: &&[u8]) -> bool {
        &self.0[..] == *other
    }
}

impl std::borrow::Borrow<[u8]> for PublicKey {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl std::borrow::Borrow<[u8; 48]> for PublicKey {
    fn borrow(&self) -> &[u8; 48] {
        &self.0
    }
}
