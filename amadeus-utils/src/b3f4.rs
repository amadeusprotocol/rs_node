/// Blake3 first 4 bytes - used for peer deduplication and indexing
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
