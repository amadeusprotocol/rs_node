use crate::Ver;

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error("message v2 is only {0} bytes")]
    WrongLength(usize),
    #[error("version format is invalid")]
    VersionFormat,
    #[error("version is out of range, expected 0..=255")]
    VersionOutOfRange,
    #[error("bad public key length, expected 48 bytes, got {0}")]
    BadPkLen(usize),
    #[error("bad signature length, expected 96 bytes, got {0}")]
    BadSigLen(usize),
    #[error("invalid magic, expected 'AMA'")]
    InvalidMagic,
    #[error("invalid flags, expected 0b00000001, got {0}")]
    InvalidFlags(u8),
    #[error("message not signed")]
    NotSigned,
    #[error("invalid shard index, expected 0..=65535, got {0}")]
    InvalidShardIndex(u16),
    #[error("invalid shard total, expected 0..=65535, got {0}")]
    InvalidShardTotal(u16),
    #[error("invalid timestamp, expected 0..=18446744073709551615, got {0}")]
    InvalidTimestamp(u64),
    #[error("invalid original size, expected 0..=4294967295, got {0}")]
    InvalidOriginalSize(u32),
    #[error("version is not supported")]
    VersionNotSupported,
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

const EARLIEST_SUPPORTED_VERSION: Ver = Ver::new(1, 1, 7);

/// Message Format (Signed or Unsigned)
///
/// Signed format (flags = 0x01):
/// <<"AMA", version_3byte::3-binary, 0::7, 1::1, pk::48-binary, signature::96-binary,
///   shard_index::16, shard_total::16, ts_n::64, original_size::32,
///   msg_compressed_or_shard::binary>>
///
/// Unsigned format (flags = 0x00) - for bootstrap messages in v1.1.7+:
/// <<"AMA", version_3byte::3-binary, 0::8, pk::48-binary,
///   shard_index::16, shard_total::16, ts_n::64, original_size::32,
///   msg_compressed_or_shard::binary>>
///
/// Offset  Length  Field               Description
/// ──────────────────────────────────────────────────────────────────
/// 0-2     3       Magic               "AMA" (0x414D41)
/// 3-5     3       Version             3-byte version (e.g., 1.1.8)
/// 6       1       Flags               0x00=unsigned, 0x01=signed
/// 7-54    48      Public Key          BLS12-381 public key (48 bytes)
/// [If signed:]
/// 55-150  96      Signature           BLS12-381 signature (96 bytes)
/// 151-152 2       Shard Index         Current shard number (big-endian)
/// [If unsigned:]
/// 55-56   2       Shard Index         Current shard number (big-endian)
/// 153-154 2       Shard Total         Total shards * 2 (big-endian)
/// 155-162 8       Timestamp           Nanosecond timestamp (big-endian)
/// 163-166 4       Original Size       Size of original message (big-endian)
/// 167+    N       Payload/Shard       Message data or Reed-Solomon shard
#[derive(Debug, Clone)]
pub struct MessageV2 {
    pub version: Ver,
    pub pk: [u8; 48],
    pub signature: Option<[u8; 96]>, // Optional for unsigned messages (v1.1.7+ bootstrap)
    pub shard_index: u16,
    pub shard_total: u16,
    pub ts_nano: u64,
    pub original_size: u32,
    pub payload: Vec<u8>,
}

impl TryFrom<&[u8]> for MessageV2 {
    type Error = Error;
    fn try_from(bin: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_inner(bin)
    }
}

impl TryInto<Vec<u8>> for MessageV2 {
    type Error = Error;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        if self.pk.len() != 48 {
            return Err(Error::BadPkLen(self.pk.len()));
        }

        let ver = self.version.as_bytes();

        // Calculate capacity based on whether we have a signature
        let capacity = if self.signature.is_some() {
            3 + 3 + 1 + 48 + 96 + 2 + 2 + 8 + 4 + self.payload.len()
        } else {
            3 + 3 + 1 + 48 + 2 + 2 + 8 + 4 + self.payload.len()
        };

        let mut out = Vec::with_capacity(capacity);

        // "AMA"
        out.extend_from_slice(b"AMA");

        // version_3byte
        out.extend_from_slice(&ver);

        // flags: 0x00 for unsigned, 0x01 for signed
        if let Some(ref sig) = self.signature {
            if sig.len() != 96 {
                return Err(Error::BadSigLen(sig.len()));
            }
            out.push(0b0000_0001); // signed

            // pk (48), signature (96)
            out.extend_from_slice(&self.pk);
            out.extend_from_slice(sig);
        } else {
            out.push(0b0000_0000); // unsigned

            // pk (48), NO signature for unsigned
            out.extend_from_slice(&self.pk);
        }

        // shard_index::16, shard_total::16 (big-endian)
        out.extend_from_slice(&self.shard_index.to_be_bytes());
        out.extend_from_slice(&self.shard_total.to_be_bytes());

        // ts_n::64 (big-endian)
        out.extend_from_slice(&self.ts_nano.to_be_bytes());

        // original_size::32 (big-endian)
        out.extend_from_slice(&self.original_size.to_be_bytes());

        // msg_compressed_or_shard::binary (rest)
        out.extend_from_slice(&self.payload);

        Ok(out)
    }
}

impl MessageV2 {
    fn try_from_inner(bin: &[u8]) -> Result<Self, Error> {
        // minimum header length for unsigned message (no signature)
        if bin.len() < 3 + 3 + 1 + 48 + 2 + 2 + 8 + 4 {
            return Err(Error::WrongLength(bin.len()));
        }

        // magic
        if &bin[0..3] != b"AMA" {
            return Err(Error::InvalidMagic);
        }

        let version_bytes = &bin[3..6];
        let version = Ver::new(version_bytes[0], version_bytes[1], version_bytes[2]);
        
        if version < EARLIEST_SUPPORTED_VERSION {
            return Err(Error::VersionNotSupported);
        }

        let flag_byte = bin[6];

        // Parse based on whether message is signed or unsigned
        if flag_byte == 0b00000001 {
            // SIGNED message (legacy format, still used for non-bootstrap messages)
            if bin.len() < 3 + 3 + 1 + 48 + 96 + 2 + 2 + 8 + 4 {
                return Err(Error::WrongLength(bin.len()));
            }

            let pk_start = 7;
            let pk_end = pk_start + 48;
            let pk = bin[pk_start..pk_end].try_into().expect("pk should be 48 bytes");

            let sig_start = pk_end;
            let sig_end = sig_start + 96;
            let signature = bin[sig_start..sig_end].try_into().expect("signature should be 96 bytes");

            let shard_index = u16::from_be_bytes(bin[sig_end..sig_end + 2].try_into().unwrap());
            let shard_total = u16::from_be_bytes(bin[sig_end + 2..sig_end + 4].try_into().unwrap());

            let ts_nano = u64::from_be_bytes(bin[sig_end + 4..sig_end + 12].try_into().unwrap());
            let original_size = u32::from_be_bytes(bin[sig_end + 12..sig_end + 16].try_into().unwrap());

            let payload = bin[sig_end + 16..].to_vec();

            Ok(Self {
                version,
                pk,
                signature: Some(signature),
                shard_index,
                shard_total,
                ts_nano,
                original_size,
                payload,
            })
        } else if flag_byte == 0b00000000 {
            // UNSIGNED message (v1.1.7+ bootstrap format)
            let pk_start = 7;
            let pk_end = pk_start + 48;
            let pk = bin[pk_start..pk_end].try_into().expect("pk should be 48 bytes");

            // No signature for unsigned messages
            let metadata_start = pk_end;

            let shard_index = u16::from_be_bytes(bin[metadata_start..metadata_start + 2].try_into().unwrap());
            let shard_total = u16::from_be_bytes(bin[metadata_start + 2..metadata_start + 4].try_into().unwrap());

            let ts_nano = u64::from_be_bytes(bin[metadata_start + 4..metadata_start + 12].try_into().unwrap());
            let original_size = u32::from_be_bytes(bin[metadata_start + 12..metadata_start + 16].try_into().unwrap());

            let payload = bin[metadata_start + 16..].to_vec();

            Ok(Self { version, pk, signature: None, shard_index, shard_total, ts_nano, original_size, payload })
        } else {
            // Invalid flags
            Err(Error::InvalidFlags(flag_byte))
        }
    }

}
