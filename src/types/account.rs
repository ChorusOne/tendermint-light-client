use crate::errors::{Error, Kind};
use ripemd160::Ripemd160;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use signatory::{ecdsa::secp256k1};
use std::fmt;
use std::fmt::{Debug, Display};
use std::str::FromStr;
use subtle::ConstantTimeEq;
use subtle_encoding::hex;

const LENGTH: usize = 20;

/// Account IDs
#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Id([u8; LENGTH]);

impl Id {
    /// Create a new account ID from raw bytes
    pub fn new(bytes: [u8; LENGTH]) -> Id {
        Id(bytes)
    }

    /// Borrow the account ID as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl ConstantTimeEq for Id {
    #[inline]
    fn ct_eq(&self, other: &Id) -> subtle::Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "account::Id({})", self)
    }
}

// RIPEMD160(SHA256(pk))
impl From<secp256k1::PublicKey> for Id {
    fn from(pk: secp256k1::PublicKey) -> Id {
        let sha_digest = Sha256::digest(pk.as_bytes());
        let ripemd_digest = Ripemd160::digest(&sha_digest[..]);
        let mut bytes = [0u8; LENGTH];
        bytes.copy_from_slice(&ripemd_digest[..LENGTH]);
        Id(bytes)
    }
}

// SHA256(pk)[:20]
impl From<ed25519_dalek::PublicKey> for Id {
    fn from(pk: ed25519_dalek::PublicKey) -> Id {
        let digest = Sha256::digest(pk.as_bytes());
        let mut bytes = [0u8; LENGTH];
        bytes.copy_from_slice(&digest[..LENGTH]);
        Id(bytes)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(|_| {
            de::Error::custom(format!(
                "expected {}-character hex string, got {:?}",
                LENGTH * 2,
                s
            ))
        })
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

/// Decode account ID from hex
impl FromStr for Id {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept either upper or lower case hex
        let bytes = hex::decode_upper(s)
            .or_else(|_| hex::decode(s))
            .map_err(|_| Kind::Parse)?;

        if bytes.len() != LENGTH {
            return Err(Kind::Parse.into());
        }

        let mut result_bytes = [0u8; LENGTH];
        result_bytes.copy_from_slice(&bytes);
        Ok(Id(result_bytes))
    }
}
