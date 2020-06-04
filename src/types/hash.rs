//! Hash functions and their outputs

use std::{
    fmt::{self, Debug, Display},
    str::FromStr,
};

use anomaly::BoxError;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use subtle_encoding::{Encoding, Hex};

use crate::errors::{Error, Kind};

/// Output size for the SHA-256 hash function
pub const SHA256_HASH_SIZE: usize = 32;

/// Hash algorithms
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Algorithm {
    /// SHA-256
    Sha256,
}

/// Hash digests
#[derive(Copy, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub enum Hash {
    /// SHA-256 hashes
    Sha256([u8; SHA256_HASH_SIZE]),
}

impl Hash {
    #[allow(clippy::new_ret_no_self)]
    /// Create a new `Hash` with the given algorithm type
    pub fn new(alg: Algorithm, bytes: &[u8]) -> Result<Hash, Error> {
        match alg {
            Algorithm::Sha256 => {
                if bytes.len() == SHA256_HASH_SIZE {
                    let mut h = [0u8; SHA256_HASH_SIZE];
                    h.copy_from_slice(bytes);
                    Ok(Hash::Sha256(h))
                } else {
                    Err(Kind::Parse.into())
                }
            }
        }
    }

    /// Decode a `Hash` from upper-case hexadecimal
    pub fn from_hex_upper(alg: Algorithm, s: &str) -> Result<Hash, BoxError> {
        match alg {
            Algorithm::Sha256 => {
                let mut h = [0u8; SHA256_HASH_SIZE];
                Hex::upper_case().decode_to_slice(s.as_bytes(), &mut h)?;
                Ok(Hash::Sha256(h))
            }
        }
    }

    /// Return the digest algorithm used to produce this hash
    pub fn algorithm(self) -> Algorithm {
        match self {
            Hash::Sha256(_) => Algorithm::Sha256,
        }
    }

    /// Borrow the `Hash` as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Hash::Sha256(ref h) => h.as_ref(),
        }
    }
}

impl Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Hash::Sha256(_) => write!(f, "Hash::Sha256({})", self),
        }
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = match self {
            Hash::Sha256(ref h) => Hex::upper_case().encode_to_string(h).unwrap(),
        };

        write!(f, "{}", hex)
    }
}

impl FromStr for Hash {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, BoxError> {
        Self::from_hex_upper(Algorithm::Sha256, s)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(deserializer)?;

        if hex.is_empty() {
            Err(D::Error::custom("empty hash"))
        } else {
            Ok(Self::from_str(&hex).map_err(|e| D::Error::custom(format!("{}", e)))?)
        }
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}
