//! Cryptographic (a.k.a. digital) signatures

use serde::{de::Error as __, Deserialize, Deserializer, Serialize, Serializer};
use signatory::signature::Signature as _;
use subtle_encoding::base64;
use signatory::ecdsa::curve::Secp256k1;

/// Signatures
#[derive(Clone, Debug, PartialEq)]
pub enum Signature {
    /// Ed25519 block signature
    Ed25519(signatory::ed25519::Signature),
    Secp256k1(signatory::ecdsa::FixedSignature<Secp256k1>),
}

impl Signature {
    /// Return the algorithm used to create this particular signature
    pub fn algorithm(self) -> Algorithm {
        match self {
            Signature::Ed25519(_) => Algorithm::Ed25519,
            Signature::Secp256k1(_) => Algorithm::EcdsaSecp256k1,
        }
    }

    /// Return the raw bytes of this signature
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Signature::Ed25519(sig) => sig.as_ref(),
            Signature::Secp256k1(sig) => sig.as_ref(),
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = base64::decode(String::deserialize(deserializer)?.as_bytes())
            .map_err(|e| D::Error::custom(format!("{}", e)))?;
        // TODO: add support for secp256k1 here.
        Ok(Signature::Ed25519(
            signatory::ed25519::Signature::from_bytes(&bytes)
                .map_err(|e| D::Error::custom(format!("{}", e)))?,
        ))
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::from_utf8(base64::encode(self.as_ref()))
            .unwrap()
            .serialize(serializer)
    }
}

/// Digital signature algorithms
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// ECDSA over secp256k1
    EcdsaSecp256k1,

    /// EdDSA over Curve25519
    Ed25519,
}
