//! Cryptographic (a.k.a. digital) signatures

use serde::{de::Error as __, Deserialize, Deserializer, Serialize, Serializer};
use signatory::ecdsa::curve::Secp256k1;
use signatory::signature::Signature as _;
use std::convert::TryInto;
use subtle_encoding::base64;

const ED25519_SIGNATURE_SERIALIZATION_PREFIX: [u8; 5] = [0x17, 0x25, 0xDF, 0x65, 0x21];
const SECP256K1_SIGNATURE_SERIALIZATION_PREFIX: [u8; 5] = [0x18, 0x26, 0xEA, 0x66, 0x22];

/// Signatures
#[derive(Clone, Debug, PartialEq)]
pub enum Signature {
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

        if bytes.len() < 5 {
            return Err(D::Error::invalid_length(bytes.len(), &"greater than 5"));
        }

        // Unwrap is okay here, since we are hard-coding the range
        match &bytes[0..5].try_into().unwrap() {
            &ED25519_SIGNATURE_SERIALIZATION_PREFIX => Ok(Signature::Ed25519(
                signatory::ed25519::Signature::from_bytes(&bytes[5..])
                    .map_err(|e| D::Error::custom(format!("{}", e)))?,
            )),
            &SECP256K1_SIGNATURE_SERIALIZATION_PREFIX => Ok(Signature::Secp256k1(
                signatory::ecdsa::FixedSignature::<Secp256k1>::from_bytes(&bytes[5..])
                    .map_err(|e| D::Error::custom(format!("{}", e)))?,
            )),
            unknown_prefix => Err(D::Error::custom(format!(
                "Expected type prefix: {:?} or {:?}, instead found: {:?}",
                ED25519_SIGNATURE_SERIALIZATION_PREFIX,
                SECP256K1_SIGNATURE_SERIALIZATION_PREFIX,
                unknown_prefix
            ))),
        }
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = match self {
            Signature::Ed25519(sig) => {
                let mut key_bytes = ED25519_SIGNATURE_SERIALIZATION_PREFIX.to_vec();
                key_bytes.extend(sig.as_ref());
                key_bytes
            }
            Signature::Secp256k1(sig) => {
                let mut key_bytes = SECP256K1_SIGNATURE_SERIALIZATION_PREFIX.to_vec();
                key_bytes.extend(sig.as_ref());
                key_bytes
            }
        };
        String::from_utf8(base64::encode(bytes))
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

#[cfg(test)]
mod tests {
    use crate::Signature;
    use serde::Serialize;
    use signatory::ecdsa::curve::Secp256k1;
    use signatory::signature::Signature as _;
    use subtle_encoding::base64;

    #[test]
    fn test_signature_serde() {
        let ed25519_sig = Signature::Ed25519(signatory::ed25519::Signature::new([1; 64]));
        let secp256k1_sig = Signature::Secp256k1(
            signatory::ecdsa::FixedSignature::<Secp256k1>::from_bytes([2 as u8; 64].as_ref())
                .unwrap(),
        );
        let encoded_ed25519_sig = serde_json::to_string(&ed25519_sig).unwrap();
        let encoded_secp256k1_sig = serde_json::to_string(&secp256k1_sig).unwrap();

        // Deserialization from string should reproduce exact object
        assert_eq!(
            serde_json::from_str::<Signature>(encoded_ed25519_sig.as_ref()).unwrap(),
            ed25519_sig
        );
        assert_eq!(
            serde_json::from_str::<Signature>(encoded_secp256k1_sig.as_ref()).unwrap(),
            secp256k1_sig
        );

        // Deserialization with string less than 5 should return an error
        let invalid_serialization =
            serde_json::to_string::<String>(&String::from_utf8(base64::encode(b"ab")).unwrap())
                .unwrap();
        let result = serde_json::from_str::<Signature>(invalid_serialization.as_str());
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            "invalid length 2, expected greater than 5"
        );

        // Deserialization with invalid prefix should return an error
        let invalid_serialization = serde_json::to_string::<String>(
            &String::from_utf8(base64::encode(b"abcdefgh")).unwrap(),
        )
        .unwrap();
        let result = serde_json::from_str::<Signature>(invalid_serialization.as_str());
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), "Expected type prefix: [23, 37, 223, 101, 33] or [24, 38, 234, 102, 34], instead found: [97, 98, 99, 100, 101]");
    }
}
