//! Cryptographic (a.k.a. digital) signatures
use base64;
use core::fmt;
use serde::de::Visitor;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

#[derive(PartialEq, Debug, Clone)]
pub struct Signature(Vec<u8>);

impl Signature {
    pub fn raw(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(base64::encode(&self).as_str())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignatureVisitor;
        impl<'de> Visitor<'de> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("base64 encoded array of bytes")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Signature(base64::decode(v).map_err(|e| {
                    de::Error::custom(format!("unable to decode string to base64, error: {}", e))
                })?))
            }
        }
        deserializer.deserialize_str(SignatureVisitor)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_slice()
    }
}
