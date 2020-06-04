pub(crate) mod hexstring {
    use serde::{Deserialize, Deserializer, Serializer};
    use subtle_encoding::hex;

    /// Deserialize hexstring into Vec<u8>
    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = Option::<String>::deserialize(deserializer)?.unwrap_or_default();
        hex::decode_upper(&string)
            .or_else(|_| hex::decode(&string))
            .map_err(serde::de::Error::custom)
    }

    /// Serialize from T into hexstring
    pub(crate) fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        let hex_bytes = hex::encode(value.as_ref());
        let hex_string = String::from_utf8(hex_bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&hex_string)
    }
}
