//! Custom, legacy serializers

use crate::types::block;
use crate::types::block::parts;
use crate::types::hash::Hash;
use serde::{de::Error as _, Deserialize, Deserializer};
use std::str::FromStr;

// Todo: Refactor the "Option"-based serializers below.
//  Most of them are not needed if the structs are defined well (with enums).

/// Option<Hash> deserialization
pub(crate) fn parse_non_empty_hash<'de, D>(deserializer: D) -> Result<Option<Hash>, D::Error>
where
    D: Deserializer<'de>,
{
    let o: Option<String> = Option::deserialize(deserializer)?;
    match o.filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => Ok(Some(
            Hash::from_str(&s).map_err(|err| D::Error::custom(format!("{}", err)))?,
        )),
    }
}

/// Parse empty block id as None.
pub(crate) fn parse_non_empty_block_id<'de, D>(
    deserializer: D,
) -> Result<Option<block::id::Id>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Parts {
        total: u64,
        hash: String,
    }
    #[derive(Deserialize)]
    struct BlockId {
        hash: String,
        part_set_header: Parts,
    }
    if let Some(tmp_id) = <Option<BlockId>>::deserialize(deserializer)? {
        if tmp_id.hash.is_empty() {
            Ok(None)
        } else {
            Ok(Some(block::id::Id {
                hash: Hash::from_str(&tmp_id.hash)
                    .map_err(|err| D::Error::custom(format!("{}", err)))?,
                part_set_header: if tmp_id.part_set_header.hash.is_empty() {
                    None
                } else {
                    Some(parts::Header {
                        total: tmp_id.part_set_header.total,
                        hash: Hash::from_str(&tmp_id.part_set_header.hash)
                            .map_err(|err| D::Error::custom(format!("{}", err)))?,
                    })
                },
            }))
        }
    } else {
        Ok(None)
    }
}
