//! Block parts

use crate::types::hash::Hash;

/// Block parts header
#[derive(Serialize, Deserialize, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Header {
    /// Number of parts in this block
    #[serde(with = "crate::serialization::from_str")]
    pub total: u64,

    /// Hash of the parts set header,
    pub hash: Hash,
}

impl Header {
    /// Create a new parts header
    pub fn new(total: u64, hash: Hash) -> Self {
        Header { total, hash }
    }
}
