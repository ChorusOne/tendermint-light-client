use crate::types::chain;
use crate::types::hash::Hash;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::time::SystemTime;

pub type Height = u64;

/// Header contains meta data about the block -
/// the height, the time, the hash of the validator set
/// that should sign this header, and the hash of the validator
/// set that should sign the next header.
pub trait Header: Clone + Debug + Serialize + DeserializeOwned {
    /// The header's notion of (bft-)time.
    /// We assume it can be converted to SystemTime.
    type Time: Into<SystemTime>;

    fn chain_id(&self) -> chain::Id;
    fn height(&self) -> Height;
    fn bft_time(&self) -> Self::Time;
    fn validators_hash(&self) -> Hash;
    fn next_validators_hash(&self) -> Hash;

    /// Hash of the header (ie. the hash of the block).
    fn hash(&self) -> Hash;
}
