use crate::types::hash::Hash;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// ValidatorSet is the full validator set.
/// It exposes its hash and its total power.
pub trait ValidatorSet: Clone + Debug + Serialize + DeserializeOwned {
    /// Hash of the validator set.
    fn hash(&self) -> Hash;

    /// Total voting power of the set
    fn total_power(&self) -> u64;
}
