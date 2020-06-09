use crate::types::account;
use crate::types::hash::Hash;
use crate::types::traits::validator::Validator;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// ValidatorSet is the full validator set.
/// It exposes its hash and its total power.
pub trait ValidatorSet<V>: Clone + Debug + Serialize + DeserializeOwned
where
    V: Validator,
{
    /// Hash of the validator set.
    fn hash(&self) -> Hash;

    /// Total voting power of the set
    fn total_power(&self) -> u64;

    fn validator(&self, val_id: account::Id) -> Option<V>;

    fn intersect(&self, validator_set: &Self) -> Self;

    fn number_of_validators(&self) -> usize;
}
