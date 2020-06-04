use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// TrustThreshold defines how much of the total voting power of a known
/// and trusted validator set is sufficient for a commit to be
/// accepted going forward.
pub trait TrustThreshold: Copy + Clone + Debug + Serialize + DeserializeOwned {
    fn is_enough_power(&self, signed_voting_power: u64, total_voting_power: u64) -> bool;
}
