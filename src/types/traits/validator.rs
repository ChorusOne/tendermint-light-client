use crate::types::account;
use crate::types::proposer_priority::ProposerPriority;
use crate::types::vote::power::Power as VotePower;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

pub trait Validator: Clone + Debug + Serialize + DeserializeOwned {
    fn power(&self) -> u64;

    fn verify_signature(&self, sign_bytes: &[u8], signature: &[u8]) -> bool;

    fn address(&self) -> account::Id;

    fn vote_power(&self) -> VotePower;

    fn proposer_priority(&self) -> Option<ProposerPriority>;

    fn hash_bytes(&self) -> Vec<u8>;
}
