use std::fmt::Debug;

use crate::merkle_tree::simple_hash_from_byte_vectors;
use crate::types::account;
use crate::types::account::Id;
use crate::types::amino::message::AminoMessage;
use crate::types::hash::Hash;
use crate::types::proposer_priority::ProposerPriority;
use crate::types::pubkey::PublicKey;
use crate::types::traits;
use crate::types::traits::validator::Validator;
use crate::types::vote::power::Power as VotePower;
use prost_amino_derive::Message;
use serde::{Deserialize, Deserializer};
use signatory::{
    ed25519,
    signature::{Signature, Verifier},
};
use signatory_dalek::Ed25519Verifier;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;

/// Validator set contains a vector of validators
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Set<V>
where
    V: Validator,
{
    #[serde(deserialize_with = "parse_vals")]
    validators: Vec<V>,
}

impl<V> Set<V>
where
    V: Validator,
{
    /// Create a new validator set.
    /// vals is mutable so it can be sorted by address.
    pub fn new(mut vals: Vec<V>) -> Set<V> {
        vals.sort_by(|v1, v2| v1.address().partial_cmp(&v2.address()).unwrap());
        vals.dedup_by(|a, b| a.address() == b.address());
        Set { validators: vals }
    }
}

impl<V> traits::validator_set::ValidatorSet<V> for Set<V>
where
    V: Validator,
{
    /// Compute the Merkle root of the validator set
    fn hash(&self) -> Hash {
        let validator_bytes: Vec<Vec<u8>> = self
            .validators
            .iter()
            .map(|validator| validator.hash_bytes())
            .collect();
        Hash::Sha256(simple_hash_from_byte_vectors(validator_bytes))
    }

    fn total_power(&self) -> u64 {
        self.validators.iter().fold(0u64, |total, val_info| {
            total + val_info.vote_power().value()
        })
    }

    fn validator(&self, val_id: account::Id) -> Option<V> {
        self.validators
            .iter()
            .find(|val| val.address() == val_id)
            .cloned()
    }

    fn intersect(&self, other: &Self) -> Self {
        let mut left_hashmap: HashMap<account::Id, V> =
            HashMap::from_iter(self.validators.iter().map(|v| (v.address(), v.clone())));
        let right_hashmap: HashMap<account::Id, V> =
            HashMap::from_iter(other.validators.iter().map(|v| (v.address(), v.clone())));

        let left_hashset: HashSet<account::Id> =
            HashSet::from_iter(left_hashmap.values().map(|v| v.address()));
        let right_hashset: HashSet<account::Id> =
            HashSet::from_iter(right_hashmap.values().map(|v| v.address()));

        let intersection = left_hashset
            .intersection(&right_hashset)
            .collect::<HashSet<&account::Id>>();

        left_hashmap.retain(|id, _| intersection.contains(id));

        Set::new(left_hashmap.drain().map(|(_, v)| v).collect())
    }

    fn number_of_validators(&self) -> usize {
        self.validators.len()
    }
}

// TODO: maybe add a type (with an Option<Vec<Info>> field) instead
// for light client integration tests only
fn parse_vals<'de, D, V>(d: D) -> Result<Vec<V>, D::Error>
where
    D: Deserializer<'de>,
    V: Validator,
{
    Deserialize::deserialize(d).map(|x: Option<_>| x.unwrap_or_default())
}

/// Validator information
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct Info {
    /// Validator account address
    address: account::Id,

    /// Validator public key
    pub_key: PublicKey,

    /// Validator voting power
    #[serde(alias = "power")]
    voting_power: VotePower,

    /// Validator proposer priority
    proposer_priority: Option<ProposerPriority>,
}

impl Validator for Info {
    /// Return the voting power of the validator.
    fn power(&self) -> u64 {
        self.voting_power.value()
    }

    /// Verify the given signature against the given sign_bytes using the validators
    /// public key.
    fn verify_signature(&self, sign_bytes: &[u8], signature: &[u8]) -> bool {
        if let Some(pk) = &self.pub_key.ed25519() {
            let verifier = Ed25519Verifier::from(pk);
            if let Ok(sig) = ed25519::Signature::from_bytes(signature) {
                return verifier.verify(sign_bytes, &sig).is_ok();
            }
        }
        false
    }

    fn address(&self) -> Id {
        self.address
    }

    fn vote_power(&self) -> VotePower {
        self.voting_power
    }

    fn proposer_priority(&self) -> Option<ProposerPriority> {
        self.proposer_priority
    }

    fn hash_bytes(&self) -> Vec<u8> {
        AminoMessage::bytes_vec(&InfoHashable::from(self))
    }
}

impl From<PublicKey> for account::Id {
    fn from(pub_key: PublicKey) -> account::Id {
        match pub_key {
            PublicKey::Ed25519(pk) => account::Id::from(pk),
            PublicKey::Secp256k1(pk) => account::Id::from(pk),
        }
    }
}

impl Info {
    /// Create a new validator.
    pub fn new(pk: PublicKey, vp: VotePower) -> Info {
        Info {
            address: account::Id::from(pk),
            pub_key: pk,
            voting_power: vp,
            proposer_priority: None,
        }
    }
}

/// InfoHashable is the form of the validator used for computing the Merkle tree.
/// It does not include the address, as that is redundant with the pubkey,
/// nor the proposer priority, as that changes with every block even if the validator set didn't.
/// It contains only the pubkey and the voting power, and is amino encoded.
/// TODO: currently only works for Ed25519 pubkeys
#[derive(Clone, PartialEq, Message)]
struct InfoHashable {
    #[prost_amino(bytes, tag = "1", amino_name = "tendermint/PubKeyEd25519")]
    pub pub_key: Vec<u8>,
    #[prost_amino(uint64, tag = "2")]
    voting_power: u64,
}

/// Info -> InfoHashable
impl From<&Info> for InfoHashable {
    fn from(info: &Info) -> InfoHashable {
        InfoHashable {
            pub_key: info.pub_key.as_bytes(),
            voting_power: info.voting_power.value(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::types::pubkey::PublicKey::Ed25519;
    use crate::types::traits::validator_set::ValidatorSet;
    use crate::types::validator::{Info, Set};
    use crate::types::vote::power::Power;
    use rand::Rng;
    use signatory::ed25519;
    use std::convert::TryInto;

    fn generate_random_validators(number_of_validators: usize, vote_power: u64) -> Vec<Info> {
        let mut vals: Vec<Info> = vec![];

        let mut rng = rand::thread_rng();

        for _ in 0..number_of_validators {
            let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen_range(0, 255)).collect();
            let pub_key = Ed25519(ed25519::PublicKey(
                random_bytes.as_slice().try_into().unwrap(),
            ));
            vals.push(Info::new(pub_key, Power::new(vote_power)));
        }

        vals
    }

    #[test]
    fn test_validator_set_intersection() {
        let validators = generate_random_validators(100, 1);
        let first_validator_set = Set::new(validators[0..60].to_vec());
        let second_validator_set = Set::new(validators[40..90].to_vec());
        let intersection = first_validator_set.intersect(&second_validator_set);
        assert_eq!(intersection.number_of_validators(), 20);
        assert_eq!(intersection.total_power(), 20);

        // 0..40 should only exists in first set
        for i in 0..40 {
            assert!(intersection.validator(validators[i].address).is_none());
            assert!(first_validator_set
                .validator(validators[i].address)
                .is_some());
            assert!(second_validator_set
                .validator(validators[i].address)
                .is_none());
        }
        // Intersection (40..60) should exists in all three set
        for i in 40..60 {
            assert!(intersection.validator(validators[i].address).is_some());
            assert!(first_validator_set
                .validator(validators[i].address)
                .is_some());
            assert!(second_validator_set
                .validator(validators[i].address)
                .is_some());
        }
        // 60 to 90 should exists only in second set
        for i in 60..90 {
            assert!(intersection.validator(validators[i].address).is_none());
            assert!(first_validator_set
                .validator(validators[i].address)
                .is_none());
            assert!(second_validator_set
                .validator(validators[i].address)
                .is_some());
        }

        let first_validator_set = Set::new(validators[0..60].to_vec());
        let second_validator_set = Set::new(validators[60..90].to_vec());
        let intersection = first_validator_set.intersect(&second_validator_set);
        assert_eq!(intersection.number_of_validators(), 0);
        assert_eq!(intersection.total_power(), 0);
    }
}
