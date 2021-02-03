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
use core::fmt;
use prost_amino_derive::Message;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ed25519_dalek::{Signature, Verifier};
use std::convert::TryFrom;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::marker::PhantomData;

/// Validator set contains a vector of validators
#[derive(Clone, Debug, PartialEq)]
pub struct Set<V>
where
    V: Validator,
{
    validators: Vec<V>,
}

impl<V> Serialize for Set<V>
where
    V: Validator,
{
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.validators.len()))?;
        for validator in &self.validators {
            seq.serialize_element(validator)?;
        }
        seq.end()
    }
}

impl<'de, V> Deserialize<'de> for Set<V>
where
    V: Validator,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        struct SetVisitor<V>
        where
            V: Validator,
        {
            _phantom_data: PhantomData<V>,
        };
        impl<'de, V> Visitor<'de> for SetVisitor<V>
        where
            V: Validator,
        {
            type Value = Set<V>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("sequence of objects implementing Validator trait")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, <A as SeqAccess<'de>>::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut validators: Vec<V> = vec![];
                while let Some(value) = seq.next_element()? {
                    validators.push(value);
                }
                Ok(Set::new(validators))
            }
        }

        deserializer.deserialize_seq(SetVisitor {
            _phantom_data: PhantomData,
        })
    }
}

impl<V> Set<V>
where
    V: Validator,
{
    /// Create a new validator set.
    /// vals is mutable so it can be sorted by address.
    pub fn new(mut vals: Vec<V>) -> Set<V> {
        vals.dedup_by(|a, b| a.address() == b.address());
        vals.sort_by(|v1, v2| v1.address().cmp(&v2.address()));
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
            if let Ok(sig) = Signature::try_from(signature) {
                return pk.verify(sign_bytes, &sig).is_ok()
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
    use crate::types::traits::{validator_set::ValidatorSet, validator::Validator};
    use crate::types::validator::{Info, Set};
    use crate::types::vote::power::Power;
    use crate::types::pubkey::PublicKey;
    use subtle_encoding::hex;

    fn generate_random_validators(number_of_validators: usize, vote_power: u64) -> Vec<Info> {
        let mut vals: Vec<Info> = vec![];
        let mut rng = rand::thread_rng();

        for _ in 0..number_of_validators {
            let keypair: ed25519_dalek::Keypair = ed25519_dalek::Keypair::generate(&mut rng);
            let pub_key = Ed25519(keypair.public);
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

    #[test]
    fn test_validate_signature() {
        let pk_bytes = hex::decode("330b745d9da896f6f89f288633d25b4608d53c0a03f53336c5b03713f1a95559").unwrap();
        let signed_bytes = hex::decode("f7d9e1b08c814154f60760e9cb7cd3c3618743f665b7af1661e9dbbab3ee005d7a4314fb992cade8a048bca5b5d27170450ca5ce87cfffb36d43a95d34b62c00").unwrap();

        let pub_key = PublicKey::from_raw_ed25519(&pk_bytes).unwrap();
        let info = Info::new(pub_key, Power::new(0));

        assert_eq!(
            info.verify_signature("test message".as_bytes(), &signed_bytes),
            true
        );

        assert_eq!(
            info.verify_signature("wrong test message".as_bytes(), &signed_bytes),
            false
        );
    }
}
