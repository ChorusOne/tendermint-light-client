use std::fmt::Debug;

use crate::merkle_tree::simple_hash_from_byte_vectors;
use crate::types::account;
use crate::types::amino::message::AminoMessage;
use crate::types::hash::Hash;
use crate::types::pubkey::PublicKey;
use crate::types::traits;
use crate::types::vote::power::Power as VotePower;
use prost_amino_derive::Message;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use signatory::{
    ed25519,
    signature::{Signature, Verifier},
};
use signatory_dalek::Ed25519Verifier;

/// Validator set contains a vector of validators
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Set {
    #[serde(deserialize_with = "parse_vals")]
    validators: Vec<Info>,
}

impl Set {
    /// Create a new validator set.
    /// vals is mutable so it can be sorted by address.
    pub fn new(mut vals: Vec<Info>) -> Set {
        vals.sort_by(|v1, v2| v1.address.partial_cmp(&v2.address).unwrap());
        Set { validators: vals }
    }

    /// Get Info of the underlying validators.
    pub fn validators(&self) -> &Vec<Info> {
        &self.validators
    }
}

impl traits::validator_set::ValidatorSet for Set {
    /// Compute the Merkle root of the validator set
    fn hash(&self) -> Hash {
        let validator_bytes: Vec<Vec<u8>> = self
            .validators()
            .iter()
            .map(|validator| validator.hash_bytes())
            .collect();
        Hash::Sha256(simple_hash_from_byte_vectors(validator_bytes))
    }

    fn total_power(&self) -> u64 {
        self.validators().iter().fold(0u64, |total, val_info| {
            total + val_info.voting_power.value()
        })
    }
}

impl Set {
    /// Returns the validator with the given Id if its in the Set.
    pub fn validator(&self, val_id: account::Id) -> Option<Info> {
        self.validators
            .iter()
            .find(|val| val.address == val_id)
            .cloned()
    }
}

// TODO: maybe add a type (with an Option<Vec<Info>> field) instead
// for light client integration tests only
fn parse_vals<'de, D>(d: D) -> Result<Vec<Info>, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(d).map(|x: Option<_>| x.unwrap_or_default())
}

/// Validator information
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct Info {
    /// Validator account address
    pub address: account::Id,

    /// Validator public key
    pub pub_key: PublicKey,

    /// Validator voting power
    #[serde(alias = "power")]
    pub voting_power: VotePower,

    /// Validator proposer priority
    pub proposer_priority: Option<ProposerPriority>,
}

impl Info {
    /// Return the voting power of the validator.
    pub fn power(&self) -> u64 {
        self.voting_power.value()
    }

    /// Verify the given signature against the given sign_bytes using the validators
    /// public key.
    pub fn verify_signature(&self, sign_bytes: &[u8], signature: &[u8]) -> bool {
        if let Some(pk) = &self.pub_key.ed25519() {
            let verifier = Ed25519Verifier::from(pk);
            if let Ok(sig) = ed25519::Signature::from_bytes(signature) {
                return verifier.verify(sign_bytes, &sig).is_ok();
            }
        }
        false
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

impl Info {
    /// Returns the bytes to be hashed into the Merkle tree -
    /// the leaves of the tree. this is an amino encoding of the
    /// pubkey and voting power, so it includes the pubkey's amino prefix.
    pub fn hash_bytes(&self) -> Vec<u8> {
        AminoMessage::bytes_vec(&InfoHashable::from(self))
    }
}

/// Proposer priority
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ProposerPriority(i64);

impl ProposerPriority {
    /// Get the current voting power
    pub fn value(self) -> i64 {
        self.0
    }
}

impl From<ProposerPriority> for i64 {
    fn from(priority: ProposerPriority) -> i64 {
        priority.value()
    }
}

impl<'de> Deserialize<'de> for ProposerPriority {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(ProposerPriority(
            String::deserialize(deserializer)?
                .parse()
                .map_err(|e| D::Error::custom(format!("{}", e)))?,
        ))
    }
}

impl Serialize for ProposerPriority {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.to_string().serialize(serializer)
    }
}
