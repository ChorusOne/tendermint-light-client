use crate::types::amino as amino_types;
use crate::types::amino::message::AminoMessage;
use crate::types::block;
use crate::types::signature::Signature;
use crate::types::time::Time;
use crate::types::{account, amino, hash};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Votes are signed messages from validators for a particular block which
/// include information about the validator signing it.
///
/// <https://github.com/tendermint/tendermint/blob/master/docs/spec/blockchain/blockchain.md#vote>
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Vote {
    /// Type of vote (prevote or precommit)
    #[serde(rename = "type")]
    pub vote_type: Type,

    /// Block height
    pub height: block::height::Height,

    /// Round
    #[serde(with = "crate::serialization::from_str")]
    pub round: u64,

    /// Block ID
    #[serde(deserialize_with = "crate::serialization::custom::parse_non_empty_block_id")]
    pub block_id: Option<block::id::Id>,

    /// Timestamp
    pub timestamp: Time,

    /// Validator address
    pub validator_address: account::Id,

    /// Validator index
    #[serde(with = "crate::serialization::from_str")]
    pub validator_index: u64,

    /// Signature
    pub signature: Signature,
}

impl Vote {
    /// Is this vote a prevote?
    pub fn is_prevote(&self) -> bool {
        match self.vote_type {
            Type::Prevote => true,
            Type::Precommit => false,
        }
    }

    /// Is this vote a precommit?
    pub fn is_precommit(&self) -> bool {
        match self.vote_type {
            Type::Precommit => true,
            Type::Prevote => false,
        }
    }

    /// Returns block_id.hash
    pub fn header_hash(&self) -> Option<hash::Hash> {
        match &self.block_id {
            Some(b) => Some(b.hash),
            None => None,
        }
    }
}

/// SignedVote is the union of a canonicalized vote, the signature on
/// the sign bytes of that vote and the id of the validator who signed it.
pub struct SignedVote {
    vote: amino::CanonicalVote,
    validator_address: account::Id,
    signature: Signature,
}

impl SignedVote {
    /// Create new SignedVote from provided canonicalized vote, validator id, and
    /// the signature of that validator.
    pub fn new(
        vote: amino::Vote,
        chain_id: &str,
        validator_address: account::Id,
        signature: Signature,
    ) -> SignedVote {
        let canonical_vote = amino::CanonicalVote::new(vote, chain_id);
        SignedVote {
            vote: canonical_vote,
            signature,
            validator_address,
        }
    }

    /// Return the id of the validator that signed this vote.
    pub fn validator_id(&self) -> account::Id {
        self.validator_address
    }

    /// Return the bytes (of the canonicalized vote) that were signed.
    pub fn sign_bytes(&self) -> Vec<u8> {
        self.vote.bytes_vec_length_delimited()
    }

    /// Return the actual signature on the canonicalized vote.
    pub fn signature(&self) -> &[u8] {
        self.signature.as_ref()
    }
}

/// Types of votes
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Type {
    /// Votes for blocks which validators observe are valid for a given round
    Prevote = 1,

    /// Votes to commit to a particular block for a given round
    Precommit = 2,
}

impl Type {
    /// Deserialize this type from a byte
    pub fn from_u8(byte: u8) -> Option<Type> {
        match byte {
            1 => Some(Type::Prevote),
            2 => Some(Type::Precommit),
            _ => None,
        }
    }

    /// Serialize this type as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Serialize this type as a 32-bit unsigned integer
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

impl Serialize for Type {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_u8().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Type {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let byte = u8::deserialize(deserializer)?;
        Type::from_u8(byte).ok_or_else(|| D::Error::custom(format!("invalid vote type: {}", byte)))
    }
}
