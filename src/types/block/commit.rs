use crate::errors::{Error, Kind};
use crate::types::block::commit_sigs::CommitSig;
use crate::types::block::header;
use crate::types::block::height::Height;
use crate::types::block::id::Id;
use crate::types::block::traits::commit::ProvableCommit;
use crate::types::traits::validator::Validator;
use crate::types::traits::validator_set::ValidatorSet as _;
use crate::types::validator::Set;
use crate::types::vote::vote;
use crate::types::{account, chain, hash};
use anomaly::fail;
use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::fmt::Debug;
use std::ops::Deref;
use std::slice;

/// Commit contains the justification (ie. a set of signatures) that a block was committed by a set
/// of validators.
/// TODO: Update links below!
/// <https://github.com/tendermint/tendermint/blob/51dc810d041eaac78320adc6d53ad8b160b06601/types/block.go#L486-L502>
/// <https://github.com/tendermint/tendermint/blob/master/docs/spec/blockchain/blockchain.md#lastcommit>
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Commit {
    /// Block height
    pub height: Height,

    /// Round
    pub round: u64,

    /// Block ID
    pub block_id: Id,

    /// Signatures
    pub signatures: CommitSigs,
}

/// CommitSigs which certify that a block is valid
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CommitSigs(Vec<CommitSig>);

impl CommitSigs {
    /// Create a new CommitSig collection
    pub fn new<I>(into_commit_sigs: I) -> Self
    where
        I: Into<Vec<CommitSig>>,
    {
        Self(into_commit_sigs.into())
    }

    /// Convert this collection of CommitSigs into a vector
    pub fn into_vec(self) -> Vec<CommitSig> {
        self.0
    }

    /// Iterate over the CommitSigs in the collection
    pub fn iter(&self) -> slice::Iter<'_, CommitSig> {
        self.0.iter()
    }
}

impl AsRef<[CommitSig]> for CommitSigs {
    fn as_ref(&self) -> &[CommitSig] {
        self.0.as_slice()
    }
}

impl Deref for CommitSigs {
    type Target = [CommitSig];

    fn deref(&self) -> &[CommitSig] {
        self.as_ref()
    }
}

impl PartialEq for CommitSigs {
    fn eq(&self, other: &Self) -> bool {
        // Note: this is used for asserts in tests:
        self.0.clone().into_iter().eq(other.0.clone().into_iter())
    }
}

impl Commit {
    /// This is a private helper method to iterate over the underlying
    /// votes to compute the voting power (see `voting_power_in` below).
    pub fn signed_votes(&self, chain_id: chain::Id) -> Vec<Result<vote::SignedVote, Error>> {
        let mut votes = non_absent_votes(&self);
        votes
            .drain(..)
            .map(|vote| {
                let possible_vote = (&vote).try_into();
                if possible_vote.is_err() {
                    Err(possible_vote.err().unwrap())
                } else {
                    Ok(vote::SignedVote::new(
                        possible_vote.unwrap(),
                        &chain_id.to_string(),
                        vote.validator_address,
                        vote.signature,
                    ))
                }
            })
            .collect()
    }
}

// this private helper function does *not* do any validation but extracts
// all non-BlockIDFlagAbsent votes from the commit:
fn non_absent_votes(commit: &Commit) -> Vec<vote::Vote> {
    let mut votes: Vec<vote::Vote> = Default::default();
    for (i, commit_sig) in commit.signatures.iter().enumerate() {
        let extracted_validator_address;
        let extracted_timestamp;
        let extracted_signature;
        let block_id;
        match commit_sig {
            CommitSig::BlockIDFlagAbsent { .. } => continue,
            CommitSig::BlockIDFlagCommit {
                validator_address,
                timestamp,
                signature,
            } => {
                extracted_validator_address = validator_address;
                extracted_timestamp = timestamp;
                extracted_signature = signature;
                block_id = Some(commit.block_id.clone());
            }
            CommitSig::BlockIDFlagNil {
                validator_address,
                timestamp,
                signature,
            } => {
                extracted_validator_address = validator_address;
                extracted_timestamp = timestamp;
                extracted_signature = signature;
                block_id = None;
            }
        }
        votes.push(vote::Vote {
            vote_type: vote::Type::Precommit,
            height: commit.height,
            round: commit.round,
            block_id,
            timestamp: *extracted_timestamp,
            validator_address: *extracted_validator_address,
            validator_index: u64::try_from(i)
                .expect("usize to u64 conversion failed for validator index"),
            signature: extracted_signature.clone(),
        })
    }
    votes
}

impl<V> ProvableCommit<V> for Commit
where
    V: Validator,
{
    type ValidatorSet = Set<V>;

    fn header_hash(&self) -> hash::Hash {
        self.block_id.hash
    }
    fn voting_power_in(
        &self,
        chain_id: chain::Id,
        validators: &Self::ValidatorSet,
    ) -> Result<u64, Error> {
        let mut seen_votes: HashSet<account::Id> = HashSet::new();
        // NOTE we don't know the validators that committed this block,
        // so we have to check for each vote if its validator is already known.
        let mut signed_power = 0u64;
        for possible_signed_vote in self.signed_votes(chain_id) {
            if possible_signed_vote.is_err() {
                return Err(possible_signed_vote.err().unwrap());
            }
            let vote = possible_signed_vote.unwrap();

            // Only count if this vote is from a known validator.
            let val_id = vote.validator_id();

            let val = match validators.validator(val_id) {
                Some(v) => v,
                None => continue,
            };

            // Fail if we have seen vote from this validator before
            if seen_votes.contains(&val_id) {
                fail!(
                    Kind::ImplementationSpecific,
                    "Duplicate vote found by validator {:?}",
                    val_id,
                );
            } else {
                seen_votes.insert(val_id);
            }

            // check vote is valid from validator
            let sign_bytes = vote.sign_bytes();

            if !val.verify_signature(&sign_bytes, vote.signature()) {
                fail!(
                    Kind::ImplementationSpecific,
                    "Couldn't verify signature {:?} with validator {:?} on sign_bytes {:?}",
                    vote.signature(),
                    val,
                    sign_bytes,
                );
            }
            signed_power += val.power();
        }

        Ok(signed_power)
    }

    fn validate(&self, vals: &Self::ValidatorSet) -> Result<(), Error> {
        // TODO: self.block_id cannot be zero in the same way as in go
        // clarify if this another encoding related issue
        if self.signatures.len() == 0 {
            fail!(Kind::ImplementationSpecific, "no signatures for commit");
        }
        if self.signatures.len() != vals.number_of_validators() {
            fail!(
                Kind::ImplementationSpecific,
                "commit signatures count: {} doesn't match validators count: {}",
                self.signatures.len(),
                vals.number_of_validators()
            );
        }

        // TODO: this last check is only necessary if we do full verification (2/3)
        // https://github.com/informalsystems/tendermint-rs/issues/281
        // returns ImplementationSpecific error if it detects a signer
        // that is not present in the validator set:
        for commit_sig in self.signatures.iter() {
            let extracted_validator_address;
            match commit_sig {
                // Todo: https://github.com/informalsystems/tendermint-rs/issues/260 - CommitSig validator address missing in Absent vote
                CommitSig::BlockIDFlagAbsent => continue,
                CommitSig::BlockIDFlagCommit {
                    validator_address, ..
                } => extracted_validator_address = validator_address,
                CommitSig::BlockIDFlagNil {
                    validator_address, ..
                } => extracted_validator_address = validator_address,
            }
            if vals.validator(*extracted_validator_address).is_none() {
                fail!(
                    Kind::ImplementationSpecific,
                    "Found a faulty signer ({}) not present in the validator set ({})",
                    extracted_validator_address,
                    vals.hash()
                );
            }
        }

        Ok(())
    }
}

/// SignedHeader bundles a [`Header`] and a [`Commit`] for convenience.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedHeader<C, H> {
    commit: C,
    header: H,
}

impl<C, H> SignedHeader<C, H> {
    pub fn new(commit: C, header: H) -> Self {
        Self { commit, header }
    }

    pub fn commit(&self) -> &C {
        &self.commit
    }

    pub fn header(&self) -> &H {
        &self.header
    }
}

pub type LightSignedHeader = SignedHeader<Commit, header::Header>;
