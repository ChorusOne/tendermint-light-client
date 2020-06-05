use crate::errors::Error;
use crate::types::chain;
use crate::types::hash::Hash;
use crate::types::traits::validator_set::ValidatorSet;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// Commit is used to prove a Header can be trusted.
/// Verifying the Commit requires access to an associated ValidatorSet
/// to determine what voting power signed the commit.
pub trait ProvableCommit: Clone + Debug + Serialize + DeserializeOwned {
    type ValidatorSet: ValidatorSet;

    /// Hash of the header this commit is for.
    fn header_hash(&self) -> Hash;

    /// Compute the voting power of the validators that correctly signed the commit,
    /// according to their voting power in the passed in validator set.
    /// Will return an error in case an invalid signature was included.
    /// TODO/XXX: This cannot detect if a signature from an incorrect validator
    /// is included. That's fine when we're just trying to see if we can skip,
    /// but when actually verifying it means we might accept commits that have sigs from
    /// outside the correct validator set, which is something we expect to be able to detect
    /// (it's not a real issue, but it would indicate a faulty full node).
    ///
    ///
    /// This method corresponds to the (pure) auxiliary function in the spec:
    /// `votingpower_in(signers(h.Commit),h.Header.V)`.
    /// Note this expects the Commit to be able to compute `signers(h.Commit)`,
    /// ie. the identity of the validators that signed it, so they
    /// can be cross-referenced with the given `vals`.
    fn voting_power_in(&self, chain_id: chain::Id, vals: &Self::ValidatorSet)
        -> Result<u64, Error>;

    /// Implementers should add addition validation against the given validator set
    /// or other implementation specific validation here.
    /// E.g. validate that the length of the included signatures in the commit match
    /// with the number of validators.
    fn validate(&self, vals: &Self::ValidatorSet) -> Result<(), Error>;
}
