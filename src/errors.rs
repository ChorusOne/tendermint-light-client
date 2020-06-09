use std::time::SystemTime;

use anomaly::{BoxError, Context};
use thiserror::Error;

use crate::types::hash::Hash;

/// The main error type verification methods will return.
/// See [`Kind`] for the different kind of errors.
pub type Error = anomaly::Error<Kind>;

/// All error kinds related to the light client.
#[derive(Clone, Debug, Error)]
pub enum Kind {
    /// The provided header expired.
    #[error("old header has expired at {at:?} (now: {now:?})")]
    Expired { at: SystemTime, now: SystemTime },

    /// Trusted header is from the future.
    #[error("trusted header time is too far in the future")]
    DurationOutOfRange,

    /// Header height smaller than expected.
    #[error("expected height >= {expected} (got: {got})")]
    NonIncreasingHeight { got: u64, expected: u64 },

    /// Header time is in the past compared to already trusted header.
    #[error("untrusted header time <= trusted header time")]
    NonIncreasingTime,

    /// Invalid validator hash.
    #[error("header's validator hash does not match actual validator hash ({header_val_hash:?}!={expected_val_hash:?})")]
    InvalidValidatorSet {
        header_val_hash: Hash,
        expected_val_hash: Hash,
    },

    /// Invalid next validator hash.
    #[error("header's next validator hash does not match next_val_hash ({header_next_val_hash:?}!={expected_next_val_hash:?})")]
    InvalidNextValidatorSet {
        header_next_val_hash: Hash,
        expected_next_val_hash: Hash,
    },

    /// Commit is not for the header we expected.
    #[error(
        "header hash does not match the hash in the commit ({header_hash:?}!={commit_hash:?})"
    )]
    InvalidCommitValue {
        header_hash: Hash,
        commit_hash: Hash,
    },

    /// Signed power does not account for +2/3 of total voting power.
    #[error("signed voting power ({signed}) do not account for +2/3 of the total voting power: ({total})")]
    InvalidCommit { total: u64, signed: u64 },

    /// This means the trust threshold (default +2/3) is not met.
    #[error("signed voting power ({}) is too small fraction of total trusted voting power: ({}), threshold: {}",
    .signed, .total, .trust_threshold
    )]
    InsufficientSignedVotingPower {
        total: u64,
        signed: u64,
        trust_threshold: String,
    },

    /// This is returned if an invalid TrustThreshold is created.
    #[error("A valid threshold is `1/3 <= threshold <= 1`, got: {got}")]
    InvalidTrustThreshold { got: String },

    /// Use the [`Kind::context`] method to wrap the underlying error of
    /// the implementation, if any.
    #[error("Implementation specific error")]
    ImplementationSpecific,

    /// Value out-of-range
    #[error("value out of range")]
    OutOfRange,

    /// Parse error
    #[error("parse error")]
    Parse,

    /// Malformatted or otherwise invalid cryptographic key
    #[error("invalid key")]
    InvalidKey,

    /// Length incorrect or too long
    #[error("length error")]
    Length,
}

impl Kind {
    /// Add additional context.
    pub fn context(self, source: impl Into<BoxError>) -> Context<Kind> {
        Context::new(self, Some(source.into()))
    }
}
