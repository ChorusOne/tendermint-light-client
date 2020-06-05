mod errors;
mod merkle_tree;
mod serialization;
mod types;
mod verification;

#[macro_use]
extern crate serde_derive;

/// Types required to construct call to verification functionality
// Concrete header
pub use types::block::header::Header as LightHeader;
// Concrete signed header
pub use types::block::commit::LightSignedHeader;
// Generic signed header
pub use types::block::commit::SignedHeader;
// Trusted state data types
pub use types::trusted::TrustThresholdFraction;
pub use types::trusted::TrustedState;
// Validator data types
pub use types::validator::Info as LightValidatorInfo;
pub use types::validator::Set as LightValidatorSet;

use crate::errors::Error;
use std::time::{Duration, SystemTime};

// Generic Function to call to validate a header
pub use verification::verify_single;

// Wrapper around generic verification function
// with concrete light types
pub fn verify_single_light(
    trusted_state: TrustedState<LightSignedHeader, LightHeader>,
    untrusted_sh: &SignedHeader<LightSignedHeader, LightHeader>,
    untrusted_vals: &LightValidatorSet,
    untrusted_next_vals: &LightValidatorSet,
    trust_threshold: TrustThresholdFraction,
    trusting_period: Duration,
    now: SystemTime,
) -> Result<TrustedState<LightSignedHeader, LightHeader>, Error> {
    verify_single(
        trusted_state,
        untrusted_sh,
        untrusted_vals,
        untrusted_next_vals,
        trust_threshold,
        trusting_period,
        now,
    )
}

/// Traits inherited by some of the exposed types
pub mod traits {
    // Validator set trait implemented by LightValidatorSet
    pub use super::types::traits::validator_set::ValidatorSet;
    // Header trait implemented by LightHeader
    pub use super::types::block::traits::header::Header;
    // TrustThreshold trait implemented by TrustThresholdFraction
    pub use super::types::traits::trusted::TrustThreshold;
    // Provable commit trait implemented by LightSignedHeader
    pub use super::types::block::traits::commit::ProvableCommit;
}
