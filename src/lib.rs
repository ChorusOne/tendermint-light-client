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
// Converts a LightSignedHeader to Generic signed header
pub use types::block::commit::convert_to_signed_header;
// Trusted state data types
pub use types::trusted::TrustThresholdFraction;
pub use types::trusted::TrustedState;
// Validator data types
pub use types::validator::Info as LightValidatorInfo;
pub use types::validator::Set as LightValidatorSet;

// Function to call to validate a header
pub use verification::verify_single;

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
