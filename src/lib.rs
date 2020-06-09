mod errors;
mod merkle_tree;
mod serialization;
mod types;
mod utils;
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
// Commit type which implements ProvableCommit
pub use types::block::commit::Commit;
// Trusted state data types
pub use types::trusted::TrustThresholdFraction;
pub use types::trusted::TrustedState;
// Validator data types
pub use types::validator::Info as LightValidator;
pub use types::validator::Set as LightValidatorSet;
// Time data type.
pub use types::time::Time;

// Generic Function to call to validate a header
pub use verification::verify_single;
// Generic function to validate initial signed header and validator set
// Client must create trusted set only if this function returns Ok.
pub use verification::validate_initial_signed_header_and_valset;

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
    // Validator trait implemented by LightValidator
    pub use super::types::traits::validator::Validator;
}
