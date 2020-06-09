use crate::errors::{Error, Kind};
use crate::types::block::commit::SignedHeader;
use crate::types::block::traits::{commit::ProvableCommit, header::Header};
use crate::types::traits::trusted::TrustThreshold;
use crate::types::traits::validator::Validator;
use serde::de::Deserialize;
use std::fmt::Debug;

/// TrustThresholdFraction defines what fraction of the total voting power of a known
/// and trusted validator set is sufficient for a commit to be
/// accepted going forward.
/// The [`Default::default()`] returns true, iff at least a third of the trusted
/// voting power signed (in other words at least one honest validator signed).
/// Some clients might require more than +1/3 and can implement their own
/// [`TrustThreshold`] which can be passed into all relevant methods.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrustThresholdFraction {
    #[serde(with = "crate::serialization::from_str")]
    pub numerator: u64,
    #[serde(with = "crate::serialization::from_str")]
    pub denominator: u64,
}

impl TrustThresholdFraction {
    /// Instantiate a TrustThresholdFraction if the given denominator and
    /// numerator are valid.
    ///
    /// The parameters are valid iff `1/3 <= numerator/denominator <= 1`.
    /// In any other case we return [`Error::InvalidTrustThreshold`].
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, Error> {
        if numerator <= denominator && denominator > 0 && 3 * numerator >= denominator {
            return Ok(Self {
                numerator,
                denominator,
            });
        }
        Err(Kind::InvalidTrustThreshold {
            got: format!("{}/{}", numerator, denominator),
        }
        .into())
    }
}

// TODO: should this go in the central place all impls live instead? (currently lite_impl)
impl TrustThreshold for TrustThresholdFraction {
    fn is_enough_power(&self, signed_voting_power: u64, total_voting_power: u64) -> bool {
        signed_voting_power >= self.minimum_power_to_be_trusted(total_voting_power)
    }

    fn minimum_power_to_be_trusted(&self, total_voting_power: u64) -> u64 {
        return ((total_voting_power * self.numerator) / self.denominator) + 1;
    }
}

impl Default for TrustThresholdFraction {
    fn default() -> Self {
        Self::new(2, 3)
            .expect("initializing TrustThresholdFraction with valid fraction mustn't panic")
    }
}

/// TrustedState contains a state trusted by a lite client,
/// including the last header (at height h-1) and the validator set
/// (at height h) to use to verify the next header.
///
/// **Note:** The `#[serde(bound = ...)]` attribute is required to
/// derive `Deserialize` for this struct as Serde is not able to infer
/// the proper bound when associated types are involved.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "C::ValidatorSet: Deserialize<'de>"))]
pub struct TrustedState<C, H, V>
where
    H: Header,
    C: ProvableCommit<V>,
    V: Validator,
{
    last_header: SignedHeader<C, H>, // height H-1
    validators: C::ValidatorSet,     // height H
}

impl<C, H, V> TrustedState<C, H, V>
where
    H: Header,
    C: ProvableCommit<V>,
    V: Validator,
{
    /// Initialize the TrustedState with the given signed header and validator set.
    /// Note that if the height of the passed in header is h-1, the passed in validator set
    /// must have been requested for height h.
    pub fn new(last_header: SignedHeader<C, H>, validators: C::ValidatorSet) -> Self {
        Self {
            last_header,
            validators,
        }
    }

    pub fn last_header(&self) -> &SignedHeader<C, H> {
        &self.last_header
    }

    pub fn validators(&self) -> &C::ValidatorSet {
        &self.validators
    }
}

#[cfg(test)]
mod tests {
    use crate::types::traits::trusted::TrustThreshold;
    use crate::TrustThresholdFraction;

    #[test]
    fn test_threshold_fraction() {
        let possible_threshold_fraction = TrustThresholdFraction::new(1, 3);
        assert!(possible_threshold_fraction.is_ok());

        // 1/3+ need to sign
        let mut threshold_fraction = possible_threshold_fraction.unwrap();
        assert!(!threshold_fraction.is_enough_power(0, 3));
        assert!(!threshold_fraction.is_enough_power(1, 3));
        assert!(threshold_fraction.is_enough_power(2, 3));
        assert!(threshold_fraction.is_enough_power(3, 3));

        // 1/2+ need to sign
        threshold_fraction.numerator = 1;
        threshold_fraction.denominator = 2;
        assert!(!threshold_fraction.is_enough_power(0, 4));
        assert!(!threshold_fraction.is_enough_power(1, 4));
        assert!(!threshold_fraction.is_enough_power(2, 4));
        assert!(threshold_fraction.is_enough_power(3, 4));
        assert!(threshold_fraction.is_enough_power(4, 4));

        // 2/3+ need to sign
        threshold_fraction.numerator = 2;
        threshold_fraction.denominator = 3;
        assert!(!threshold_fraction.is_enough_power(0, 3));
        assert!(!threshold_fraction.is_enough_power(1, 3));
        assert!(!threshold_fraction.is_enough_power(2, 3));
        assert!(threshold_fraction.is_enough_power(3, 3));

        // All+ need to sign
        threshold_fraction.numerator = 3;
        threshold_fraction.denominator = 3;
        assert!(!threshold_fraction.is_enough_power(0, 3));
        assert!(!threshold_fraction.is_enough_power(1, 3));
        assert!(!threshold_fraction.is_enough_power(2, 3));
        assert!(!threshold_fraction.is_enough_power(3, 3));
        assert!(threshold_fraction.is_enough_power(4, 3));
    }
}
