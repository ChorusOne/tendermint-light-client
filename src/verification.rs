use std::cmp::Ordering;
use std::ops::Add;
use std::time::{Duration, SystemTime};

use anomaly::ensure;

use crate::errors::{Error, Kind};
use crate::types::block::commit::SignedHeader;
use crate::types::block::traits::commit::ProvableCommit;
use crate::types::block::traits::header::Header;
use crate::types::traits::trusted::TrustThreshold;
use crate::types::traits::validator::Validator;
use crate::types::traits::validator_set::ValidatorSet;
use crate::types::trusted::TrustedState;

/// Verify a single untrusted header against a trusted state.
/// Ensures our last trusted header hasn't expired yet, and that
/// the untrusted header can be verified using only our latest trusted
/// state from the store.
///
/// On success, the caller is responsible for updating the store with the returned
/// header to be trusted.
///
/// This function is primarily for use by IBC handlers.
pub fn verify_single<H, C, L, V>(
    trusted_state: TrustedState<C, H, V>,
    untrusted_sh: &SignedHeader<C, H>,
    untrusted_vals: &C::ValidatorSet,
    untrusted_next_vals: &C::ValidatorSet,
    trust_threshold: L,
    trusting_period: Duration,
    now: SystemTime,
) -> Result<TrustedState<C, H, V>, Error>
where
    H: Header,
    C: ProvableCommit<V>,
    L: TrustThreshold,
    V: Validator,
{
    // Fetch the latest state and ensure it hasn't expired.
    let trusted_sh = trusted_state.last_header();
    is_within_trust_period(trusted_sh.header(), trusting_period, now)?;

    verify_single_inner(
        &trusted_state,
        untrusted_sh,
        untrusted_vals,
        untrusted_next_vals,
        trust_threshold,
    )?;

    // The untrusted header is now trusted;
    // return to the caller so they can update the store:
    Ok(TrustedState::new(
        untrusted_sh.clone(),
        untrusted_next_vals.clone(),
    ))
}

pub fn validate_initial_signed_header_and_valset<H, C, V>(
    untrusted_sh: &SignedHeader<C, H>,
    untrusted_vals: &C::ValidatorSet,
) -> Result<(), Error>
where
    H: Header,
    C: ProvableCommit<V>,
    V: Validator,
{
    let header = untrusted_sh.header();
    let commit = untrusted_sh.commit();

    validate(header, commit, untrusted_vals, None)?;

    verify_commit_full(untrusted_vals, header, commit)?;

    Ok(())
}

/// Returns an error if the header has expired according to the given
/// trusting_period and current time. If so, the verifier must be reset subjectively.
fn is_within_trust_period<H>(
    last_header: &H,
    trusting_period: Duration,
    now: SystemTime,
) -> Result<(), Error>
where
    H: Header,
{
    let header_time: SystemTime = last_header.bft_time().into();
    let expires_at = header_time.add(trusting_period);
    // Ensure now > expires_at.
    if expires_at <= now {
        return Err(Kind::Expired {
            at: expires_at,
            now,
        }
        .into());
    }
    // Also make sure the header is not after now.
    ensure!(
        header_time <= now,
        Kind::DurationOutOfRange,
        "header time: ({:?}) > now: ({:?})",
        header_time,
        now
    );
    Ok(())
}

// Verify a single untrusted header against a trusted state.
// Includes all validation and signature verification.
// Not publicly exposed since it does not check for expiry
// and hence it's possible to use it incorrectly.
// If trusted_state is not expired and this returns Ok, the
// untrusted_sh and untrusted_next_vals can be considered trusted.
fn verify_single_inner<H, C, L, V>(
    trusted_state: &TrustedState<C, H, V>,
    untrusted_sh: &SignedHeader<C, H>,
    untrusted_vals: &C::ValidatorSet,
    untrusted_next_vals: &C::ValidatorSet,
    trust_threshold: L,
) -> Result<(), Error>
where
    H: Header,
    C: ProvableCommit<V>,
    L: TrustThreshold,
    V: Validator,
{
    // validate the untrusted header against its commit, vals, and next_vals
    let untrusted_header = untrusted_sh.header();
    let untrusted_commit = untrusted_sh.commit();

    validate(
        untrusted_sh.header(),
        untrusted_sh.commit(),
        untrusted_vals,
        Some(untrusted_next_vals),
    )?;

    // ensure the new height is higher.
    // if its +1, ensure the vals are correct.
    // if its >+1, ensure we can skip to it
    let trusted_header = trusted_state.last_header().header();
    let trusted_height = trusted_header.height();
    let untrusted_height = untrusted_sh.header().height();

    // ensure the untrusted_header.bft_time() > trusted_header.bft_time()
    if untrusted_header.bft_time().into() <= trusted_header.bft_time().into() {
        return Err(Kind::NonIncreasingTime.into());
    }

    match untrusted_height.cmp(&trusted_height.checked_add(1).expect("height overflow")) {
        Ordering::Less => {
            return Err(Kind::NonIncreasingHeight {
                got: untrusted_height,
                expected: trusted_height + 1,
            }
            .into())
        }
        Ordering::Equal => {
            let trusted_vals_hash = trusted_header.next_validators_hash();
            let untrusted_vals_hash = untrusted_header.validators_hash();
            if trusted_vals_hash != untrusted_vals_hash {
                return Err(Kind::InvalidValidatorSet {
                    header_val_hash: untrusted_vals_hash,
                    expected_val_hash: trusted_vals_hash,
                }
                .into());
            }
        }
        Ordering::Greater => {
            let trusted_validators = trusted_state.validators();
            // We need to intersect trusted validators with untrusted validator because
            // only if our previously trusted validators are part of validator set for this
            // height, its vote can be considered valid.
            let common_vals = trusted_validators.intersect(untrusted_vals);

            // Minimum trusted voting power required to consider this header as trusted
            let minimum_trusted_voting_power_required =
                trust_threshold.minimum_power_to_be_trusted(trusted_validators.total_power());

            // Sum of voting power of validators who has legitimately signed this header
            let signed_power =
                untrusted_commit.voting_power_in(untrusted_header.chain_id(), &common_vals)?;

            // check the signers' total voting powers are greater than or equal to minimum
            // trusted voting power required.
            if signed_power < minimum_trusted_voting_power_required {
                return Err(Kind::InsufficientSignedVotingPower {
                    total: trusted_validators.total_power(),
                    signed: signed_power,
                    trust_threshold: format!("{:?}", trust_threshold),
                }
                .into());
            }
        }
    }

    // All validation passed successfully. Verify the validators correctly committed the block.
    verify_commit_full(untrusted_vals, untrusted_header, untrusted_commit)
}

/// Validate the validators, next validators, against the signed header.
/// This is equivalent to validateSignedHeaderAndVals in the spec.
fn validate<C, H, V>(
    header: &H,
    commit: &C,
    vals: &C::ValidatorSet,
    possible_next_vals: Option<&C::ValidatorSet>,
) -> Result<(), Error>
where
    C: ProvableCommit<V>,
    H: Header,
    V: Validator,
{
    // ensure the header validator hashes match the given validators
    if header.validators_hash() != vals.hash() {
        return Err(Kind::InvalidValidatorSet {
            header_val_hash: header.validators_hash(),
            expected_val_hash: vals.hash(),
        }
        .into());
    }

    if possible_next_vals.is_some() {
        let next_vals = possible_next_vals.unwrap();
        if header.next_validators_hash() != next_vals.hash() {
            return Err(Kind::InvalidNextValidatorSet {
                header_next_val_hash: header.next_validators_hash(),
                expected_next_val_hash: next_vals.hash(),
            }
            .into());
        }
    }

    // ensure the header matches the commit
    if header.hash() != commit.header_hash() {
        return Err(Kind::InvalidCommitValue {
            header_hash: header.hash(),
            commit_hash: commit.header_hash(),
        }
        .into());
    }

    // additional implementation specific validation:
    commit.validate(vals)?;

    Ok(())
}

/// Verify that +2/3 of the correct validator set signed this commit.
/// NOTE: These validators are expected to be the correct validators for the commit,
/// but since we're using voting_power_in, we can't actually detect if there's
/// votes from validators not in the set.
fn verify_commit_full<H, C, V>(vals: &C::ValidatorSet, header: &H, commit: &C) -> Result<(), Error>
where
    C: ProvableCommit<V>,
    H: Header,
    V: Validator,
{
    let total_power = vals.total_power();
    let signed_power = commit.voting_power_in(header.chain_id(), vals)?;

    // check the signers account for +2/3 of the voting power
    if signed_power * 3 <= total_power * 2 {
        return Err(Kind::InvalidCommit {
            total: total_power,
            signed: signed_power,
        }
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::types::block::traits::header::Header;
    use crate::types::mocks::{fixed_hash, MockCommit, MockHeader, MockSignedHeader, MockValSet};
    use crate::types::traits::validator_set::ValidatorSet;
    use crate::verification::{is_within_trust_period, verify_single_inner};
    use crate::{TrustThresholdFraction, TrustedState};
    use std::time::{Duration, SystemTime};

    type MockState = TrustedState<MockCommit<usize>, MockHeader, usize>;

    #[derive(Clone)]
    struct ValsAndCommit {
        vals_vec: Vec<usize>,
        commit_vec: Vec<usize>,
    }

    impl ValsAndCommit {
        pub fn new(vals_vec: Vec<usize>, commit_vec: Vec<usize>) -> ValsAndCommit {
            ValsAndCommit {
                vals_vec,
                commit_vec,
            }
        }
    }

    // create the next state with the given vals and commit.
    fn next_state(
        vals_and_commit: ValsAndCommit,
    ) -> (MockSignedHeader, MockValSet<usize>, MockValSet<usize>) {
        let time = init_time() + Duration::new(10, 0);
        let height = 10;
        let vals = MockValSet::new(vals_and_commit.vals_vec);
        let next_vals = vals.clone();
        let header = MockHeader::new(height, time, vals.hash(), next_vals.hash());
        let commit = MockCommit::new(header.hash(), vals_and_commit.commit_vec);
        (MockSignedHeader::new(commit, header), vals, next_vals)
    }

    // start all blockchains from here ...
    fn init_time() -> SystemTime {
        SystemTime::UNIX_EPOCH
    }

    // create an initial trusted state from the given vals
    fn init_trusted_state(
        vals_and_commit_vec: ValsAndCommit,
        next_vals_vec: Vec<usize>,
        height: u64,
    ) -> MockState {
        // time has to be increasing:
        let time = init_time() + Duration::new(height * 2, 0);
        let vals = MockValSet::new(vals_and_commit_vec.vals_vec);
        let next_vals = MockValSet::new(next_vals_vec);
        let header = MockHeader::new(height, time, vals.hash(), next_vals.hash());
        let commit = MockCommit::new(header.hash(), vals_and_commit_vec.commit_vec);
        let sh = MockSignedHeader::new(commit, header);
        MockState::new(sh, vals)
    }

    // make a state with the given vals and commit and ensure we get the expected error kind.
    fn assert_single_err(
        ts: &TrustedState<MockCommit<usize>, MockHeader, usize>,
        vals_and_commit: ValsAndCommit,
        err_str: String,
    ) {
        let (un_sh, un_vals, un_next_vals) = next_state(vals_and_commit);
        let result = verify_single_inner(
            ts,
            &un_sh,
            &un_vals,
            &un_next_vals,
            TrustThresholdFraction::default(),
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), err_str);
    }

    // make a state with the given vals and commit and ensure we get no error.
    fn assert_single_ok(ts: &MockState, vals_and_commit: ValsAndCommit) {
        let (un_sh, un_vals, un_next_vals) = next_state(vals_and_commit);
        assert!(verify_single_inner(
            ts,
            &un_sh,
            &un_vals,
            &un_next_vals,
            TrustThresholdFraction::default()
        )
        .is_ok());
    }

    // valid to skip, but invalid commit. 1 validator.
    #[test]
    fn test_verify_single_skip_1_val_verify() {
        let vac = ValsAndCommit::new(vec![0], vec![0]);
        let ts = &init_trusted_state(vac, vec![0], 1);

        // 100% overlap, but wrong commit.
        // NOTE: This should be an invalid commit error since there's
        // a vote from a validator not in the set!
        // but voting_power_in isn't smart enough to see this ...
        // TODO(ismail): https://github.com/interchainio/tendermint-rs/issues/140
        let invalid_vac = ValsAndCommit::new(vec![1], vec![0]);
        assert_single_err(
            ts,
            invalid_vac,
            String::from(
                "signed voting power (0) is too small fraction of total trusted voting power: (1), threshold: TrustThresholdFraction { numerator: 2, denominator: 3 }",
            ),
        );
    }

    // valid commit and data, starting with 1 validator.
    // test if we can skip to it.
    #[test]
    fn test_verify_single_skip_1_val_skip() {
        let mut vac = ValsAndCommit::new(vec![0], vec![0]);
        let ts = &init_trusted_state(vac.clone(), vec![0], 1);
        //*****
        // Ok

        // 100% overlap (original signer is present in commit)
        assert_single_ok(ts, vac);

        vac = ValsAndCommit::new(vec![0, 1], vec![0, 1]);
        assert_single_ok(ts, vac);

        vac = ValsAndCommit::new(vec![0, 1, 2], vec![0, 1, 2]);
        assert_single_ok(ts, vac);

        vac = ValsAndCommit::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]);
        assert_single_ok(ts, vac);

        //*****
        // Err
        let err = "signed voting power (0) is too small fraction of total trusted voting power: (1), threshold: TrustThresholdFraction { numerator: 2, denominator: 3 }";

        // 0% overlap - val set contains original signer, but they didn't sign
        vac = ValsAndCommit::new(vec![0, 1, 2, 3], vec![1, 2, 3]);
        assert_single_err(ts, vac, err.into());

        // 0% overlap - new val set without the original signer
        vac = ValsAndCommit::new(vec![1], vec![1]);
        assert_single_err(ts, vac, err.clone().into());
    }

    // valid commit and data, starting with 2 validators.
    // test if we can skip to it.
    #[test]
    fn test_verify_single_skip_2_val_skip() {
        let mut vac = ValsAndCommit::new(vec![0, 1], vec![0, 1]);
        let ts = &init_trusted_state(vac.clone(), vec![0, 1], 1);

        //*************
        // OK

        // 100% overlap (both original signers still present)
        assert_single_ok(ts, vac);

        vac = ValsAndCommit::new(vec![0, 1, 2], vec![0, 1, 2]);
        assert_single_ok(ts, vac);

        //*************
        // Err
        let err = "signed voting power (1) is too small fraction of total trusted voting power: (2), threshold: TrustThresholdFraction { numerator: 2, denominator: 3 }";

        // 50% overlap (one original signer still present)
        vac = ValsAndCommit::new(vec![0], vec![0]);
        assert_single_err(ts, vac, err.clone().into());

        vac = ValsAndCommit::new(vec![0, 1, 2, 3], vec![1, 2, 3]);
        assert_single_err(ts, vac, err.clone().into());

        //*************
        // Err
        let err = "signed voting power (0) is too small fraction of total trusted voting power: (2), threshold: TrustThresholdFraction { numerator: 2, denominator: 3 }";

        // 0% overlap (neither original signer still present)
        vac = ValsAndCommit::new(vec![2], vec![2]);
        assert_single_err(ts, vac, err.clone().into());

        // 0% overlap (original signer is still in val set but not in commit)
        vac = ValsAndCommit::new(vec![0, 2, 3, 4], vec![2, 3, 4]);
        assert_single_err(ts, vac, err.into());
    }

    // valid commit and data, starting with 3 validators.
    // test if we can skip to it.
    #[test]
    fn test_verify_single_skip_3_val_skip() {
        let mut vac = ValsAndCommit::new(vec![0, 1, 2], vec![0, 1, 2]);
        let ts = &init_trusted_state(vac.clone(), vec![0, 1, 2], 1);

        //*************
        // OK

        // 100% overlap (both original signers still present)
        assert_single_ok(ts, vac);

        vac = ValsAndCommit::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]);
        assert_single_ok(ts, vac);

        //*************
        // Err
        let err = "signed voting power (2) is too small fraction of total trusted voting power: (3), threshold: TrustThresholdFraction { numerator: 2, denominator: 3 }";

        // 66% overlap (two original signers still present)
        vac = ValsAndCommit::new(vec![0, 1], vec![0, 1]);
        assert_single_err(ts, vac, err.clone().into());

        vac = ValsAndCommit::new(vec![0, 1, 2, 3], vec![1, 2, 3]);
        assert_single_err(ts, vac, err.clone().into());

        let err = "signed voting power (1) is too small fraction of total trusted voting power: (3), threshold: TrustThresholdFraction { numerator: 2, denominator: 3 }";

        // 33% overlap (one original signer still present)
        vac = ValsAndCommit::new(vec![0], vec![0]);
        assert_single_err(ts, vac, err.clone().into());

        vac = ValsAndCommit::new(vec![0, 3], vec![0, 3]);
        assert_single_err(ts, vac, err.clone().into());

        let err = "signed voting power (0) is too small fraction of total trusted voting power: (3), threshold: TrustThresholdFraction { numerator: 2, denominator: 3 }";

        // 0% overlap (neither original signer still present)
        vac = ValsAndCommit::new(vec![3], vec![0, 1, 2]);
        assert_single_err(ts, vac, err.into());

        // 0% overlap (original signer is still in val set but not in commit)
        vac = ValsAndCommit::new(vec![0, 3, 4, 5], vec![3, 4, 5]);
        assert_single_err(ts, vac, err.into());
    }

    #[test]
    fn test_verify_single_skip_4_val_skip() {
        let vac = ValsAndCommit::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]);
        let ts = &init_trusted_state(vac.clone(), vec![0, 1, 2, 3], 1);

        // 100% overlap (all signers present)
        assert_single_ok(ts, vac);

        // 75% overlap (three signers present)
        let vac = ValsAndCommit::new(vec![0, 1, 2], vec![0, 1, 2]);
        assert_single_ok(ts, vac);

        let vac = ValsAndCommit::new(vec![0, 1, 2, 4], vec![0, 1, 2, 4]);
        assert_single_ok(ts, vac);

        let err = "signed voting power (2) is too small fraction of total trusted voting power: (4), threshold: TrustThresholdFraction { numerator: 2, denominator: 3 }";

        // 50% overlap (two signers still present)
        let vac = ValsAndCommit::new(vec![0, 1], vec![0, 1]);
        assert_single_err(ts, vac, err.into());

        let vac = ValsAndCommit::new(vec![0, 1, 4, 5], vec![0, 1, 4, 5]);
        assert_single_err(ts, vac, err.into());

        let err = "signed voting power (1) is too small fraction of total trusted voting power: (4), threshold: TrustThresholdFraction { numerator: 2, denominator: 3 }";

        // 25% overlap (one signer still present)
        let vac = ValsAndCommit::new(vec![0, 4, 5, 6], vec![0, 4, 5, 6]);
        assert_single_err(ts, vac, err.into());

        let err = "signed voting power (0) is too small fraction of total trusted voting power: (4), threshold: TrustThresholdFraction { numerator: 2, denominator: 3 }";

        // 0% overlap (none of the signers present)
        let vac = ValsAndCommit::new(vec![4, 5, 6], vec![4, 5, 6]);
        assert_single_err(ts, vac, err.clone().into());

        // 0% overlap (one signer present in val set but does not commit)
        let vac = ValsAndCommit::new(vec![3, 4, 5, 6], vec![4, 5, 6]);
        assert_single_err(ts, vac, err.into());
    }

    #[test]
    fn test_is_within_trust_period() {
        let header_time = SystemTime::UNIX_EPOCH;
        let period = Duration::new(100, 0);
        let now = header_time + Duration::new(10, 0);

        // less than the period, OK
        let header = MockHeader::new(4, header_time, fixed_hash(), fixed_hash());
        assert!(is_within_trust_period(&header, period, now).is_ok());

        // equal to the period, not OK
        let now = header_time + period;
        assert!(is_within_trust_period(&header, period, now).is_err());

        // greater than the period, not OK
        let now = header_time + period + Duration::new(1, 0);
        assert!(is_within_trust_period(&header, period, now).is_err());

        // bft time in header is later than now, not OK:
        let now = SystemTime::UNIX_EPOCH;
        let later_than_now = now + Duration::new(60, 0);
        let future_header = MockHeader::new(4, later_than_now, fixed_hash(), fixed_hash());
        assert!(is_within_trust_period(&future_header, period, now).is_err());
    }
}
