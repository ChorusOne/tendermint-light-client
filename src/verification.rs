use std::cmp::Ordering;
use std::ops::Add;
use std::time::{Duration, SystemTime};

use anomaly::ensure;

use crate::errors::{Error, Kind};
use crate::types::block::commit::SignedHeader;
use crate::types::block::traits::commit::ProvableCommit;
use crate::types::block::traits::header::Header;
use crate::types::traits::trusted::TrustThreshold;
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
pub fn verify_single<H, C, L>(
    trusted_state: TrustedState<C, H>,
    untrusted_sh: &SignedHeader<C, H>,
    untrusted_vals: &C::ValidatorSet,
    untrusted_next_vals: &C::ValidatorSet,
    trust_threshold: L,
    trusting_period: Duration,
    now: SystemTime,
) -> Result<TrustedState<C, H>, Error>
where
    H: Header,
    C: ProvableCommit,
    L: TrustThreshold,
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

/// Returns an error if the header has expired according to the given
/// trusting_period and current time. If so, the verifier must be reset subjectively.
pub fn is_within_trust_period<H>(
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
fn verify_single_inner<H, C, L>(
    trusted_state: &TrustedState<C, H>,
    untrusted_sh: &SignedHeader<C, H>,
    untrusted_vals: &C::ValidatorSet,
    untrusted_next_vals: &C::ValidatorSet,
    trust_threshold: L,
) -> Result<(), Error>
where
    H: Header,
    C: ProvableCommit,
    L: TrustThreshold,
{
    // validate the untrusted header against its commit, vals, and next_vals
    let untrusted_header = untrusted_sh.header();
    let untrusted_commit = untrusted_sh.commit();

    validate(untrusted_sh, untrusted_vals, untrusted_next_vals)?;

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
                // TODO: more specific error
                // ie. differentiate from when next_vals.hash() doesnt
                // match the header hash ...
                return Err(Kind::InvalidNextValidatorSet {
                    header_next_val_hash: trusted_vals_hash,
                    next_val_hash: untrusted_vals_hash,
                }
                .into());
            }
        }
        Ordering::Greater => {
            let trusted_vals = trusted_state.validators();
            verify_commit_trusting(trusted_vals, untrusted_commit, trust_threshold)?;
        }
    }

    // All validation passed successfully. Verify the validators correctly committed the block.
    verify_commit_full(untrusted_vals, untrusted_sh.commit())
}

/// Validate the validators, next validators, against the signed header.
/// This is equivalent to validateSignedHeaderAndVals in the spec.
pub fn validate<C, H>(
    signed_header: &SignedHeader<C, H>,
    vals: &C::ValidatorSet,
    next_vals: &C::ValidatorSet,
) -> Result<(), Error>
where
    C: ProvableCommit,
    H: Header,
{
    let header = signed_header.header();
    let commit = signed_header.commit();

    // ensure the header validator hashes match the given validators
    if header.validators_hash() != vals.hash() {
        return Err(Kind::InvalidValidatorSet {
            header_val_hash: header.validators_hash(),
            val_hash: vals.hash(),
        }
        .into());
    }
    if header.next_validators_hash() != next_vals.hash() {
        return Err(Kind::InvalidNextValidatorSet {
            header_next_val_hash: header.next_validators_hash(),
            next_val_hash: next_vals.hash(),
        }
        .into());
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
pub fn verify_commit_full<C>(vals: &C::ValidatorSet, commit: &C) -> Result<(), Error>
where
    C: ProvableCommit,
{
    let total_power = vals.total_power();
    let signed_power = commit.voting_power_in(vals)?;

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

/// Verify that +1/3 of the given validator set signed this commit.
/// NOTE the given validators do not necessarily correspond to the validator set for this commit,
/// but there may be some intersection. The trust_level parameter allows clients to require more
/// than +1/3 by implementing the TrustLevel trait accordingly.
pub fn verify_commit_trusting<C, L>(
    validators: &C::ValidatorSet,
    commit: &C,
    trust_level: L,
) -> Result<(), Error>
where
    C: ProvableCommit,
    L: TrustThreshold,
{
    let total_power = validators.total_power();
    let signed_power = commit.voting_power_in(validators)?;

    // check the signers account for +1/3 of the voting power (or more if the
    // trust_level requires so)
    if !trust_level.is_enough_power(signed_power, total_power) {
        return Err(Kind::InsufficientVotingPower {
            total: total_power,
            signed: signed_power,
            trust_treshold: format!("{:?}", trust_level),
        }
        .into());
    }

    Ok(())
}
