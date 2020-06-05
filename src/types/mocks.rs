use anomaly::fail;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::errors::{Error, Kind};
use crate::types::block::traits::commit::ProvableCommit;
use crate::types::block::traits::header::{Header, Height};
use crate::types::chain;
use crate::types::hash::{Algorithm, Hash};
use crate::types::traits::validator_set::ValidatorSet;
use crate::{SignedHeader, TrustedState};
use std::str::FromStr;
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockHeader {
    height: u64,
    time: SystemTime,
    vals: Hash,
    next_vals: Hash,
}

impl MockHeader {
    pub fn new(height: u64, time: SystemTime, vals: Hash, next_vals: Hash) -> MockHeader {
        MockHeader {
            height,
            time,
            vals,
            next_vals,
        }
    }

    pub fn set_time(&mut self, new_time: SystemTime) {
        self.time = new_time
    }
}

impl Header for MockHeader {
    type Time = SystemTime;

    fn chain_id(&self) -> chain::Id {
        chain::Id::from_str("test").unwrap()
    }
    fn height(&self) -> Height {
        self.height
    }
    fn bft_time(&self) -> Self::Time {
        self.time
    }
    fn validators_hash(&self) -> Hash {
        self.vals
    }
    fn next_validators_hash(&self) -> Hash {
        self.next_vals
    }
    fn hash(&self) -> Hash {
        json_hash(self)
    }
}

pub fn json_hash<T: ?Sized + Serialize>(value: &T) -> Hash {
    let encoded = serde_json::to_vec(value).unwrap();
    let hashed = Sha256::digest(&encoded);
    Hash::new(Algorithm::Sha256, &hashed).unwrap()
}

// vals are just ints, each has power 1
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockValSet {
    // NOTE: use HashSet instead?
    vals: Vec<usize>,
}

impl MockValSet {
    pub fn new(vals: Vec<usize>) -> MockValSet {
        MockValSet { vals }
    }
}

impl ValidatorSet for MockValSet {
    fn hash(&self) -> Hash {
        json_hash(&self)
    }
    fn total_power(&self) -> u64 {
        self.vals.len() as u64
    }
}

// commit is a list of vals that signed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockCommit {
    hash: Hash,
    vals: Vec<usize>,
}

impl MockCommit {
    pub fn new(hash: Hash, vals: Vec<usize>) -> MockCommit {
        MockCommit { hash, vals }
    }
}
impl ProvableCommit for MockCommit {
    type ValidatorSet = MockValSet;

    fn header_hash(&self) -> Hash {
        self.hash
    }

    // just the intersection
    fn voting_power_in(
        &self,
        chain_id: chain::Id,
        vals: &Self::ValidatorSet,
    ) -> Result<u64, Error> {
        let mut power = 0;
        // if there's a signer thats not in the val set,
        // we can't detect it...
        for signer in self.vals.iter() {
            for val in vals.vals.iter() {
                if signer == val {
                    power += 1
                }
            }
        }
        Ok(power)
    }

    fn validate(&self, _vals: &Self::ValidatorSet) -> Result<(), Error> {
        // some implementation specific checks:
        if self.vals.is_empty() || self.hash.algorithm() != Algorithm::Sha256 {
            fail!(
                Kind::ImplementationSpecific,
                "validator set is empty, or, invalid hash algo"
            );
        }
        Ok(())
    }
}

pub type MockSignedHeader = SignedHeader<MockCommit, MockHeader>;
pub type MockTrustedState = TrustedState<MockCommit, MockHeader>;

pub fn fixed_hash() -> Hash {
    Hash::new(Algorithm::Sha256, &Sha256::digest(&[5])).unwrap()
}
