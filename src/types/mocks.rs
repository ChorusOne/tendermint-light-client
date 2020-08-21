use anomaly::fail;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::errors::{Error, Kind};
use crate::types::account::Id;
use crate::types::block::traits::commit::ProvableCommit;
use crate::types::block::traits::header::{Header, Height};
use crate::types::chain;
use crate::types::hash::{Algorithm, Hash};
use crate::types::proposer_priority::ProposerPriority;
use crate::types::traits::validator::Validator;
use crate::types::traits::validator_set::ValidatorSet;
use crate::types::vote::power::Power;
use crate::SignedHeader;
use std::collections::HashSet;
use std::iter::FromIterator;
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

impl Validator for usize {
    fn power(&self) -> u64 {
        *self as u64
    }

    fn verify_signature(&self, _sign_bytes: &[u8], _signature: &[u8]) -> bool {
        unimplemented!()
    }

    fn address(&self) -> Id {
        unimplemented!()
    }

    fn vote_power(&self) -> Power {
        unimplemented!()
    }

    fn proposer_priority(&self) -> Option<ProposerPriority> {
        unimplemented!()
    }

    fn hash_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }
}

// vals are just ints, each has power 1
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockValSet<V> {
    // NOTE: use HashSet instead?
    vals: Vec<V>,
}

impl<V> MockValSet<V>
where
    V: Validator,
{
    pub fn new(vals: Vec<V>) -> MockValSet<V> {
        MockValSet { vals }
    }
}

impl<V> ValidatorSet<V> for MockValSet<V>
where
    V: Validator + Eq + std::hash::Hash,
{
    fn hash(&self) -> Hash {
        json_hash(&self)
    }
    fn total_power(&self) -> u64 {
        self.vals.len() as u64
    }

    fn validator(&self, _val_id: Id) -> Option<V> {
        unimplemented!()
    }

    fn intersect(&self, validator_set: &Self) -> Self {
        let my_hashset: HashSet<V> = HashSet::from_iter(self.vals.iter().map(|v| v.clone()));
        let other_hashset: HashSet<V> =
            HashSet::from_iter(validator_set.vals.iter().map(|v| v.clone()));

        MockValSet::new(
            my_hashset
                .intersection(&other_hashset)
                .map(|v| v.clone())
                .collect(),
        )
    }

    fn number_of_validators(&self) -> usize {
        unimplemented!()
    }
}

// commit is a list of vals that signed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockCommit<V> {
    hash: Hash,
    vals: Vec<V>,
}

impl<V> MockCommit<V>
where
    V: Validator,
{
    pub fn new(hash: Hash, vals: Vec<V>) -> MockCommit<V> {
        MockCommit { hash, vals }
    }
}
impl<V> ProvableCommit<V> for MockCommit<V>
where
    V: Validator + PartialEq + std::hash::Hash + Eq,
{
    type ValidatorSet = MockValSet<V>;

    fn header_hash(&self) -> Hash {
        self.hash
    }

    // just the intersection
    fn voting_power_in(
        &self,
        _chain_id: chain::Id,
        vals: &Self::ValidatorSet,
    ) -> Result<u64, Error> {
        let mut power = 0;
        // if there's a signer thats not in the val set,
        // we can't detect it...
        for signer in self.vals.iter() {
            for val in vals.vals.iter() {
                if *signer == *val {
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

pub type MockSignedHeader = SignedHeader<MockCommit<usize>, MockHeader>;

pub fn fixed_hash() -> Hash {
    Hash::new(Algorithm::Sha256, &Sha256::digest(&[5])).unwrap()
}
