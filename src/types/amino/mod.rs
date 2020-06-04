pub(crate) mod message;

use crate::errors::Error;
use crate::types::block::parts;
use crate::types::hash::Hash;
use crate::types::time::{ParseTimestamp, Time};
use crate::types::{block, vote::vote};
use crate::types::{chain, hash};
use anomaly::BoxError;
use chrono::offset::TimeZone;
use chrono::Utc;
use prost_amino::DecodeError;
use prost_amino_derive::Message;
use std::convert::TryFrom;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, PartialEq, Message)]
pub struct BlockId {
    #[prost_amino(bytes, tag = "1")]
    pub hash: Vec<u8>,
    #[prost_amino(message, tag = "2")]
    pub parts_header: Option<PartsSetHeader>,
}

impl BlockId {
    pub fn new(hash: Vec<u8>, parts_header: Option<PartsSetHeader>) -> Self {
        BlockId { hash, parts_header }
    }
}

impl block::id::ParseId for BlockId {
    fn parse_block_id(&self) -> Result<block::id::Id, BoxError> {
        let hash = Hash::new(hash::Algorithm::Sha256, &self.hash)?;
        let parts_header = self
            .parts_header
            .as_ref()
            .and_then(PartsSetHeader::parse_parts_header);
        Ok(block::id::Id::new(hash, parts_header))
    }
}

impl From<&block::id::Id> for BlockId {
    fn from(bid: &block::id::Id) -> Self {
        let bid_hash = bid.hash.as_bytes();
        BlockId::new(
            bid_hash.to_vec(),
            bid.parts.as_ref().map(PartsSetHeader::from),
        )
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct PartsSetHeader {
    #[prost_amino(int64, tag = "1")]
    pub total: i64,
    #[prost_amino(bytes, tag = "2")]
    pub hash: Vec<u8>,
}

impl PartsSetHeader {
    pub fn new(total: i64, hash: Vec<u8>) -> Self {
        PartsSetHeader { total, hash }
    }
}

impl From<&parts::Header> for PartsSetHeader {
    fn from(parts: &parts::Header) -> Self {
        PartsSetHeader::new(parts.total as i64, parts.hash.as_bytes().to_vec())
    }
}

impl PartsSetHeader {
    fn parse_parts_header(&self) -> Option<parts::Header> {
        Hash::new(hash::Algorithm::Sha256, &self.hash)
            .map(|hash| parts::Header::new(self.total as u64, hash))
            .ok()
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct TimeMsg {
    // TODO(ismail): switch to protobuf's well known type as soon as
    // https://github.com/tendermint/go-amino/pull/224 was merged
    // and tendermint caught up on the latest amino release.
    #[prost_amino(int64, tag = "1")]
    pub seconds: i64,
    #[prost_amino(int32, tag = "2")]
    pub nanos: i32,
}

impl ParseTimestamp for TimeMsg {
    fn parse_timestamp(&self) -> Result<Time, Error> {
        Ok(Utc.timestamp(self.seconds, self.nanos as u32).into())
    }
}

impl From<Time> for TimeMsg {
    fn from(ts: Time) -> TimeMsg {
        // TODO: non-panicking method for getting this?
        let duration = ts.duration_since(Time::unix_epoch()).unwrap();
        let seconds = duration.as_secs() as i64;
        let nanos = duration.subsec_nanos() as i32;

        TimeMsg { seconds, nanos }
    }
}

/// Converts `Time` to a `SystemTime`.
impl From<TimeMsg> for SystemTime {
    fn from(time: TimeMsg) -> SystemTime {
        if time.seconds >= 0 {
            UNIX_EPOCH + Duration::new(time.seconds as u64, time.nanos as u32)
        } else {
            UNIX_EPOCH - Duration::new(time.seconds as u64, time.nanos as u32)
        }
    }
}

#[derive(Clone, Message)]
pub struct ConsensusVersion {
    /// Block version
    #[prost_amino(uint64, tag = "1")]
    pub block: u64,

    /// App version
    #[prost_amino(uint64, tag = "2")]
    pub app: u64,
}

impl From<&block::header::Version> for ConsensusVersion {
    fn from(version: &block::header::Version) -> Self {
        ConsensusVersion {
            block: version.block,
            app: version.app,
        }
    }
}

/// Signed message types. This follows:
/// <https://github.com/tendermint/tendermint/blob/455d34134cc53c334ebd3195ac22ea444c4b59bb/types/signed_msg_type.go#L3-L16>
#[derive(Copy, Clone, Debug)]
pub enum SignedMsgType {
    /// Votes
    PreVote,

    /// Commits
    PreCommit,

    /// Proposals
    Proposal,
}

impl SignedMsgType {
    pub fn to_u32(self) -> u32 {
        match self {
            // Votes
            SignedMsgType::PreVote => 0x01,
            SignedMsgType::PreCommit => 0x02,
            // Proposals
            SignedMsgType::Proposal => 0x20,
        }
    }

    #[allow(dead_code)]
    fn from(data: u32) -> Result<SignedMsgType, DecodeError> {
        match data {
            0x01 => Ok(SignedMsgType::PreVote),
            0x02 => Ok(SignedMsgType::PreCommit),
            0x20 => Ok(SignedMsgType::Proposal),
            _ => Err(DecodeError::new("Invalid vote type")),
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Vote {
    #[prost_amino(uint32, tag = "1")]
    pub vote_type: u32,
    #[prost_amino(int64)]
    pub height: i64,
    #[prost_amino(int64)]
    pub round: i64,
    #[prost_amino(message)]
    pub block_id: Option<BlockId>,
    #[prost_amino(message)]
    pub timestamp: Option<TimeMsg>,
    #[prost_amino(bytes)]
    pub validator_address: Vec<u8>,
    #[prost_amino(int64)]
    pub validator_index: i64,
    #[prost_amino(bytes)]
    pub signature: Vec<u8>,
}

impl Vote {
    fn msg_type(&self) -> Option<SignedMsgType> {
        if self.vote_type == SignedMsgType::PreVote.to_u32() {
            Some(SignedMsgType::PreVote)
        } else if self.vote_type == SignedMsgType::PreCommit.to_u32() {
            Some(SignedMsgType::PreCommit)
        } else {
            None
        }
    }
}

impl From<&vote::Vote> for Vote {
    fn from(vote: &vote::Vote) -> Self {
        Vote {
            vote_type: vote.vote_type.to_u32(),
            height: vote.height.value() as i64, // TODO potential overflow :-/
            round: vote.round as i64,
            block_id: vote.block_id.as_ref().map(|block_id| BlockId {
                hash: block_id.hash.as_bytes().to_vec(),
                parts_header: block_id.parts.as_ref().map(PartsSetHeader::from),
            }),
            timestamp: Some(TimeMsg::from(vote.timestamp)),
            validator_address: vote.validator_address.as_bytes().to_vec(),
            validator_index: vote.validator_index as i64, // TODO potential overflow :-/
            signature: vote.signature.as_bytes().to_vec(),
        }
    }
}

impl block::height::ParseHeight for Vote {
    fn parse_block_height(&self) -> Result<block::height::Height, Error> {
        block::height::Height::try_from(self.height)
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct CanonicalVote {
    #[prost_amino(uint32, tag = "1")]
    pub vote_type: u32,
    #[prost_amino(sfixed64)]
    pub height: i64,
    #[prost_amino(sfixed64)]
    pub round: i64,
    #[prost_amino(message)]
    pub block_id: Option<CanonicalBlockId>,
    #[prost_amino(message)]
    pub timestamp: Option<TimeMsg>,
    #[prost_amino(string)]
    pub chain_id: String,
}

impl chain::ParseId for CanonicalVote {
    fn parse_chain_id(&self) -> Result<chain::Id, Error> {
        self.chain_id.parse()
    }
}

impl block::height::ParseHeight for CanonicalVote {
    fn parse_block_height(&self) -> Result<block::height::Height, Error> {
        block::height::Height::try_from(self.height)
    }
}

impl CanonicalVote {
    pub fn new(vote: Vote, chain_id: &str) -> CanonicalVote {
        CanonicalVote {
            vote_type: vote.vote_type,
            chain_id: chain_id.to_string(),
            block_id: match vote.block_id {
                Some(bid) => Some(CanonicalBlockId {
                    hash: bid.hash,
                    parts_header: match bid.parts_header {
                        Some(psh) => Some(CanonicalPartSetHeader {
                            hash: psh.hash,
                            total: psh.total,
                        }),
                        None => None,
                    },
                }),
                None => None,
            },
            height: vote.height,
            round: vote.round,
            timestamp: match vote.timestamp {
                None => Some(TimeMsg {
                    seconds: -62_135_596_800,
                    nanos: 0,
                }),
                Some(t) => Some(t),
            },
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct CanonicalPartSetHeader {
    #[prost_amino(bytes, tag = "1")]
    pub hash: Vec<u8>,
    #[prost_amino(int64, tag = "2")]
    pub total: i64,
}

impl CanonicalPartSetHeader {
    fn parse_parts_header(&self) -> Option<block::parts::Header> {
        Hash::new(hash::Algorithm::Sha256, &self.hash)
            .map(|hash| block::parts::Header::new(self.total as u64, hash))
            .ok()
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct CanonicalBlockId {
    #[prost_amino(bytes, tag = "1")]
    pub hash: Vec<u8>,
    #[prost_amino(message, tag = "2")]
    pub parts_header: Option<CanonicalPartSetHeader>,
}

impl block::id::ParseId for CanonicalBlockId {
    fn parse_block_id(&self) -> Result<block::id::Id, BoxError> {
        let hash = Hash::new(hash::Algorithm::Sha256, &self.hash)?;
        let parts_header = self
            .parts_header
            .as_ref()
            .and_then(CanonicalPartSetHeader::parse_parts_header);
        Ok(block::id::Id::new(hash, parts_header))
    }
}
