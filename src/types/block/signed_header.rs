//! SignedHeader contains commit and and block header.
//! It is what the rpc endpoint /commit returns and hence can be used by a
//! light client.
use serde::{Deserialize, Serialize};

use crate::types::block;

/// Signed block headers
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SignedHeader {
    /// Block header
    pub header: block::header::Header,
    /// Commit containing signatures for the header
    pub commit: block::commit::Commit,
}
