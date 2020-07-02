//! Tendermint client identifiers

use crate::errors::{Error, Kind};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    cmp::Ordering,
    fmt::{self, Debug, Display},
    str::{self, FromStr},
};
use std::convert::TryFrom;

/// Maximum length of a `client::Id` name.
pub const MAX_LENGTH: usize = 20;
/// Maximum length of a `client::Id` name.
pub const MIN_LENGTH: usize = 10;

/// Client identifier (e.g. 'ajjlsinbshj')
#[derive(Copy, Clone)]
pub struct Id([u8; MAX_LENGTH]);

impl Id {
    /// Get the client ID as a `str`
    pub fn as_str(&self) -> &str {
        let byte_slice = match self.0.as_ref().iter().position(|b| *b == b'\0') {
            Some(pos) => &self.0[..pos],
            None => self.0.as_ref(),
        };

        // We assert above the ID only has characters in the valid UTF-8 range,
        // so in theory this should never panic
        str::from_utf8(byte_slice).unwrap()
    }

    /// Get the client ID as a raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.as_str().as_bytes()
    }
}

impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "client::Id({})", self.as_str())
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<'a> TryFrom<&'a str> for Id {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl FromStr for Id {
    type Err = Error;
    /// Parses string to create a new client ID
    fn from_str(name: &str) -> Result<Self, Error> {
        if name.is_empty() || name.len() < MIN_LENGTH || name.len() > MAX_LENGTH {
            return Err(Kind::Length.into());
        }

        for byte in name.as_bytes() {
            match byte {
                b'a'..=b'z' => (),
                _ => return Err(Kind::Parse.into()),
            }
        }

        let mut bytes = [0u8; MAX_LENGTH];
        bytes[..name.as_bytes().len()].copy_from_slice(name.as_bytes());
        Ok(Id(bytes))
    }
}

impl PartialOrd for Id {
    fn partial_cmp(&self, other: &Id) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Id {
    fn cmp(&self, other: &Id) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialEq for Id {
    fn eq(&self, other: &Id) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Id {}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_str(&String::deserialize(deserializer)?)
            .map_err(|e| D::Error::custom(format!("{}", e)))
    }
}

/// Parse `client::Id` from a type
pub trait ParseId {
    /// Parse `client::Id`, or return an `Error` if parsing failed
    fn parse_client_id(&self) -> Result<Id, Error>;
}
