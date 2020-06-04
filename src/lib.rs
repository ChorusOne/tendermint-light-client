mod errors;
mod merkle_tree;
mod serialization;
mod types;
pub mod verification;

#[macro_use]
extern crate serde_derive;

pub mod block {
    pub use crate::types::block::{height::Height, id::Id, commit::Commit, header::Header, signed_header::SignedHeader};
}

pub mod time {
    pub use crate::types::time::Time;
}

pub mod validator {
    pub use crate::types::validator::{Set,Info};
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
