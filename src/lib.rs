mod errors;
mod merkle_tree;
mod serialization;
mod types;
pub mod verification;

#[macro_use]
extern crate serde_derive;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
