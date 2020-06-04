//! Merkle tree used in Tendermint networks

use sha2::{Digest, Sha256};

/// Size of Merkle root hash
pub const HASH_SIZE: usize = 32;

/// Hash is the output of the cryptographic digest function
pub type Hash = [u8; HASH_SIZE];

/// Compute a simple Merkle root from vectors of arbitrary byte vectors.
/// The leaves of the tree are the bytes of the given byte vectors in
/// the given order.
pub fn simple_hash_from_byte_vectors(byte_vecs: Vec<Vec<u8>>) -> Hash {
    simple_hash_from_byte_slices_inner(byte_vecs.as_slice())
}

// recurse into subtrees
fn simple_hash_from_byte_slices_inner(byte_slices: &[Vec<u8>]) -> Hash {
    let length = byte_slices.len();
    match length {
        0 => [0; HASH_SIZE],
        1 => leaf_hash(byte_slices[0].as_slice()),
        _ => {
            let k = get_split_point(length);
            let left = simple_hash_from_byte_slices_inner(&byte_slices[..k]);
            let right = simple_hash_from_byte_slices_inner(&byte_slices[k..]);
            inner_hash(&left, &right)
        }
    }
}

// returns the largest power of 2 less than length
fn get_split_point(length: usize) -> usize {
    match length {
        0 => panic!("tree is empty!"),
        1 => panic!("tree has only one element!"),
        2 => 1,
        _ => length.next_power_of_two() / 2,
    }
}

// tmhash(0x00 || leaf)
fn leaf_hash(bytes: &[u8]) -> Hash {
    // make a new array starting with 0 and copy in the bytes
    let mut leaf_bytes = Vec::with_capacity(bytes.len() + 1);
    leaf_bytes.push(0x00);
    leaf_bytes.extend_from_slice(bytes);

    // hash it !
    let digest = Sha256::digest(&leaf_bytes);

    // copy the GenericArray out
    let mut hash_bytes = [0u8; HASH_SIZE];
    hash_bytes.copy_from_slice(&digest);
    hash_bytes
}

// tmhash(0x01 || left || right)
fn inner_hash(left: &[u8], right: &[u8]) -> Hash {
    // make a new array starting with 0x1 and copy in the bytes
    let mut inner_bytes = Vec::with_capacity(left.len() + right.len() + 1);
    inner_bytes.push(0x01);
    inner_bytes.extend_from_slice(left);
    inner_bytes.extend_from_slice(right);

    // hash it !
    let digest = Sha256::digest(&inner_bytes);

    // copy the GenericArray out
    let mut hash_bytes = [0u8; HASH_SIZE];
    hash_bytes.copy_from_slice(&digest);
    hash_bytes
}
