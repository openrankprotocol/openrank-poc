use halo2curves::{bn256::Fr, ff::PrimeField};

mod merkle_tree;
mod params;
mod poseidon;

/// Converts given bytes to the bits.
pub fn to_bits(num: &[u8]) -> Vec<bool> {
    let len = num.len() * 8;
    let mut bits = Vec::new();
    for i in 0..len {
        let bit = num[i / 8] & (1 << (i % 8)) != 0;
        bits.push(bit);
    }
    bits
}

/// Converts given field element to the bits.
pub fn field_to_bits_vec(num: Fr) -> Vec<bool> {
    let bits = to_bits(&num.to_bytes());
    let sliced_bits = bits[..Fr::NUM_BITS as usize].to_vec();
    sliced_bits
}

fn main() {
    println!("Hello, world!");
}
