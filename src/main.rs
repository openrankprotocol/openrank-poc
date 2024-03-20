use algo::{field, rational};
use halo2curves::{
    bn256::Fr,
    ff::{Field, PrimeField},
};
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use params::poseidon_bn254_5x5::Params;
use poseidon::Poseidon;
use rand::thread_rng;
use std::collections::HashMap;

use crate::algo::rational::Br;

mod algo;
mod compute_tree;
mod local_trust_tree;
mod merkle_tree;
mod params;
mod poseidon;

type Hasher = Poseidon<5, Params>;

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
    let mut rng = thread_rng();
    let peers = vec![
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
    ];
    let domain = "EigenTrust".to_string();
    let lt = [
        [0, 1, 4, 1, 4],
        [0, 0, 4, 1, 4],
        [0, 1, 0, 1, 4],
        [2, 1, 5, 0, 4],
        [3, 1, 4, 1, 0],
    ];
    let pre_trust = [0, 0, 0, 3, 7];

    let lt_f = lt.map(|lt_vec| lt_vec.map(|score| Fr::from(score)));
    let pre_trust_f = pre_trust.map(|score| Fr::from(score));
    let res_f = field::positive_run(domain, lt_f, pre_trust_f);
    println!("{:#?}", res_f);
}
