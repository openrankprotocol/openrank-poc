use halo2curves::{bn256::Fr, ff::PrimeField};
use params::poseidon_bn254_5x5::Params;
use poseidon::Poseidon;
use std::collections::HashMap;

mod compute_tree;
mod eigen_trust;
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

pub struct Attestation {
    pub(crate) from: Fr,
    pub(crate) to: Fr,
    pub(crate) weight: Fr,
    pub(crate) timestamp: Fr,
}

impl Attestation {
    fn verify(&self) -> bool {
        true
    }
}

pub struct LinearCombination {
    pub(crate) from: Fr,
    pub(crate) to: Fr,
    pub(crate) sum_weights: Fr,
}

fn aggregate_attestations(atts: Vec<Attestation>) -> Vec<LinearCombination> {
    let mut peer_map = HashMap::new();
    atts.iter().for_each(|x| {
        assert!(x.verify());
        let prev = peer_map.get(&(x.from, x.to)).unwrap_or(&Fr::zero()).clone();
        peer_map.insert((x.from, x.to), prev + x.weight);
    });

    peer_map
        .iter()
        .map(|(&(from, to), &val)| LinearCombination {
            from,
            to,
            sum_weights: val,
        })
        .collect()
}

fn main() {
    println!("Hello, world!");
}
