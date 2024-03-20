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
    let mut rng = thread_rng();
    let peers = vec![
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
    ];
    let attestations = vec![
        Attestation {
            from: peers[0],
            to: peers[1],
            weight: Fr::from(1),
            timestamp: Fr::zero(),
        },
        Attestation {
            from: peers[0],
            to: peers[2],
            weight: Fr::from(4),
            timestamp: Fr::zero(),
        },
        Attestation {
            from: peers[0],
            to: peers[3],
            weight: Fr::from(1),
            timestamp: Fr::zero(),
        },
        Attestation {
            from: peers[0],
            to: peers[4],
            weight: Fr::from(4),
            timestamp: Fr::zero(),
        },
        Attestation {
            from: peers[1],
            to: peers[2],
            weight: Fr::from(4),
            timestamp: Fr::zero(),
        },
        Attestation {
            from: peers[1],
            to: peers[3],
            weight: Fr::from(1),
            timestamp: Fr::zero(),
        },
        Attestation {
            from: peers[1],
            to: peers[4],
            weight: Fr::from(4),
            timestamp: Fr::zero(),
        },
        Attestation {
            from: peers[2],
            to: peers[4],
            weight: Fr::from(4),
            timestamp: Fr::zero(),
        },
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
