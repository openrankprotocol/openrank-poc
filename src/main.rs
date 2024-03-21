use algo::{field, rational};
use compute_node::ComputeNode;
use da::SmartContract;
use halo2curves::{
    bn256::Fr,
    ff::{Field, PrimeField},
};
use merkle_tree::SparseMerkleTree;
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use params::poseidon_bn254_5x5::Params;
use poseidon::Poseidon;
use rand::thread_rng;
use std::collections::HashMap;

use crate::algo::rational::Br;

mod algo;
mod compute_node;
mod da;
mod merkle_tree;
mod params;
mod poseidon;

type Hasher = Poseidon<5, Params>;

struct LinearCombination {
    from: Fr,
    to: Fr,
    sum_of_weights: Fr,
}

#[derive(Clone, Debug)]
struct Challenge {
    from: Fr,
    to: Fr,
}

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

fn compute_node_work() -> ComputeNode {
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

    ComputeNode::new(
        peers,
        lt.map(|lt_vec| lt_vec.map(|score| Fr::from(score)).to_vec())
            .to_vec(),
        res_f.to_vec(),
    )
}

fn main() {
    let mut sc = SmartContract::new();

    // Compute node does the work
    let compute_node = compute_node_work();
    let da_data = compute_node.da_data();

    // Compute node sumbits data to a smart contract
    sc.post_data(da_data);

    // TODO: Implement challenger logic
    // TODO: Implement final challange response logic
}
