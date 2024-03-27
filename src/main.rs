use algo::{
    field,
    rational::{self, Br},
};
use compute_node::ComputeNode;
use da::SmartContract;
use halo2curves::{
    bn256::Fr,
    ff::{Field, PrimeField},
};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One};
use params::poseidon_bn254_5x5::Params;
use poseidon::Poseidon;
use rand::thread_rng;

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
pub struct Challenge {
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

fn compute_node_work(peers: [Fr; 5], lt: [[u64; 5]; 5], pre_trust: [u64; 5]) -> ComputeNode {
    let lt_f = lt.map(|lt_arr| lt_arr.map(|score| Fr::from(score)));
    let pre_trust_f = pre_trust.map(|score| Fr::from(score));
    let lt_br = lt.map(|lt_arr| lt_arr.map(|score| BigUint::from_u64(score).unwrap()));
    let pre_trust_br = pre_trust.map(|score| BigUint::from_u64(score).unwrap());

    let seed = pre_trust_br.clone().map(|x| Br::new(x, BigUint::one()));
    let res_f = field::positive_run::<30>(lt_f, pre_trust_f);
    let res_br = rational::positive_run::<30>(lt_br.clone(), seed.clone());
    let res_final_br = rational::positive_run::<1>(lt_br, res_br.clone());

    ComputeNode::new(
        peers.to_vec(),
        lt_f.map(|lt_arr| lt_arr.to_vec()).to_vec(),
        res_f.to_vec(),
        res_br.to_vec(),
        res_final_br.to_vec(),
    )
}

fn main() {
    let mut rng = thread_rng();
    let peers = [
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
    ];
    let lt = [
        [0, 1, 4, 1, 4],
        [0, 0, 4, 1, 4],
        [0, 1, 0, 1, 4],
        [2, 1, 5, 0, 4],
        [3, 1, 4, 1, 0],
    ];
    let pre_trust = [0, 0, 0, 3, 7];

    let mut sc = SmartContract::new();

    // Compute node does the work
    let compute_node = compute_node_work(peers, lt, pre_trust);

    // Compute node sumbits data to a smart contract
    let sc_data = compute_node.sc_data();
    sc.post_data(sc_data);

    // Challenger submits a challenge
    let challenge = Challenge {
        from: peers[0], // wrong at the incoming arc from 'from'/peer[0]
        to: peers[1],   // this peers score is wrong
    };
    sc.post_challenge(challenge.clone());

    // The submitter posts a response to the challenge
    let proof = compute_node.compute_fraud_proof(challenge, 10, 10);
    sc.post_response(proof); // proof is also verified here
}
