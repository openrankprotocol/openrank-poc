use algo::{
    et_field,
    et_rational::{self, normalise, Br},
};
use compute_node::ComputeNode;
use halo2curves::{
    bn256::Fr,
    ff::{Field, PrimeField},
};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Zero;
use num_traits::{FromPrimitive, One};
use params::poseidon_bn254_5x5::Params;
use poseidon::Poseidon;
use rand::thread_rng;
use settlement::SmartContract;
use std::array::from_fn;

mod algo;
mod compute_node;
mod merkle_tree;
mod params;
mod poseidon;
mod settlement;

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

#[derive(Clone, Debug)]
pub struct ConsistencyChallenge {
    target1: Challenge,
    target2: Challenge,
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

fn compute_node_work(
    lt: [[u64; 5]; 5],
    pre_trust: [u64; 5],
) -> ([[Fr; 5]; 5], [Fr; 5], [Br; 5], [Br; 5]) {
    let lt_f = lt.map(|lt_arr| lt_arr.map(|score| Fr::from(score)));
    let pre_trust_f = pre_trust.map(|score| Fr::from(score));
    let lt_br = lt.map(|lt_arr| lt_arr.map(|score| BigUint::from_u64(score).unwrap()));
    let pre_trust_br = pre_trust.map(|score| BigUint::from_u64(score).unwrap());
    let seed_br = pre_trust_br.clone().map(|x| Br::new(x, BigUint::one()));

    let res_f = et_field::positive_run::<30>(lt_f.clone(), pre_trust_f);
    let res_br = et_rational::positive_run::<30>(lt_br.clone(), seed_br.clone());
    let res_final_br = et_rational::positive_run::<1>(lt_br, res_br.clone());

    (lt_f, res_f, res_br, res_final_br)
}

fn optimisitic_interactive_positive() {
    let mut rng = thread_rng();
    let peers = [
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
    ];
    let lt = [
        [0, 1, 4, 1, 4], // 10
        [0, 0, 4, 1, 4], // 9
        [0, 1, 0, 1, 4], // 6
        [2, 1, 5, 0, 4], // 12
        [3, 1, 4, 1, 0], // 9
    ];
    let pre_trust = [0, 0, 0, 3, 7];

    let mut sc = SmartContract::new();

    // Compute node does the work
    let (lt_f, res_f, res_br, res_final_br) = compute_node_work(lt, pre_trust);
    let compute_node = ComputeNode::new(
        peers.to_vec(),
        lt_f.map(|lt_arr| lt_arr.to_vec()).to_vec(),
        res_f.to_vec(),
        res_br.to_vec(),
        res_final_br.to_vec(),
    );

    // Compute node sumbits data to a smart contract
    let sc_data = compute_node.sc_data();
    sc.post_data(sc_data);

    // Challenger submits a challenge
    let challenge_validity = Challenge {
        from: peers[0], // wrong at the incoming arc from 'from'/peer[0]
        to: peers[3],   // this peers score is wrong
    };
    let challange_consistency = ConsistencyChallenge {
        target1: challenge_validity.clone(),
        // Different location
        target2: Challenge {
            from: peers[0],
            to: peers[4],
        },
    };
    sc.post_challenge(challenge_validity.clone(), challange_consistency.clone());

    let precision = 6;
    // The submitter posts a response to the challenge
    let validity_proof = compute_node.compute_validity_proof(challenge_validity, precision);
    let consistency_proof = compute_node.compute_consistency_proof(challange_consistency);
    sc.post_response(validity_proof, consistency_proof); // proof is also verified here
}

fn optimisitic_interactive_negative() {
    let mut rng = thread_rng();
    let peers = [
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
    ];
    let lt = [
        [0, 1, 4, 1, 4], // 10
        [0, 0, 4, 1, 4], // 9
        [0, 1, 0, 1, 4], // 6
        [2, 1, 5, 0, 4], // 12
        [3, 1, 4, 1, 0], // 9
    ];
    let pre_trust = [0, 0, 0, 3, 7];

    let mut sc = SmartContract::new();

    // Compute node does the work
    let (lt_f, mut res_f, res_br, res_final_br) = compute_node_work(lt, pre_trust);

    // Modify one score, make it invalid
    res_f[1] = Fr::zero();
    let compute_node = ComputeNode::new(
        peers.to_vec(),
        lt_f.map(|lt_arr| lt_arr.to_vec()).to_vec(),
        res_f.to_vec(),
        res_br.to_vec(),
        res_final_br.to_vec(),
    );

    // Compute node sumbits data to a smart contract
    let sc_data = compute_node.sc_data();
    sc.post_data(sc_data);

    // Challenger submits a challenge
    let challenge_validity = Challenge {
        from: peers[1], // wrong at the incoming arc from 'from'/peer[1]
        to: peers[3],   // this peers score is wrong
    };
    let challange_consistency = ConsistencyChallenge {
        target1: challenge_validity.clone(),
        // Different location
        target2: Challenge {
            from: peers[1],
            to: peers[4],
        },
    };
    sc.post_challenge(challenge_validity.clone(), challange_consistency.clone());

    let precision = 6;
    // The submitter posts a response to the challenge
    let validity_proof = compute_node.compute_validity_proof(challenge_validity, precision);
    let consistency_proof = compute_node.compute_consistency_proof(challange_consistency);
    sc.post_response(validity_proof, consistency_proof); // proof is also verified here
}

fn pessimistic_positive() {
    let lt = [
        [0, 1, 4, 1, 4], // 10
        [0, 0, 4, 1, 4], // 9
        [0, 1, 0, 1, 4], // 6
        [2, 1, 5, 0, 4], // 12
        [3, 1, 4, 1, 0], // 9
    ];
    let pre_trust = [0, 0, 0, 3, 7];

    // Compute node does the work
    let (_, _, res_br, _) = compute_node_work(lt.clone(), pre_trust);

    let mut normalised_lt: [[Br; 5]; 5] = from_fn(|_| from_fn(|_| Br::zero()));
    for i in 0..5 {
        normalised_lt[i] = normalise(lt[i].map(|score| BigUint::from_u64(score).unwrap()));
    }

    let target_peer_id = 1;
    let mut new_s = Br::zero();
    for j in 0..5 {
        new_s += normalised_lt[j][target_peer_id].clone() * res_br[j].clone();
    }

    let prev_s = res_br[target_peer_id].clone();

    let lcm = prev_s.denom().lcm(&new_s.denom());
    let c_numer = prev_s.numer().clone() * (lcm.clone() / prev_s.denom().clone());
    let c_prime_numer = new_s.numer() * (lcm.clone() / new_s.denom());

    let scale = BigUint::from(10usize).pow(46);
    let c_numer_reduced = c_numer.div_floor(&scale);
    let c_prime_numer_reduced = c_prime_numer.div_floor(&scale);

    assert_eq!(c_numer_reduced, c_prime_numer_reduced);
}

fn pessimistic_negative() {
    let lt = [
        [0, 1, 4, 1, 4], // 10
        [0, 0, 4, 1, 4], // 9
        [0, 1, 0, 1, 4], // 6
        [2, 1, 5, 0, 4], // 12
        [3, 1, 4, 1, 0], // 9
    ];
    let pre_trust = [0, 0, 0, 3, 7];

    // Compute node does the work
    let (_, _, mut res_br, _) = compute_node_work(lt.clone(), pre_trust);

    let mut normalised_lt: [[Br; 5]; 5] = from_fn(|_| from_fn(|_| Br::zero()));
    for i in 0..5 {
        normalised_lt[i] = normalise(lt[i].map(|score| BigUint::from_u64(score).unwrap()));
    }

    let target_peer_id = 1;
    // Make the score for 'target_peer_id' invalid
    res_br[target_peer_id] = Br::zero();

    let mut new_s = Br::zero();
    for j in 0..5 {
        new_s += normalised_lt[j][target_peer_id].clone() * res_br[j].clone();
    }

    let prev_s = res_br[target_peer_id].clone();

    let lcm = prev_s.denom().lcm(&new_s.denom());
    let c_numer = prev_s.numer().clone() * (lcm.clone() / prev_s.denom().clone());
    let c_prime_numer = new_s.numer() * (lcm.clone() / new_s.denom());

    let scale = BigUint::from(10usize).pow(46);
    let c_numer_reduced = c_numer.div_floor(&scale);
    let c_prime_numer_reduced = c_prime_numer.div_floor(&scale);

    assert_eq!(c_numer_reduced, c_prime_numer_reduced);
}

fn main() {
    pessimistic_negative();
}
