use crate::compute_node::big_to_fe_rat;
use halo2curves::bn256::Fr;
use num_bigint::BigUint;
use num_integer::Integer;
use num_rational::Ratio;
use num_traits::{FromPrimitive, One, Zero};
use std::array::from_fn;

pub type Br = Ratio<BigUint>;

pub fn transpose<const N: usize>(s: [[BigUint; N]; N]) -> [[BigUint; N]; N] {
    let mut new_s: [[BigUint; N]; N] = from_fn(|_| from_fn(|_| BigUint::zero()));
    for i in 0..N {
        for j in 0..N {
            new_s[i][j] = s[j][i].clone();
        }
    }
    new_s
}

pub fn normalise_sqrt<const N: usize>(vector: [Br; N]) -> [Br; N] {
    let sum: Br = vector.iter().map(|x| x.pow(2)).sum();
    if sum == Br::zero() {
        return from_fn(|_| Br::zero());
    }
    let num_sqrt = sum.numer().sqrt();
    let den_sqrt = sum.denom().sqrt();
    let sum_sqrt = Br::new(num_sqrt, den_sqrt);

    vector.map(|x| x / sum_sqrt.clone())
}

pub fn normalise(scores: [BigUint; NUM_NEIGHBOURS]) -> [Br; NUM_NEIGHBOURS] {
    let sum: BigUint = scores.clone().into_iter().sum();
    scores.map(|x| Br::new(x, sum.clone()))
}

const NUM_NEIGHBOURS: usize = 5;

pub fn run<const NUM_ITER: usize>(
    am: [[BigUint; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
    initial_state_hubs: [Br; NUM_NEIGHBOURS],
    initial_state_auth: [Br; NUM_NEIGHBOURS],
) -> ([Br; NUM_NEIGHBOURS], [Br; NUM_NEIGHBOURS]) {
    let mut s_hubs = initial_state_hubs.clone();
    let mut s_auth = initial_state_auth.clone();
    let transposed_am = transpose(am.clone());
    let am_br = am.map(|xs| xs.map(|x| Br::new(x, BigUint::one())));
    let transposed_am_br = transposed_am.map(|xs| xs.map(|x| Br::new(x, BigUint::one())));

    for _ in 0..NUM_ITER {
        let mut new_s_hubs = from_fn(|_| Br::zero());
        let mut new_s_auth = from_fn(|_| Br::zero());

        // Hubs
        for i in 0..NUM_NEIGHBOURS {
            for j in 0..NUM_NEIGHBOURS {
                new_s_hubs[i] += am_br[j][i].clone() * s_auth[j].clone();
            }
        }
        // Authorities
        for i in 0..NUM_NEIGHBOURS {
            for j in 0..NUM_NEIGHBOURS {
                new_s_auth[i] += transposed_am_br[j][i].clone() * s_hubs[j].clone();
            }
        }

        let final_s_hubs = normalise_sqrt(new_s_hubs);
        let final_s_auth = normalise_sqrt(new_s_auth);

        s_hubs = final_s_hubs;
        s_auth = final_s_auth;
    }

    (s_hubs, s_auth)
}

pub fn run_job() {
    // Brom hubs to authorities
    let adjacency_matrix: [[BigUint; NUM_NEIGHBOURS]; NUM_NEIGHBOURS] = [
        [
            BigUint::zero(),
            BigUint::one(),
            BigUint::zero(),
            BigUint::one(),
            BigUint::zero(),
        ],
        [
            BigUint::zero(),
            BigUint::zero(),
            BigUint::zero(),
            BigUint::one(),
            BigUint::zero(),
        ],
        [
            BigUint::one(),
            BigUint::zero(),
            BigUint::zero(),
            BigUint::one(),
            BigUint::one(),
        ],
        [
            BigUint::zero(),
            BigUint::one(),
            BigUint::zero(),
            BigUint::zero(),
            BigUint::zero(),
        ],
        [
            BigUint::zero(),
            BigUint::one(),
            BigUint::zero(),
            BigUint::one(),
            BigUint::zero(),
        ],
    ];
    let initial_state_hubs = [
        BigUint::from_u128(32).unwrap(),
        BigUint::zero(),
        BigUint::from_u128(22).unwrap(),
        BigUint::zero(),
        BigUint::from_u128(66).unwrap(),
    ];
    let initial_state_auth = [
        BigUint::from_u128(32).unwrap(),
        BigUint::from_u128(11).unwrap(),
        BigUint::from_u128(14).unwrap(),
        BigUint::from_u128(1).unwrap(),
        BigUint::from_u128(33).unwrap(),
    ];

    let initial_state_hubs = normalise(initial_state_hubs);
    let initial_state_auth = normalise(initial_state_auth);
    run::<30>(adjacency_matrix, initial_state_hubs, initial_state_auth);
}
