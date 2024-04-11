use halo2curves::bn256::Fr;
use halo2curves::ff::{Field, PrimeField};

pub fn transpose<const N: usize>(s: [[Fr; N]; N]) -> [[Fr; N]; N] {
    let mut new_s: [[Fr; N]; N] = [[Fr::zero(); N]; N];
    for i in 0..N {
        for j in 0..N {
            new_s[i][j] = s[j][i];
        }
    }
    new_s
}

pub fn normalise_sqrt<const N: usize>(vector: [Fr; N]) -> [Fr; N] {
    let sum: Fr = vector.iter().map(|x| x.square()).sum();
    if sum == Fr::zero() {
        return [Fr::zero(); N];
    }
    vector.map(|x| x * sum.sqrt().unwrap().invert().unwrap())
}

pub fn normalise(vector: [Fr; NUM_NEIGHBOURS]) -> [Fr; NUM_NEIGHBOURS] {
    let sum: Fr = vector.iter().sum();
    vector.map(|x| x * sum.invert().unwrap())
}

const NUM_NEIGHBOURS: usize = 5;

pub fn run<const NUM_ITER: usize>(
    am: [[Fr; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
    initial_state_hubs: [Fr; NUM_NEIGHBOURS],
    initial_state_auth: [Fr; NUM_NEIGHBOURS],
) -> ([Fr; NUM_NEIGHBOURS], [Fr; NUM_NEIGHBOURS]) {
    let mut s_hubs = initial_state_hubs.clone();
    let mut s_auth = initial_state_auth.clone();
    let transposed_am = transpose(am);

    for _ in 0..NUM_ITER {
        let mut new_s_hubs = [Fr::zero(); 5];
        let mut new_s_auth = [Fr::zero(); 5];

        // Hubs
        for i in 0..NUM_NEIGHBOURS {
            for j in 0..NUM_NEIGHBOURS {
                new_s_hubs[i] += am[j][i] * s_auth[j];
            }
        }
        // Authorities
        for i in 0..NUM_NEIGHBOURS {
            for j in 0..NUM_NEIGHBOURS {
                new_s_auth[i] += transposed_am[j][i] * s_hubs[j];
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
    // From hubs to authorities
    let adjacency_matrix: [[Fr; NUM_NEIGHBOURS]; NUM_NEIGHBOURS] = [
        [Fr::zero(), Fr::one(), Fr::zero(), Fr::one(), Fr::zero()],
        [Fr::zero(), Fr::zero(), Fr::zero(), Fr::one(), Fr::zero()],
        [Fr::one(), Fr::zero(), Fr::zero(), Fr::one(), Fr::one()],
        [Fr::zero(), Fr::one(), Fr::zero(), Fr::zero(), Fr::zero()],
        [Fr::zero(), Fr::one(), Fr::zero(), Fr::one(), Fr::zero()],
    ];
    let mut initial_state_hubs = [
        Fr::from_u128(32),
        Fr::zero(),
        Fr::from_u128(22),
        Fr::zero(),
        Fr::from_u128(66),
    ];
    let mut initial_state_auth = [
        Fr::from_u128(32),
        Fr::from_u128(11),
        Fr::from_u128(14),
        Fr::from_u128(1),
        Fr::from_u128(33),
    ];

    initial_state_hubs = normalise(initial_state_hubs);
    initial_state_auth = normalise(initial_state_auth);
    run::<30>(adjacency_matrix, initial_state_hubs, initial_state_auth);
}
