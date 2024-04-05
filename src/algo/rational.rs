use num_bigint::BigUint;
use num_rational::Ratio;
use num_traits::Zero;
use std::array::from_fn;

pub type Br = Ratio<BigUint>;

const NUM_NEIGHBOURS: usize = 5;

fn validate_lt(lt: [[BigUint; NUM_NEIGHBOURS]; NUM_NEIGHBOURS]) {
    // Compute sum of incoming distrust
    for i in 0..NUM_NEIGHBOURS {
        for j in 0..NUM_NEIGHBOURS {
            // Make sure we are not giving score to ourselves
            if i == j {
                assert_eq!(lt[i][j], BigUint::zero());
            }
        }
    }
}

pub fn normalise(lt_vec: [BigUint; NUM_NEIGHBOURS]) -> [Br; NUM_NEIGHBOURS] {
    let sum: BigUint = lt_vec.clone().into_iter().sum();
    lt_vec.map(|x| Br::new(x, sum.clone()))
}

fn vec_add(s: [Br; NUM_NEIGHBOURS], y: [Br; NUM_NEIGHBOURS]) -> [Br; NUM_NEIGHBOURS] {
    let mut out: [Br; NUM_NEIGHBOURS] = from_fn(|_| Br::zero());
    for i in 0..NUM_NEIGHBOURS {
        out[i] = s[i].clone() + y[i].clone();
    }
    out
}

pub fn positive_run<const NUM_ITER: usize>(
    lt: [[BigUint; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
    seed: [Br; NUM_NEIGHBOURS],
) -> [Br; NUM_NEIGHBOURS] {
    validate_lt(lt.clone());
    let mut normalised_lt: [[Br; NUM_NEIGHBOURS]; NUM_NEIGHBOURS] =
        from_fn(|_| from_fn(|_| Br::zero()));
    for i in 0..NUM_NEIGHBOURS {
        normalised_lt[i] = normalise(lt[i].clone());
    }

    let mut s = seed.clone();

    for _ in 0..NUM_ITER {
        let mut new_s = from_fn(|_| Br::zero());

        // Compute sum of incoming weights
        for i in 0..NUM_NEIGHBOURS {
            for j in 0..NUM_NEIGHBOURS {
                new_s[i] += normalised_lt[j][i].clone() * s[j].clone();
            }
        }

        s = new_s;
    }

    s
}
