use num_bigint::BigUint;
use num_rational::Ratio;
use num_traits::{FromPrimitive, One, Zero};
use std::array::from_fn;

pub type Br = Ratio<BigUint>;

const NUM_NEIGHBOURS: usize = 5;
const NUM_ITER: usize = 30;

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

fn normalise(
    lt_vec: [BigUint; NUM_NEIGHBOURS],
    pre_trust: [BigUint; NUM_NEIGHBOURS],
) -> [Br; NUM_NEIGHBOURS] {
    let sum: BigUint = lt_vec.clone().into_iter().sum();
    if sum == BigUint::zero() {
        return pre_trust.map(|x| Br::new(x, BigUint::one()));
    }
    lt_vec.map(|x| Br::new(x, sum.clone()))
}

fn vec_add(s: [Br; NUM_NEIGHBOURS], y: [Br; NUM_NEIGHBOURS]) -> [Br; NUM_NEIGHBOURS] {
    let mut out: [Br; NUM_NEIGHBOURS] = from_fn(|_| Br::zero());
    for i in 0..NUM_NEIGHBOURS {
        out[i] = s[i].clone() + y[i].clone();
    }
    out
}

pub fn positive_run(
    domain: String,
    lt: [[BigUint; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
    pre_trust: [BigUint; NUM_NEIGHBOURS],
) -> [Br; NUM_NEIGHBOURS] {
    println!();
    println!("{} - Trust:", domain);

    validate_lt(lt.clone());
    let mut normalised_lt: [[Br; NUM_NEIGHBOURS]; NUM_NEIGHBOURS] =
        from_fn(|_| from_fn(|_| Br::zero()));
    for i in 0..NUM_NEIGHBOURS {
        normalised_lt[i] = normalise(lt[i].clone(), pre_trust.clone());
    }

    let mut s = pre_trust.clone().map(|x| Br::new(x, BigUint::one()));
    let pre_trust_weight = Br::new(BigUint::one(), BigUint::from_u8(2).unwrap());
    let pre_trusted_scores =
        pre_trust.map(|x| Br::new(x, BigUint::one()) * pre_trust_weight.clone());

    for _ in 0..NUM_ITER {
        let mut new_s = from_fn(|_| Br::zero());

        // Compute sum of incoming weights
        for i in 0..NUM_NEIGHBOURS {
            for j in 0..NUM_NEIGHBOURS {
                new_s[i] += normalised_lt[j][i].clone() * s[j].clone();
            }
        }

        let global_scores = new_s.map(|x| (Br::one() - pre_trust_weight.clone()) * x);
        let current_s = vec_add(pre_trusted_scores.clone(), global_scores);

        s = current_s;
    }

    s
}
