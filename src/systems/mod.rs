use halo2curves::{bn256::Fr, ff::PrimeField};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One};

use crate::algo::{
    et_field,
    et_rational::{self, Br},
    h_and_a_float, h_and_a_rational,
};

pub mod optimistic;
pub mod pessimistic;

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

pub fn compute_node_et_work(
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

pub fn compute_node_ha_work(
    am: [[u64; 5]; 5],
    initial_state_hubs: [u64; 5],
    initial_state_auth: [u64; 5],
) -> (
    [[Fr; 5]; 5],
    [[BigUint; 5]; 5],
    ([Fr; 5], [Fr; 5]),
    ([Br; 5], [Br; 5]),
    ([Br; 5], [Br; 5]),
) {
    let am_f = am.map(|xs| xs.map(|x| Fr::from(x)));

    let am_bn = am.map(|xs| xs.map(|x| BigUint::from(x)));
    let initial_state_hubs_bn = initial_state_hubs.map(|x| BigUint::from(x));
    let initial_state_auth_bn = initial_state_auth.map(|x| BigUint::from(x));

    let initial_state_hubs_br = h_and_a_rational::normalise(initial_state_hubs_bn);
    let initial_state_auth_br = h_and_a_rational::normalise(initial_state_auth_bn);

    let am_fl = am.map(|xs| xs.map(|x| x as f32));
    let initial_state_hubs_fl = initial_state_hubs.map(|x| x as f32);
    let initial_state_auth_fl = initial_state_auth.map(|x| x as f32);

    let initial_state_hubs_fl = h_and_a_float::normalise(initial_state_hubs_fl);
    let initial_state_auth_fl = h_and_a_float::normalise(initial_state_auth_fl);

    let (scores_hubs_fl, scores_auth_fl) =
        h_and_a_float::run::<30>(am_fl, initial_state_hubs_fl, initial_state_auth_fl);
    let (scores_hubs_br, scores_auth_br) =
        h_and_a_rational::run::<30>(am_bn.clone(), initial_state_hubs_br, initial_state_auth_br);
    let (final_scores_hubs, final_scores_auth) = h_and_a_rational::run::<1>(
        am_bn.clone(),
        scores_hubs_br.clone(),
        scores_auth_br.clone(),
    );

    const SCALE: f32 = 1000000000.0;
    let scores_hubs_f = scores_hubs_fl.map(|x| Fr::from_u128((x * SCALE) as u128));
    let scores_auth_f = scores_auth_fl.map(|x| Fr::from_u128((x * SCALE) as u128));

    (
        am_f,
        am_bn,
        (scores_hubs_f, scores_auth_f),
        (scores_hubs_br, scores_auth_br),
        (final_scores_hubs, final_scores_auth),
    )
}