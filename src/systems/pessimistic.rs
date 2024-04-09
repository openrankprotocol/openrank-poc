use crate::algo::et_rational::{normalise, Br};
use crate::systems::compute_node_et_work;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::FromPrimitive;
use num_traits::Zero;
use std::array::from_fn;

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
    let (_, _, res_br, _) = compute_node_et_work(lt.clone(), pre_trust);

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
    let (_, _, mut res_br, _) = compute_node_et_work(lt.clone(), pre_trust);

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
