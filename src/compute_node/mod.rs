use crate::{algo::rational::Br, merkle_tree::Path, Challenge, Hasher};
use halo2curves::ff::Field;
use halo2curves::{bn256::Fr, ff::PrimeField};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Num;

use self::{
    compute_tree::{ComputeTree, ComputeTreeMembershipProof},
    lt_tree::{LocalTrustTree, LocalTrustTreeMembershipProof},
};

mod compute_tree;
mod lt_tree;

// TODO: Rename to appropriate name
pub struct ComputeTreeFraudProof {
    // Peers Global Trust path
    peer_path: ComputeTreeMembershipProof,
    // Neighbours Global Trust path
    neighbour_path: Path<Hasher>,
    // Neighbours local trust path
    lt_tree_path: LocalTrustTreeMembershipProof,
    // Claimed score
    c: BrDecomposed,
    // Calculated score
    c_prime: BrDecomposed,
}

impl ComputeTreeFraudProof {
    pub fn verify(&self, data: [Fr; 2], challenge: Challenge) -> bool {
        let [local_trust_tree_root, compute_tree_root] = data;

        let is_peer_path_correct = self.peer_path.verify();
        let is_neighbour_lt_path_correct = self.lt_tree_path.verify();
        let is_neighbour_path_correct = self.neighbour_path.verify();

        let (peer_root, _) = self.peer_path.master_tree_path.root();
        let (lt_root, _) = self.lt_tree_path.master_tree_path.root();
        let (n_root, _) = self.neighbour_path.root();

        let is_peer_root_correct = peer_root == compute_tree_root;
        let is_lt_root_correct = lt_root == local_trust_tree_root;
        let is_neighbour_root_correct = compute_tree_root == n_root;

        let (_, lc) = self.lt_tree_path.sub_tree_path.value();
        let (_, sum) = self.lt_tree_path.sub_tree_path.root();
        let (_, n_gt) = self.neighbour_path.value();
        let (lt_peer_subtree, gt_peer_subtree) = self.peer_path.sub_tree_path.value();

        let is_lt_correct = lc * sum.invert().unwrap() == lt_peer_subtree;
        let is_gt_correct = n_gt == gt_peer_subtree;

        let is_neighbour_index_correct = self.neighbour_path.index == challenge.from;
        let is_neighbour_local_trust_correct =
            self.lt_tree_path.sub_tree_path.index == challenge.to;
        let is_peer_local_trust_correct =
            self.lt_tree_path.master_tree_path.index == challenge.from;
        let is_peer_global_trust_term_correct =
            self.peer_path.sub_tree_path.index == challenge.from;
        let is_peer_global_trust_correct = self.peer_path.master_tree_path.index == challenge.to;

        let (_, final_score_prime) = self.peer_path.sub_tree_path.root();
        let (_, final_score) = self.peer_path.master_tree_path.value();

        let composed_c_num =
            compose_big_decimal_f(self.c.num.clone(), self.c.num_limbs, self.c.power_of_ten);
        let composed_c_den =
            compose_big_decimal_f(self.c.den.clone(), self.c.num_limbs, self.c.power_of_ten);

        let composed_c_prime_num = compose_big_decimal_f(
            self.c_prime.num.clone(),
            self.c_prime.num_limbs,
            self.c_prime.power_of_ten,
        );
        let composed_c_prime_den = compose_big_decimal_f(
            self.c_prime.den.clone(),
            self.c_prime.num_limbs,
            self.c_prime.power_of_ten,
        );

        let composed_c = composed_c_num * composed_c_den.invert().unwrap();
        let composed_c_prime = composed_c_prime_num * composed_c_prime_den.invert().unwrap();
        let rounded_c = self.c.den[0] * self.c.num[0];
        let rounded_c_prime = self.c_prime.den[0] * self.c_prime.num[0];

        let is_c_equal = composed_c == final_score;
        let is_c_prime_equal = composed_c_prime == final_score_prime;
        let is_rounded_equal = rounded_c == rounded_c_prime;

        is_peer_path_correct
            && is_neighbour_lt_path_correct
            && is_neighbour_path_correct
            && is_neighbour_root_correct
            && is_lt_root_correct
            && is_peer_root_correct
            && is_lt_correct
            && is_gt_correct
            && is_neighbour_index_correct
            && is_neighbour_local_trust_correct
            && is_peer_local_trust_correct
            && is_peer_global_trust_term_correct
            && is_peer_global_trust_correct
            && is_c_equal
            && is_c_prime_equal
            && is_rounded_equal
    }
}

pub struct ComputeNode {
    compute_tree: ComputeTree,
    local_trust_tree: LocalTrustTree,
    scores_br: Vec<Br>,
    scores_final_br: Vec<Br>,
    peers: Vec<Fr>,
}

impl ComputeNode {
    pub fn new(
        peers: Vec<Fr>,
        lt: Vec<Vec<Fr>>,
        scores_f: Vec<Fr>,
        scores_br: Vec<Br>,
        scores_final_br: Vec<Br>,
    ) -> Self {
        let local_trust_tree = LocalTrustTree::new(peers.clone(), lt.clone());
        let compute_tree = ComputeTree::new(peers.clone(), lt, scores_f);
        Self {
            compute_tree,
            local_trust_tree,
            scores_br,
            scores_final_br,
            peers,
        }
    }

    pub fn compute_fraud_proof(
        &self,
        challenge: Challenge,
        num_decimal_limbs: usize,
        power_of_ten: usize,
    ) -> ComputeTreeFraudProof {
        let peer_path = self.compute_tree.find_membership_proof(challenge.clone());
        let lt_tree_path = self
            .local_trust_tree
            .find_membership_proof(challenge.clone());
        let neighbour_path = self.compute_tree.master_tree.find_path(challenge.from);

        let index = self.peers.iter().position(|&x| challenge.to == x).unwrap();
        let c = big_to_fe_rat(
            self.scores_br[index].clone(),
            num_decimal_limbs,
            power_of_ten,
        );
        let c_prime = big_to_fe_rat(
            self.scores_final_br[index].clone(),
            num_decimal_limbs,
            power_of_ten,
        );

        ComputeTreeFraudProof {
            peer_path,
            lt_tree_path,
            neighbour_path,
            c,
            c_prime,
        }
    }

    pub fn sc_data(&self) -> [Fr; 2] {
        let lt_root = self.local_trust_tree.master_tree.root().0;
        let compute_root = self.compute_tree.master_tree.root().0;
        [lt_root, compute_root]
    }
}

#[derive(Debug, Clone)]
pub struct BrDecomposed {
    num: Vec<Fr>,
    den: Vec<Fr>,
    num_limbs: usize,
    power_of_ten: usize,
}

/// Converts a `BigRational` into scaled, decomposed numerator and denominator arrays of field elements.
pub fn big_to_fe_rat(ratio: Br, num_decimal_limbs: usize, power_of_ten: usize) -> BrDecomposed {
    let num = ratio.numer();
    let den = ratio.denom();
    let max_len = num_decimal_limbs * power_of_ten;
    let bigger = num.max(den);
    let dig_len = bigger.to_string().len();
    let diff = max_len - dig_len;

    let scale = BigUint::from(10_u32).pow(diff as u32);
    let num_scaled = num * scale.clone();
    let den_scaled = den * scale;

    let num_decomposed = decompose_big_decimal(num_scaled, num_decimal_limbs, power_of_ten);
    let den_decomposed = decompose_big_decimal(den_scaled, num_decimal_limbs, power_of_ten);

    BrDecomposed {
        num: num_decomposed,
        den: den_decomposed,
        num_limbs: num_decimal_limbs,
        power_of_ten,
    }
}

/// Returns `limbs` by decomposing [`BigUint`].
pub fn decompose_big_decimal(mut e: BigUint, num_limbs: usize, power_of_ten: usize) -> Vec<Fr> {
    let scale = BigUint::from(10usize).pow(power_of_ten as u32);
    let mut limbs = Vec::new();
    for _ in 0..num_limbs {
        let (new_e, rem) = e.div_mod_floor(&scale);
        e = new_e;
        limbs.push(big_to_fr(rem));
    }
    limbs
}

/// Returns `limbs` by decomposing [`BigUint`].
pub fn compose_big_decimal_f(mut limbs: Vec<Fr>, num_limbs: usize, power_of_ten: usize) -> Fr {
    let scale = Fr::from_u128(10).pow([power_of_ten as u64]);
    limbs.reverse();
    let mut val = limbs[0];
    for i in 1..num_limbs {
        val *= scale;
        val += limbs[i];
    }
    val
}

/// Returns modulus of the [`FieldExt`] as [`BigUint`].
pub fn modulus() -> BigUint {
    BigUint::from_str_radix(&Fr::MODULUS[2..], 16).unwrap()
}

/// Returns [`FieldExt`] for the given [`BigUint`].
pub fn big_to_fr(e: BigUint) -> Fr {
    let modulus = modulus();
    let e = e % modulus;
    Fr::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}
