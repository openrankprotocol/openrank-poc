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

pub struct ComputeTreeValidityProof {
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

impl ComputeTreeValidityProof {
    pub fn verify(&self, data: [Fr; 2], challenge: Challenge) -> bool {
        self.check_against_challenge(challenge)
            && self.check_against_data(data)
            && self.check_score_correctness()
    }

    // Checking if the score has converged for a peer specified in Challenge
    pub fn check_score_correctness(&self) -> bool {
        let (_, lt_score) = self.lt_tree_path.sub_tree_path.value();
        let (_, sum) = self.lt_tree_path.sub_tree_path.root();
        let (lt, gt) = self.peer_path.sub_tree_path.value();
        let (_, gt_prime) = self.neighbour_path.value();

        // First, we compose the decomposed rational numbers
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

        // Then we check the correctness of local trust score
        let is_lt_correct = (lt_score * sum.invert().unwrap()) == lt;

        // Then we check the equality with the field elements corresponding to each score separately
        let composed_c = composed_c_num * composed_c_den.invert().unwrap();
        let composed_c_prime = composed_c_prime_num * composed_c_prime_den.invert().unwrap();
        let is_c_equal = composed_c == gt;
        let is_c_prime_equal = composed_c_prime == gt_prime;

        // Then we check the upper most chunks equality
        // This means that we are rounding the floating point number to just a few most significat digits
        let rounded_c = self.c.den.last().unwrap() * self.c.num.last().unwrap();
        let rounded_c_prime = self.c_prime.den.last().unwrap() * self.c_prime.num.last().unwrap();
        let is_rounded_equal = rounded_c == rounded_c_prime;

        is_lt_correct && is_c_equal && is_c_prime_equal && is_rounded_equal
    }

    // Checking if the proof merkle paths and root are correct
    pub fn check_against_data(&self, data: [Fr; 2]) -> bool {
        let [local_trust_tree_root, compute_tree_root] = data;

        // Check if merkle paths are correct
        let is_peer_path_correct = self.peer_path.verify();
        let is_neighbour_lt_path_correct = self.lt_tree_path.verify();
        let is_neighbour_path_correct = self.neighbour_path.verify();

        let (peer_root, _) = self.peer_path.master_tree_path.root();
        let (lt_root, _) = self.lt_tree_path.master_tree_path.root();
        let (n_root, _) = self.neighbour_path.root();

        // Check if merkle tree roots are matching the commited roots
        let is_peer_root_correct = peer_root == compute_tree_root;
        let is_lt_root_correct = lt_root == local_trust_tree_root;
        let is_neighbour_root_correct = n_root == compute_tree_root;

        is_peer_path_correct
            && is_neighbour_lt_path_correct
            && is_neighbour_path_correct
            && is_neighbour_root_correct
            && is_lt_root_correct
            && is_peer_root_correct
    }

    // Check if the proof path indices are matching the challenge
    pub fn check_against_challenge(&self, challenge: Challenge) -> bool {
        let is_peer_lt_correct = self.lt_tree_path.master_tree_path.index == challenge.from;
        let is_neighbour_lt_correct = self.lt_tree_path.sub_tree_path.index == challenge.to;
        let is_peer_gt_term_correct = self.peer_path.sub_tree_path.index == challenge.from;
        let is_peer_gt_correct = self.peer_path.master_tree_path.index == challenge.to;
        let is_neighbour_index_correct = self.neighbour_path.index == challenge.from;

        is_peer_lt_correct
            && is_neighbour_lt_correct
            && is_peer_gt_term_correct
            && is_peer_gt_correct
            && is_neighbour_index_correct
    }
}

pub struct ComputeNode {
    compute_tree: ComputeTree,
    local_trust_tree: LocalTrustTree,
    peers: Vec<Fr>,
    scores_br: Vec<Br>,
    scores_final_br: Vec<Br>,
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
        let compute_tree = ComputeTree::new(peers.clone(), lt, scores_f.clone());
        Self {
            compute_tree,
            local_trust_tree,
            peers,
            scores_br,
            scores_final_br,
        }
    }

    pub fn compute_validity_proof(
        &self,
        challenge: Challenge,
        precision: usize,
    ) -> ComputeTreeValidityProof {
        // Construct merkle path for LT Tree and Compute Tree
        let peer_path = self.compute_tree.find_membership_proof(challenge.clone());
        let lt_tree_path = self
            .local_trust_tree
            .find_membership_proof(challenge.clone());
        let neighbour_path = self.compute_tree.master_tree.find_path(challenge.from);

        let index = self
            .peers
            .iter()
            .position(|&x| challenge.from == x)
            .unwrap();

        // Find lowest common multiplier for 2 scores (rational numbers)
        // To find the common grond needed for comparison
        let c_br = self.scores_br[index].clone();
        let c_prime_br = self.scores_final_br[index].clone();
        let lcm = c_br.denom().lcm(&c_prime_br.denom());
        let c_numer = c_br.numer().clone() * (lcm.clone() / c_br.denom().clone());
        let c_prime_numer = c_prime_br.numer() * (lcm.clone() / c_prime_br.denom());

        // Decompose the numerators into limbs with each limb having 'precision' amount of digits
        let c = big_to_fe_rat(c_numer, lcm.clone(), precision);
        let c_prime = big_to_fe_rat(c_prime_numer, lcm, precision);

        ComputeTreeValidityProof {
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
pub fn big_to_fe_rat(num: BigUint, den: BigUint, precision: usize) -> BrDecomposed {
    let num_den_diff = num.to_string().len() - den.to_string().len();
    assert!(precision >= num_den_diff * 2);

    let bigger = num.clone().max(den.clone());
    let dig_len = bigger.to_string().len();
    let num_limbs = (dig_len / precision) + 1;
    let new_len = num_limbs * precision;
    let diff = new_len - dig_len;

    let scale = BigUint::from(10_u32).pow(diff as u32);
    let num_scaled = num * scale.clone();
    let den_scaled = den * scale;

    let num_decomposed = decompose_big_decimal(num_scaled, num_limbs, precision);
    let den_decomposed = decompose_big_decimal(den_scaled, num_limbs, precision);

    BrDecomposed {
        num: num_decomposed,
        den: den_decomposed,
        num_limbs,
        power_of_ten: precision,
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

#[cfg(test)]
mod test {
    use super::ComputeTree;
    use crate::{algo::field, compute_node::lt_tree::LocalTrustTree, Challenge};
    use halo2curves::bn256::Fr;

    #[test]
    fn should_create_compute_and_lt_tree() {
        let peers = [1, 2, 3, 4, 5].map(|x| Fr::from(x));

        let lt = [
            [0, 1, 4, 1, 4],
            [0, 0, 4, 1, 4],
            [0, 1, 0, 1, 4],
            [2, 1, 5, 0, 4],
            [3, 1, 4, 1, 0],
        ]
        .map(|xs| xs.map(|x| Fr::from(x)));

        let pre_trust = [0, 0, 0, 3, 7].map(|x| Fr::from(x));
        let res = field::positive_run::<30>(lt, pre_trust);

        let compute_tree = ComputeTree::new(
            peers.to_vec(),
            lt.map(|lt_arr| lt_arr.to_vec()).to_vec(),
            res.to_vec(),
        );
        let lt_tree =
            LocalTrustTree::new(peers.to_vec(), lt.map(|lt_arr| lt_arr.to_vec()).to_vec());

        let challenge = Challenge {
            from: peers[0],
            to: peers[1],
        };
        let cp_proof = compute_tree.find_membership_proof(challenge.clone());
        let lt_proof = lt_tree.find_membership_proof(challenge);

        let (lt_cp, _) = cp_proof.sub_tree_path.value();
        let (_, lt) = lt_proof.sub_tree_path.value();
        let (_, sum) = lt_proof.sub_tree_path.root();

        assert!((lt * sum.invert().unwrap()) == lt_cp);
        assert!(cp_proof.verify());
        assert!(lt_proof.verify());
    }
}
