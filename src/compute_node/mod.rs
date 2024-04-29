use std::collections::HashMap;

use crate::params::poseidon_bn254_5x5::Params;
use crate::poseidon::{Hasher as HTrait, Poseidon};
use crate::systems::optimistic::{Challenge, ConsistencyChallenge};
use crate::{algo::et_rational::Br, merkle_tree::Path};
use halo2curves::ff::Field;
use halo2curves::{bn256::Fr, ff::PrimeField};
use num_bigint::BigUint;
use num_integer::Integer;
use num_rational::Ratio;
use num_traits::Num;

use self::am_tree::AdjacencyMatrixTree;
use self::{
    am_tree::AmTreeMembershipProof,
    compute_tree::{ComputeTree, ComputeTreeMembershipProof},
};

mod am_tree;
mod compute_tree;

type Hasher = Poseidon<5, Params>;

pub struct ConsistencyProof {
    // Peers Global Trust path
    target1_path: ComputeTreeMembershipProof,
    target2_path: ComputeTreeMembershipProof,
}

impl ConsistencyProof {
    pub fn verify(&self, data: [Fr; 2], challenge: ConsistencyChallenge) -> bool {
        self.verify_against_data(data)
            && self.verify_against_challenge(challenge)
            && self.check_score_consistency()
    }

    pub fn check_score_consistency(&self) -> bool {
        let (_, score1) = self.target1_path.sub_tree_path.value();
        let (_, score2) = self.target2_path.sub_tree_path.value();
        let is_score_same = score1 == score2;

        is_score_same
    }

    pub fn verify_against_data(&self, data: [Fr; 2]) -> bool {
        let [_, compute_root] = data;

        let is_valid1 = self.target1_path.verify();
        let is_valid2 = self.target2_path.verify();

        let (target1_root, _) = self.target1_path.master_tree_path.root();
        let (target2_root, _) = self.target2_path.master_tree_path.root();

        let is_target1_root_correct = target1_root == compute_root;
        let is_target2_root_correct = target2_root == compute_root;

        is_valid1 && is_valid2 && is_target1_root_correct && is_target2_root_correct
    }

    pub fn verify_against_challenge(&self, challenge: ConsistencyChallenge) -> bool {
        let is_origin_same = challenge.target1.from == challenge.target2.from;
        let is_target_different = challenge.target1.to != challenge.target2.to;
        let is_from1_correct = self.target1_path.sub_tree_path.index == challenge.target1.from;
        let is_from2_correct = self.target2_path.sub_tree_path.index == challenge.target2.from;
        let is_to1_correct = self.target1_path.master_tree_path.index == challenge.target1.to;
        let is_to2_correct = self.target2_path.master_tree_path.index == challenge.target2.to;

        is_origin_same
            && is_target_different
            && is_from1_correct
            && is_from2_correct
            && is_to1_correct
            && is_to2_correct
    }
}

pub struct EtComputeTreeValidityProof {
    // Peers Global Trust path
    peer_path: ComputeTreeMembershipProof,
    // Neighbours Global Trust path
    neighbour_path: Path<Hasher>,
    // Neighbours local trust path
    lt_tree_path: AmTreeMembershipProof,
    // Claimed score
    c: BrDecomposed,
    // Calculated score
    c_prime: BrDecomposed,
}

impl EtComputeTreeValidityProof {
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

        // Then we check the correctness of local trust score
        let is_lt_correct = (lt_score * sum.invert().unwrap()) == lt;

        // First, we compose the decomposed rational numbers
        let composed_c_num = compose_big_decimal_f(self.c.num.clone(), self.c.power_of_ten);
        let composed_c_den = compose_big_decimal_f(self.c.den.clone(), self.c.power_of_ten);

        let composed_c_prime_num =
            compose_big_decimal_f(self.c_prime.num.clone(), self.c_prime.power_of_ten);
        let composed_c_prime_den =
            compose_big_decimal_f(self.c_prime.den.clone(), self.c_prime.power_of_ten);

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

pub struct EtComputeNode {
    compute_tree: ComputeTree,
    local_trust_tree: AdjacencyMatrixTree,
    peers: Vec<Fr>,
    scores_br: Vec<Br>,
    scores_final_br: Vec<Br>,
}

impl EtComputeNode {
    pub fn new(
        peers: Vec<Fr>,
        lt: Vec<Vec<Fr>>,
        scores_f: Vec<Fr>,
        scores_br: Vec<Br>,
        scores_final_br: Vec<Br>,
    ) -> Self {
        let local_trust_tree = AdjacencyMatrixTree::new(peers.clone(), lt.clone());
        let compute_tree = Self::construct_compute_tree(peers.clone(), lt, scores_f);
        Self {
            compute_tree,
            local_trust_tree,
            peers,
            scores_br,
            scores_final_br,
        }
    }

    pub fn construct_compute_tree(
        peers: Vec<Fr>,
        lt: Vec<Vec<Fr>>,
        scores_f: Vec<Fr>,
    ) -> ComputeTree {
        let mut lt_sum: Vec<Fr> = Vec::new();
        for i in 0..peers.len() {
            lt_sum.push(lt[i].iter().sum());
        }
        let mut master_c_tree_leaves = Vec::new();
        let mut sub_trees = HashMap::new();
        for i in 0..peers.len() {
            let mut sub_tree_leaves = Vec::new();
            for j in 0..peers.len() {
                let gt = scores_f[j];
                let lt_norm = lt[j][i] * lt_sum[j].invert().unwrap();
                sub_tree_leaves.push((lt_norm, gt));
            }
            let sub_tree = ComputeTree::construct_sub_tree(peers.clone(), sub_tree_leaves);
            let (root_hash, score) = sub_tree.root();

            sub_trees.insert(peers[i], sub_tree);
            master_c_tree_leaves.push((root_hash, score));
        }

        let master_tree = ComputeTree::construct_master_tree(peers, master_c_tree_leaves);
        let compute_tree = ComputeTree::new(sub_trees, master_tree);
        compute_tree
    }

    pub fn compute_consistency_proof(&self, challenge: ConsistencyChallenge) -> ConsistencyProof {
        let target1_path = self.compute_tree.find_membership_proof(challenge.target1);
        let target2_path = self.compute_tree.find_membership_proof(challenge.target2);
        ConsistencyProof {
            target1_path,
            target2_path,
        }
    }

    pub fn compute_validity_proof(
        &self,
        challenge: Challenge,
        precision: usize,
    ) -> EtComputeTreeValidityProof {
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

        EtComputeTreeValidityProof {
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

pub struct HaComputeTreeValidityProof {
    // Peers Global Trust path
    peer_path: ComputeTreeMembershipProof,
    // Neighbours Global Score path
    neighbour_path: Path<Hasher>,
    // Neighbours adjacency tree path
    am_tree_path: AmTreeMembershipProof,
    // Are we using an entry from transposed AM Matrix
    is_transposed_am: bool,
    // Neighbour score pre-image
    neighbour_score_preimage: [Fr; 4],
    // Peer score pre-image
    peer_score_preimage: [Fr; 4],
    // Claimed score
    c: BrDecomposed,
    // Calculated score
    approx_c_prime: BrDecomposed,
    // R calculated from approximate square root
    approx_sum: BrDecomposed,
    // Approximate sum sqrt
    approx_sum_sqrt: BrDecomposed,
    // Real R used in the tree
    real_sum: BrDecomposed,
}

impl HaComputeTreeValidityProof {
    pub fn verify(&self, data: [Fr; 3], challenge: Challenge) -> bool {
        let ac = self.check_against_challenge(challenge);
        let ad = self.check_against_data(data);
        let sc = self.check_score_correctness();
        ac && ad && sc
    }

    pub fn check_score_correctness(&self) -> bool {
        let (_, am_score) = self.am_tree_path.sub_tree_path.value();
        let (edge, c) = self.peer_path.sub_tree_path.value();
        let (_, real_r) = self.neighbour_path.root();
        let [_, _, c_prime, _] = self.neighbour_score_preimage;

        let is_am_score_correct = (am_score == Fr::one()) || (am_score == Fr::zero());
        let is_edge_correct = edge == am_score;

        let composed_approx_sum = lcm_compose(self.approx_sum.clone());

        let is_approx_sum_equal = approx_equal(
            self.real_sum.clone(),
            real_r,
            self.approx_sum.clone(),
            composed_approx_sum,
        );

        // Check if the given sum sqrt is correct
        let composed_approx_sum_sqrt = lcm_compose(self.approx_sum_sqrt.clone());
        let is_approx_sqrt_correct =
            (composed_approx_sum_sqrt * composed_approx_sum_sqrt) == composed_approx_sum;

        let approx_c_prime = c_prime * composed_approx_sum_sqrt.invert().unwrap();

        let is_approx_c_prime_equal = approx_equal(
            self.c.clone(),
            c,
            self.approx_c_prime.clone(),
            approx_c_prime,
        );

        is_am_score_correct
            && is_edge_correct
            && is_approx_sum_equal
            && is_approx_sqrt_correct
            && is_approx_c_prime_equal
    }

    pub fn check_against_data(&self, data: [Fr; 3]) -> bool {
        let [local_trust_tree_root, hubs_compute_tree_root, auth_compute_tree_root] = data;

        // Check if merkle paths are correct
        let is_peer_path_correct = self
            .peer_path
            .verify_with_preimage(self.peer_score_preimage);
        let is_neighbour_lt_path_correct = self.am_tree_path.verify();
        let is_neighbour_path_correct = self.neighbour_path.verify();

        let (peer_root, _) = self.peer_path.master_tree_path.root();
        let (lt_root, _) = self.am_tree_path.master_tree_path.root();
        let (n_root, _) = self.neighbour_path.root();
        let n_leaf = self.neighbour_path.value();

        let [sub_root_hash, a, b, c] = self.neighbour_score_preimage;
        let val = a + b * c;
        let hash = Hasher::new([sub_root_hash, a, b, c, Fr::zero()]).finalize();

        // Check if merkle tree roots are matching the commited roots
        let is_peer_root_correct =
            (peer_root == hubs_compute_tree_root) || (peer_root == auth_compute_tree_root);
        let is_lt_root_correct = lt_root == local_trust_tree_root;
        let is_neighbour_root_correct =
            (n_root == hubs_compute_tree_root) || (n_root == auth_compute_tree_root);
        let is_compute_root_different = peer_root != n_root;
        let is_neighbour_leaf_correct = n_leaf == (hash, val);

        is_peer_path_correct
            && is_neighbour_lt_path_correct
            && is_neighbour_path_correct
            && is_neighbour_root_correct
            && is_lt_root_correct
            && is_peer_root_correct
            && is_compute_root_different
            && is_neighbour_leaf_correct
    }

    pub fn check_against_challenge(&self, challenge: Challenge) -> bool {
        let (is_peer_lt_correct, is_neighbour_lt_correct) = if self.is_transposed_am {
            (
                self.am_tree_path.master_tree_path.index == challenge.to,
                self.am_tree_path.sub_tree_path.index == challenge.from,
            )
        } else {
            (
                self.am_tree_path.master_tree_path.index == challenge.from,
                self.am_tree_path.sub_tree_path.index == challenge.to,
            )
        };
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

pub struct HaComputeNode {
    hubs_compute_tree: ComputeTree,
    auth_compute_tree: ComputeTree,
    ajacency_matrix_tree: AdjacencyMatrixTree,
    peers: Vec<Fr>,
    scores_hubs_br: Vec<Br>,
    scores_auth_br: Vec<Br>,
    scores_hubs_final_unnormalised_br: Vec<Br>,
    scores_auth_final_unnormalised_br: Vec<Br>,
    hubs_compute_tree_preimages: Vec<[Fr; 4]>,
    auth_compute_tree_preimages: Vec<[Fr; 4]>,
}

impl HaComputeNode {
    pub fn new(
        peers: Vec<Fr>,
        am: Vec<Vec<Fr>>,
        am_t: Vec<Vec<Fr>>,
        scores_hubs_f: Vec<Fr>,
        scores_auth_f: Vec<Fr>,
        scores_hubs_br: Vec<Br>,
        scores_auth_br: Vec<Br>,
        scores_hubs_final_unnormalised_br: Vec<Br>,
        scores_auth_final_unnormalised_br: Vec<Br>,
    ) -> Self {
        let ajacency_matrix_tree = AdjacencyMatrixTree::new(peers.clone(), am.clone());
        let (auth_compute_tree, auth_compute_tree_preimages) =
            Self::construct_compute_tree(peers.clone(), am_t, scores_hubs_f.clone());
        let (hubs_compute_tree, hubs_compute_tree_preimages) =
            Self::construct_compute_tree(peers.clone(), am, scores_auth_f.clone());
        Self {
            hubs_compute_tree,
            auth_compute_tree,
            ajacency_matrix_tree,
            peers,
            scores_hubs_br,
            scores_auth_br,
            scores_hubs_final_unnormalised_br,
            scores_auth_final_unnormalised_br,
            hubs_compute_tree_preimages,
            auth_compute_tree_preimages,
        }
    }

    pub fn construct_compute_tree(
        peers: Vec<Fr>,
        am: Vec<Vec<Fr>>,
        scores_f: Vec<Fr>,
    ) -> (ComputeTree, Vec<[Fr; 4]>) {
        let mut lt_sum: Vec<Fr> = Vec::new();
        for i in 0..peers.len() {
            lt_sum.push(am[i].iter().sum());
        }
        let mut master_c_tree_leaves = Vec::new();
        let mut sub_trees = HashMap::new();
        let mut pre_images = Vec::new();
        for i in 0..peers.len() {
            let mut sub_tree_leaves = Vec::new();
            for j in 0..peers.len() {
                sub_tree_leaves.push((am[j][i], scores_f[j]));
            }
            let sub_tree = ComputeTree::construct_sub_tree(peers.clone(), sub_tree_leaves);
            let (root_hash, score) = sub_tree.root();
            sub_trees.insert(peers[i], sub_tree);

            let pre_image = [root_hash, Fr::zero(), score, score];
            let (leaf, val) = ComputeTree::pre_process_leaf(pre_image);
            master_c_tree_leaves.push((leaf, val));
            pre_images.push(pre_image);
        }

        let master_tree = ComputeTree::construct_master_tree(peers, master_c_tree_leaves);
        let compute_tree = ComputeTree::new(sub_trees, master_tree);
        (compute_tree, pre_images)
    }

    pub fn compute_hubs_validity_proof(
        &self,
        challenge: Challenge,
        c_precision: usize,
        sqrt_precision: usize,
    ) -> HaComputeTreeValidityProof {
        // Construct merkle path for AM Tree and Compute Tree
        let peer_path = self
            .hubs_compute_tree
            .find_membership_proof(challenge.clone());
        let am_tree_path = self
            .ajacency_matrix_tree
            .find_membership_proof(challenge.clone());
        let neighbour_path = self.auth_compute_tree.master_tree.find_path(challenge.from);

        let n_index = self
            .peers
            .iter()
            .position(|&x| challenge.from == x)
            .unwrap();
        let p_index = self.peers.iter().position(|&x| challenge.to == x).unwrap();
        let neighbour_score_preimage = self.auth_compute_tree_preimages[n_index];
        let peer_score_preimage = self.hubs_compute_tree_preimages[p_index];

        let c_br = self.scores_auth_br[n_index].clone();
        let c_prime_br = self.scores_auth_final_unnormalised_br[n_index].clone();

        // Calculate the sum of squared scores
        let sum: Br = self
            .scores_auth_final_unnormalised_br
            .iter()
            .map(|x| x.pow(2))
            .sum::<Br>();

        // Approximate square root of the sum
        let approx_sum_sqrt_br = Br::new(sum.numer().sqrt(), sum.denom().sqrt());
        // Reconstructed sum from it's square root
        let approx_sum_br = approx_sum_sqrt_br.clone() * approx_sum_sqrt_br.clone();
        // C' or final normalised score of a peer; C' = C / sqrt(sum(C^2))
        let approx_c_prime_br = c_prime_br.clone() / approx_sum_sqrt_br.clone();
        // Find lowest common multiplier for sqrt squared and the original sum
        let (c, approx_c_prime) = lcm_decompose(c_br, approx_c_prime_br.clone(), c_precision);
        // Find lowest common multiplier for sqrt squared and the original sum
        let (approx_sum, real_sum) = lcm_decompose(approx_sum_br, sum, sqrt_precision);
        // Approximate sum sqrt decomposed
        let approx_sum_sqrt = big_to_fe_rat(
            approx_sum_sqrt_br.numer().clone(),
            approx_sum_sqrt_br.denom().clone(),
            sqrt_precision,
        );

        HaComputeTreeValidityProof {
            peer_path,
            am_tree_path,
            neighbour_path,
            is_transposed_am: false,
            neighbour_score_preimage,
            peer_score_preimage,
            c,
            approx_c_prime,
            approx_sum_sqrt,
            approx_sum,
            real_sum,
        }
    }

    pub fn compute_auth_validity_proof(
        &self,
        challenge: Challenge,
        c_precision: usize,
        sqrt_precision: usize,
    ) -> HaComputeTreeValidityProof {
        // Construct merkle path for AM Tree and Compute Tree
        let peer_path = self
            .auth_compute_tree
            .find_membership_proof(challenge.clone());
        let am_tree_path = self.ajacency_matrix_tree.find_membership_proof(Challenge {
            from: challenge.to,
            to: challenge.from,
        });
        let neighbour_path = self.hubs_compute_tree.master_tree.find_path(challenge.from);

        let n_index = self
            .peers
            .iter()
            .position(|&x| challenge.from == x)
            .unwrap();
        let p_index = self.peers.iter().position(|&x| challenge.to == x).unwrap();
        let neighbour_score_preimage = self.hubs_compute_tree_preimages[n_index];
        let peer_score_preimage = self.auth_compute_tree_preimages[p_index];

        let c_br = self.scores_hubs_br[n_index].clone();
        let c_prime_br = self.scores_hubs_final_unnormalised_br[n_index].clone();

        // Calculate the sum of squared scores
        let sum: Br = self
            .scores_hubs_final_unnormalised_br
            .iter()
            .map(|x| x.pow(2))
            .sum::<Br>();

        // Approximate square root of the sum
        let approx_sum_sqrt_br = Br::new(sum.numer().sqrt(), sum.denom().sqrt());
        // Reconstructed sum from it's square root
        let approx_sum_br = approx_sum_sqrt_br.clone() * approx_sum_sqrt_br.clone();
        // C' or final normalised score of a peer; C' = C / sqrt(sum(C^2))
        let approx_c_prime_br = c_prime_br.clone() / approx_sum_sqrt_br.clone();
        // Find lowest common multiplier for sqrt squared and the original sum
        let (c, approx_c_prime) = lcm_decompose(c_br, approx_c_prime_br.clone(), c_precision);
        // Find lowest common multiplier for sqrt squared and the original sum
        let (approx_sum, real_sum) = lcm_decompose(approx_sum_br, sum, sqrt_precision);
        // Approximate sum sqrt decomposed
        let approx_sum_sqrt = big_to_fe_rat(
            approx_sum_sqrt_br.numer().clone(),
            approx_sum_sqrt_br.denom().clone(),
            sqrt_precision,
        );

        HaComputeTreeValidityProof {
            peer_path,
            am_tree_path,
            neighbour_path,
            is_transposed_am: true,
            neighbour_score_preimage,
            peer_score_preimage,
            c,
            approx_c_prime,
            approx_sum_sqrt,
            approx_sum,
            real_sum,
        }
    }

    pub fn sc_data(&self) -> [Fr; 3] {
        let am_root = self.ajacency_matrix_tree.master_tree.root().0;
        let hubs_compute_root = self.hubs_compute_tree.master_tree.root().0;
        let auth_compute_root = self.auth_compute_tree.master_tree.root().0;
        [am_root, hubs_compute_root, auth_compute_root]
    }
}

#[derive(Debug, Clone)]
pub struct BrDecomposed {
    pub(crate) num: Vec<Fr>,
    pub(crate) den: Vec<Fr>,
    num_limbs: usize,
    power_of_ten: usize,
}

fn approx_equal(p: BrDecomposed, p_f: Fr, q: BrDecomposed, q_f: Fr) -> bool {
    let p_composed = lcm_compose(p.clone());
    let q_composed = lcm_compose(q.clone());
    let rounded_c = p.den.last().unwrap() * p.num.last().unwrap();
    let rounded_c_prime = q.den.last().unwrap() * q.num.last().unwrap();

    let is_precision_equal = p.power_of_ten == q.power_of_ten;
    let is_p_correct = p_composed == p_f;
    let is_q_correct = q_composed == q_f;
    let is_rounded_p_q_equal = rounded_c == rounded_c_prime;

    is_precision_equal && is_p_correct && is_q_correct && is_rounded_p_q_equal
}

fn lcm_compose(n: BrDecomposed) -> Fr {
    let composed_num = compose_big_decimal_f(n.num.clone(), n.power_of_ten);
    let composed_den = compose_big_decimal_f(n.den.clone(), n.power_of_ten);
    let composed = composed_num * composed_den.invert().unwrap();
    composed
}

fn lcm_decompose(br_a: Br, br_b: Br, precision: usize) -> (BrDecomposed, BrDecomposed) {
    let c_br = br_a.clone();
    let c_prime_br = br_b.clone();
    let lcm = c_br.denom().lcm(&c_prime_br.denom());
    let c_numer = c_br.numer().clone() * (lcm.clone() / c_br.denom().clone());
    let c_prime_numer = c_prime_br.numer() * (lcm.clone() / c_prime_br.denom());

    // Decompose the numerators into limbs with each limb having 'precision' amount of digits
    let c = big_to_fe_rat(c_numer, lcm.clone(), precision);
    let c_prime = big_to_fe_rat(c_prime_numer, lcm, precision);

    (c, c_prime)
}

/// Converts a `BigRational` into scaled, decomposed numerator and denominator arrays of field elements.
pub fn big_to_fe_rat(num: BigUint, den: BigUint, precision: usize) -> BrDecomposed {
    let num_den_diff = ((num.to_string().len() as i32) - (den.to_string().len() as i32)).abs();
    assert!(precision >= (num_den_diff * 2) as usize);

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
pub fn compose_big_decimal_f(mut limbs: Vec<Fr>, power_of_ten: usize) -> Fr {
    let scale = Fr::from_u128(10).pow([power_of_ten as u64]);
    limbs.reverse();
    let mut val = limbs[0];
    for i in 1..limbs.len() {
        val *= scale;
        val += limbs[i];
    }
    val
}

/// Returns modulus of the [`FieldExt`] as [`BigUint`].
pub fn modulus() -> BigUint {
    BigUint::from_str_radix(&Fr::MODULUS[2..], 16).unwrap()
}

pub fn ratio_to_fr(r: Ratio<BigUint>) -> Fr {
    let num = big_to_fr(r.numer().clone());
    let den = big_to_fr(r.denom().clone());
    num * den.invert().unwrap()
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
    use crate::{
        algo::et_field,
        compute_node::{am_tree::AdjacencyMatrixTree, EtComputeNode},
        systems::optimistic::Challenge,
    };
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
        let res = et_field::positive_run::<30>(lt, pre_trust);

        let compute_node = EtComputeNode::new(
            peers.to_vec(),
            lt.map(|lt_arr| lt_arr.to_vec()).to_vec(),
            res.to_vec(),
            Vec::new(),
            Vec::new(),
        );
        let lt_tree =
            AdjacencyMatrixTree::new(peers.to_vec(), lt.map(|lt_arr| lt_arr.to_vec()).to_vec());

        let challenge = Challenge {
            from: peers[0],
            to: peers[1],
        };
        let cp_proof = compute_node
            .compute_tree
            .find_membership_proof(challenge.clone());
        let lt_proof = lt_tree.find_membership_proof(challenge);

        let (lt_cp, _) = cp_proof.sub_tree_path.value();
        let (_, lt) = lt_proof.sub_tree_path.value();
        let (_, sum) = lt_proof.sub_tree_path.root();

        assert!((lt * sum.invert().unwrap()) == lt_cp);
        assert!(cp_proof.verify());
        assert!(lt_proof.verify());
    }
}
