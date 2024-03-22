use std::collections::HashMap;

use crate::{
    merkle_tree::{Path, SparseMerkleTree},
    Challenge, Hasher, LinearCombination,
};
use halo2curves::{bn256::Fr, ff::PrimeField};

// TODO: Rename to appropriate name
pub struct ComputeTreeFraudProof {
    // Peers Global Trust path
    peer_path: ComputeTreeMembershipProof,
    // Neighbours Global Trust path
    neighbour_path: Path<Hasher>,
    // Neighbours local trust path
    lt_tree_path: LocalTrustTreeMembershipProof,
}

impl ComputeTreeFraudProof {
    pub fn verify(&self, data: [Fr; 2], challenge: Challenge) -> bool {
        let [local_trust_tree_root, compute_tree_root] = data;
        let is_peer_path_correct = self.peer_path.verify();
        let is_neighbour_lt_path_correct = self.lt_tree_path.verify();
        let is_neighbour_path_correct = self.neighbour_path.verify();
        let is_neighbour_root_correct =
            self.neighbour_path.path_arr[Fr::NUM_BITS as usize - 1][0] == compute_tree_root;
        let is_lt_path_correct = self.lt_tree_path.master_tree_path.path_arr
            [Fr::NUM_BITS as usize - 1][0]
            == local_trust_tree_root;
        let is_peer_root_correct = self.peer_path.master_tree_path.path_arr
            [Fr::NUM_BITS as usize - 1][0]
            == compute_tree_root;

        let is_neighbour_index_correct = self.neighbour_path.index == challenge.from;
        let is_neighbour_local_trust_correct =
            self.lt_tree_path.sub_tree_path.index == challenge.from;
        let is_peer_local_trust_correct = self.lt_tree_path.master_tree_path.index == challenge.to;
        let is_peer_global_trust_term_correct =
            self.peer_path.sub_tree_path.index == challenge.from;
        let is_peer_global_trust_correct = self.peer_path.master_tree_path.index == challenge.to;

        is_peer_path_correct
            && is_neighbour_lt_path_correct
            && is_neighbour_path_correct
            && is_neighbour_root_correct
            && is_lt_path_correct
            && is_peer_root_correct
            && is_neighbour_index_correct
            && is_neighbour_local_trust_correct
            && is_peer_local_trust_correct
            && is_peer_global_trust_term_correct
            && is_peer_global_trust_correct
    }
}

pub struct ComputeNode {
    compute_tree: ComputeTree,
    local_trust_tree: LocalTrustTree,
}

impl ComputeNode {
    pub fn new(peers: Vec<Fr>, lt: Vec<Vec<Fr>>, res: Vec<Fr>) -> Self {
        let local_trust_tree = LocalTrustTree::new(peers.clone(), lt.clone());
        let compute_tree = ComputeTree::new(peers, lt, res);
        Self {
            compute_tree,
            local_trust_tree,
        }
    }

    pub fn compute_fraud_proof(&self, challenge: Challenge) -> ComputeTreeFraudProof {
        let peer_path = self.compute_tree.find_membership_proof(challenge.clone());
        let lt_tree_path = self
            .local_trust_tree
            .find_membership_proof(challenge.clone());
        let neighbour_path = self.compute_tree.master_tree.find_path(challenge.from);
        ComputeTreeFraudProof {
            peer_path,
            lt_tree_path,
            neighbour_path,
        }
    }

    pub fn sc_data(&self) -> [Fr; 2] {
        let lt_root = self.local_trust_tree.master_tree.root().0;
        let compute_root = self.compute_tree.master_tree.root().0;
        [lt_root, compute_root]
    }
}

struct ComputeTreeMembershipProof {
    master_tree_path: Path<Hasher>,
    sub_tree_path: Path<Hasher>,
}

impl ComputeTreeMembershipProof {
    pub fn verify(&self) -> bool {
        let is_root_correct = self.master_tree_path.verify() & self.sub_tree_path.verify();
        let is_link_correct = self.master_tree_path.value() == self.sub_tree_path.root();
        is_root_correct && is_link_correct
    }
}

struct ComputeTree {
    master_tree: SparseMerkleTree<Hasher>,
    sub_trees: HashMap<Fr, SparseMerkleTree<Hasher>>,
}

impl ComputeTree {
    pub fn new(peers: Vec<Fr>, lt: Vec<Vec<Fr>>, res: Vec<Fr>) -> Self {
        let mut master_c_tree_leaves = Vec::new();
        let mut sub_trees = HashMap::new();
        for i in 0..peers.len() {
            let mut sub_tree_leaves = Vec::new();
            for j in 0..peers.len() {
                let gt = res[j];
                let lt = lt[j][i];
                sub_tree_leaves.push((gt, lt));
            }
            let sub_tree = Self::construct_sub_tree(peers.clone(), sub_tree_leaves);
            let (root_hash, _) = sub_tree.root();
            master_c_tree_leaves.push((root_hash, res[i]));
            sub_trees.insert(peers[i], sub_tree);
        }

        let master_tree = Self::construct_master_tree(peers, master_c_tree_leaves);

        Self {
            master_tree,
            sub_trees,
        }
    }

    pub fn construct_sub_tree(indices: Vec<Fr>, leaves: Vec<(Fr, Fr)>) -> SparseMerkleTree<Hasher> {
        let mut smt = SparseMerkleTree::new();

        leaves
            .iter()
            .zip(indices)
            .for_each(|(&(local_trust, global_trust), index)| {
                smt.insert_leaf_mul(index, (local_trust, global_trust));
            });

        smt
    }

    pub fn construct_master_tree(
        indices: Vec<Fr>,
        leaves: Vec<(Fr, Fr)>,
    ) -> SparseMerkleTree<Hasher> {
        let mut smt = SparseMerkleTree::new();

        leaves
            .iter()
            .zip(indices)
            .for_each(|(&(sub_root_hash, score), index)| {
                smt.insert_leaf(index, (sub_root_hash, score));
            });

        smt
    }

    fn find_membership_proof(&self, challenge: Challenge) -> ComputeTreeMembershipProof {
        let sub_tree = self.sub_trees.get(&challenge.to).unwrap();
        let sub_tree_path = sub_tree.find_path(challenge.from);
        let master_tree_path = self.master_tree.find_path(challenge.to);
        ComputeTreeMembershipProof {
            master_tree_path,
            sub_tree_path,
        }
    }
}

struct LocalTrustTreeMembershipProof {
    master_tree_path: Path<Hasher>,
    sub_tree_path: Path<Hasher>,
}

impl LocalTrustTreeMembershipProof {
    pub fn verify(&self) -> bool {
        let is_root_correct = self.master_tree_path.verify() & self.sub_tree_path.verify();
        let is_link_correct = self.master_tree_path.value() == self.sub_tree_path.root();
        is_root_correct && is_link_correct
    }
}

struct LocalTrustTree {
    master_tree: SparseMerkleTree<Hasher>,
    sub_trees: HashMap<Fr, SparseMerkleTree<Hasher>>,
}

impl LocalTrustTree {
    pub fn new(peers: Vec<Fr>, lt: Vec<Vec<Fr>>) -> Self {
        let mut master_lt_tree_leaves = Vec::new();
        let mut sub_tree_map = HashMap::new();
        for i in 0..peers.len() {
            let from = peers[i];

            let mut lcs = Vec::new();
            for j in 0..peers.len() {
                let to = peers[j];
                let lt = lt[i][j];
                let lc = LinearCombination {
                    from,
                    to,
                    sum_of_weights: lt,
                };
                lcs.push(lc);
            }
            let subtree = Self::construct_sub_tree(from, &lcs);
            let (root_hash, total_score) = subtree.root();
            master_lt_tree_leaves.push((root_hash, total_score));
            sub_tree_map.insert(from, subtree);
        }

        let master_lt_tree = Self::construct_master_tree(peers.clone(), master_lt_tree_leaves);
        Self {
            master_tree: master_lt_tree,
            sub_trees: sub_tree_map,
        }
    }

    pub fn construct_sub_tree(from: Fr, lcs: &Vec<LinearCombination>) -> SparseMerkleTree<Hasher> {
        let mut smt = SparseMerkleTree::new();

        lcs.iter().for_each(|x| {
            assert!(x.from == from);
            smt.insert_leaf(x.to, (x.to, x.sum_of_weights));
        });

        smt
    }

    pub fn construct_master_tree(
        indices: Vec<Fr>,
        leaves: Vec<(Fr, Fr)>,
    ) -> SparseMerkleTree<Hasher> {
        let mut smt = SparseMerkleTree::new();

        leaves
            .iter()
            .zip(indices)
            .for_each(|(&(sub_root_hash, total_lt), index)| {
                smt.insert_leaf(index, (sub_root_hash, total_lt));
            });

        smt
    }

    fn find_membership_proof(&self, challenge: Challenge) -> LocalTrustTreeMembershipProof {
        let sub_tree = self.sub_trees.get(&challenge.from).unwrap();
        let sub_tree_path = sub_tree.find_path(challenge.to);
        let master_tree_path = self.master_tree.find_path(challenge.from);
        LocalTrustTreeMembershipProof {
            master_tree_path,
            sub_tree_path,
        }
    }
}
