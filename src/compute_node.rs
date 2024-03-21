use std::collections::HashMap;

use crate::{
    algo::field,
    merkle_tree::{Path, SparseMerkleTree},
    Challenge, Hasher, LinearCombination,
};
use halo2curves::bn256::Fr;

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
    // TODO: implement verification logic
    pub fn verify(&self, data: [Fr; 2], challenge: Challenge) -> bool {
        true
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

    pub fn da_data(&self) -> [Fr; 2] {
        let lt_root = self.local_trust_tree.master_tree.root().0;
        let compute_root = self.compute_tree.master_tree.root().0;
        [lt_root, compute_root]
    }
}

struct ComputeTreeMembershipProof {
    master_tree_path: Path<Hasher>,
    sub_tree_path: Path<Hasher>,
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
