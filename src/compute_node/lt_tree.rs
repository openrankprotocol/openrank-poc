use std::collections::HashMap;

use halo2curves::bn256::Fr;

use crate::{
    merkle_tree::{Path, SparseMerkleTree},
    Challenge, Hasher, LinearCombination,
};

pub struct LocalTrustTreeMembershipProof {
    pub(crate) master_tree_path: Path<Hasher>,
    pub(crate) sub_tree_path: Path<Hasher>,
}

impl LocalTrustTreeMembershipProof {
    pub fn verify(&self) -> bool {
        let is_root_correct = self.master_tree_path.verify() && self.sub_tree_path.verify();
        let is_link_correct = self.master_tree_path.value() == self.sub_tree_path.root();
        is_root_correct && is_link_correct
    }
}

pub struct LocalTrustTree {
    pub(crate) master_tree: SparseMerkleTree<Hasher>,
    pub(crate) sub_trees: HashMap<Fr, SparseMerkleTree<Hasher>>,
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

    pub fn find_membership_proof(&self, challenge: Challenge) -> LocalTrustTreeMembershipProof {
        let sub_tree = self.sub_trees.get(&challenge.from).unwrap();
        let sub_tree_path = sub_tree.find_path(challenge.to);
        let master_tree_path = self.master_tree.find_path(challenge.from);
        LocalTrustTreeMembershipProof {
            master_tree_path,
            sub_tree_path,
        }
    }
}
