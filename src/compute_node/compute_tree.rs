use std::collections::HashMap;

use halo2curves::bn256::Fr;

use crate::{
    merkle_tree::{Path, SparseMerkleTree},
    Challenge, Hasher,
};

pub struct ComputeTreeMembershipProof {
    pub(crate) master_tree_path: Path<Hasher>,
    pub(crate) sub_tree_path: Path<Hasher>,
}

impl ComputeTreeMembershipProof {
    pub fn verify(&self) -> bool {
        let is_sub_root_correct = self.sub_tree_path.verify_mul();
        let is_master_root_correct = self.master_tree_path.verify();
        // let (leaf_value, _) = self.master_tree_path.value();
        // let (root_value, _) = self.sub_tree_path.root();
        // let is_link_correct = leaf_value == root_value;
        is_master_root_correct && is_sub_root_correct // && is_link_correct
    }
}

pub struct ComputeTree {
    pub(crate) master_tree: SparseMerkleTree<Hasher>,
    pub(crate) sub_trees: HashMap<Fr, SparseMerkleTree<Hasher>>,
}

impl ComputeTree {
    pub fn new(peers: Vec<Fr>, lt: Vec<Vec<Fr>>, res: Vec<Fr>) -> Self {
        let mut master_c_tree_leaves = Vec::new();
        let mut sub_trees = HashMap::new();
        for i in 0..peers.len() {
            let mut sub_tree_leaves = Vec::new();
            for j in 0..peers.len() {
                let gt = res[j];
                let sum: Fr = lt[j].iter().sum();
                let lt_norm = lt[j][i] * sum.invert().unwrap();
                if j == 0 && i == 1 {
                    println!("{:?} {:?} {:?}", lt[j][i], sum, lt_norm);
                }
                sub_tree_leaves.push((lt_norm, gt));
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

    pub fn find_membership_proof(&self, challenge: Challenge) -> ComputeTreeMembershipProof {
        let sub_tree = self.sub_trees.get(&challenge.to).unwrap();
        let sub_tree_path = sub_tree.find_path(challenge.from);
        let master_tree_path = self.master_tree.find_path(challenge.to);
        ComputeTreeMembershipProof {
            master_tree_path,
            sub_tree_path,
        }
    }
}
