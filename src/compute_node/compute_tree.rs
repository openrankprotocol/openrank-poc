use super::Hasher;
use crate::{
    merkle_tree::{Path, SparseMerkleTree},
    poseidon::Hasher as HTrait,
    systems::optimistic::Challenge,
};
use halo2curves::bn256::Fr;
use std::collections::HashMap;

pub struct ComputeTreeMembershipProof {
    // Proof of membership for Master Tree
    pub(crate) master_tree_path: Path<Hasher>,
    // Proof of membership for Sub Tree
    pub(crate) sub_tree_path: Path<Hasher>,
}

impl ComputeTreeMembershipProof {
    pub fn verify(&self) -> bool {
        let is_sub_root_correct = self.sub_tree_path.verify_mul();
        let is_master_root_correct = self.master_tree_path.verify();
        let (leaf_value, _) = self.master_tree_path.value();
        let (root_value, _) = self.sub_tree_path.root();
        let is_link_correct = leaf_value == root_value;
        is_master_root_correct && is_sub_root_correct && is_link_correct
    }
}

pub struct ComputeTree {
    // Master Tree that has the final scores in the leaf level
    // (final scores are converged EigenTrust scores in the last iteration)
    pub(crate) master_tree: SparseMerkleTree<Hasher>,
    // Sub Trees - for each user there is a Sub Tree
    // that has the scores of the second to last iteration as the leaf level
    pub(crate) sub_trees: HashMap<Fr, SparseMerkleTree<Hasher>>,
}

impl ComputeTree {
    pub fn new(
        sub_trees: HashMap<Fr, SparseMerkleTree<Hasher>>,
        master_tree: SparseMerkleTree<Hasher>,
    ) -> Self {
        Self {
            master_tree,
            sub_trees,
        }
    }

    pub fn pre_process_leaf(vals: [Fr; 4]) -> (Fr, Fr) {
        let [prefix, a, b, c] = vals;
        let res = a + b * c;
        let inputs = [prefix, a, b, c, Fr::zero()];
        let hash = Hasher::new(inputs).finalize();
        (hash, res)
    }

    // Helper function to construct the sub tree given the vector of leaves
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

    // Helper function to construct the master tree given the vector of leaves
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

    // Find membership proof for the 2 underlying trees, based on the challenge
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
