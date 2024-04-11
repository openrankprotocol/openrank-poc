use halo2curves::bn256::Fr;
use std::collections::HashMap;

use crate::{
    merkle_tree::{Path, SparseMerkleTree},
    systems::optimistic::Challenge,
};

use super::Hasher;

struct LinearCombination {
    from: Fr,
    to: Fr,
    sum_of_weights: Fr,
}

pub struct LocalTrustTreeMembershipProof {
    // Proof of membership for Master Tree
    pub(crate) master_tree_path: Path<Hasher>,
    // Proof of membership for Sub Tree
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
    // Master Tree that contains every peers sub tree
    pub(crate) master_tree: SparseMerkleTree<Hasher>,
    // Each peer has a separate sub tree, where the root will contain the sum of outgoing local scores
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

    // Helper function for constructing sub trees
    pub fn construct_sub_tree(from: Fr, lcs: &Vec<LinearCombination>) -> SparseMerkleTree<Hasher> {
        let mut smt = SparseMerkleTree::new();

        lcs.iter().for_each(|x| {
            assert!(x.from == from);
            smt.insert_leaf(x.to, (x.to, x.sum_of_weights));
        });

        smt
    }

    // Helper function for constructing master tree
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

    // Find membership proofs based on the challenge
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

#[cfg(test)]
mod test {
    use crate::systems::optimistic::Challenge;

    use super::LocalTrustTree;
    use halo2curves::bn256::Fr;

    #[test]
    fn should_create_lt_tree() {
        let peers = [1, 2, 3, 4, 5].map(|x| Fr::from(x));

        let lt = [
            [0, 1, 4, 1, 4],
            [0, 0, 4, 1, 4],
            [0, 1, 0, 1, 4],
            [2, 1, 5, 0, 4],
            [3, 1, 4, 1, 0],
        ]
        .map(|xs| xs.map(|x| Fr::from(x)));

        let lt_tree =
            LocalTrustTree::new(peers.to_vec(), lt.map(|lt_arr| lt_arr.to_vec()).to_vec());

        let challenge = Challenge {
            from: peers[0],
            to: peers[1],
        };
        let mem_proof = lt_tree.find_membership_proof(challenge);
        assert!(mem_proof.verify());
    }
}
