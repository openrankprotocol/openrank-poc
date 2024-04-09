use std::collections::HashMap;

use halo2curves::bn256::Fr;

use crate::{
    merkle_tree::{Path, SparseMerkleTree},
    systems::optimistic::Challenge,
    Hasher,
};

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
    pub fn new(peers: Vec<Fr>, lt: Vec<Vec<Fr>>, res: Vec<Fr>) -> Self {
        let mut lt_sum: Vec<Fr> = Vec::new();
        for i in 0..peers.len() {
            lt_sum.push(lt[i].iter().sum());
        }
        let mut master_c_tree_leaves = Vec::new();
        let mut sub_trees = HashMap::new();
        for i in 0..peers.len() {
            let mut sub_tree_leaves = Vec::new();
            for j in 0..peers.len() {
                let gt = res[j];
                let lt_norm = lt[j][i] * lt_sum[j].invert().unwrap();
                sub_tree_leaves.push((lt_norm, gt));
            }
            let sub_tree = Self::construct_sub_tree(peers.clone(), sub_tree_leaves);
            let (root_hash, score) = sub_tree.root();

            sub_trees.insert(peers[i], sub_tree);
            master_c_tree_leaves.push((root_hash, score));
        }

        let master_tree = Self::construct_master_tree(peers, master_c_tree_leaves);

        Self {
            master_tree,
            sub_trees,
        }
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

#[cfg(test)]
mod test {
    use super::ComputeTree;
    use crate::{algo::et_field, systems::optimistic::Challenge};
    use halo2curves::bn256::Fr;

    #[test]
    fn should_create_compute_tree() {
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

        let compute_tree = ComputeTree::new(
            peers.to_vec(),
            lt.map(|lt_arr| lt_arr.to_vec()).to_vec(),
            res.to_vec(),
        );

        let challenge = Challenge {
            from: peers[0],
            to: peers[1],
        };
        let mem_proof = compute_tree.find_membership_proof(challenge);
        assert!(mem_proof.verify());
    }
}
