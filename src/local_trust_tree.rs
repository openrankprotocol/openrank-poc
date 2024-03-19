use crate::{
    merkle_tree::{Path, SparseMerkleTree},
    Hasher, LinearCombination,
};
use halo2curves::bn256::Fr;

struct TrustTreeFraudProof {
    master_tree_path: Path<Hasher>,
    sub_tree_path: Path<Hasher>,
    linear_combination: LinearCombination,
}

fn construct_sub_tree(from: Fr, lcs: &Vec<LinearCombination>) -> SparseMerkleTree<Hasher> {
    let mut smt = SparseMerkleTree::new();

    lcs.iter().for_each(|x| {
        assert!(x.from == from);
        smt.insert_leaf(x.to, (x.to, x.sum_weights));
    });

    smt
}

fn construct_master_tree(indices: Vec<Fr>, peers: Vec<(Fr, Fr)>) -> SparseMerkleTree<Hasher> {
    let mut smt = SparseMerkleTree::new();

    peers
        .iter()
        .zip(indices)
        .for_each(|(&(sub_root_hash, total_lt), index)| {
            smt.insert_leaf(index, (sub_root_hash, total_lt));
        });

    smt
}
