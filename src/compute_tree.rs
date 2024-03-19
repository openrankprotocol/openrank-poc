use crate::{
    merkle_tree::{Path, SparseMerkleTree},
    Hasher,
};
use halo2curves::bn256::Fr;

struct ComputeTreeFraudProof {
    // Peers Global Trust path
    master_path: Path<Hasher>,
    sub_path: Path<Hasher>,
    // Neighbours local trust path
    trust_tree_master_path: Path<Hasher>,
    trust_tree_sub_path: Path<Hasher>,
    // Neighbours Global Trust path
    compute_tree_master_path: Path<Hasher>,
    compute_tree_sub_path: Path<Hasher>,
}

fn construct_sub_tree(indices: Vec<Fr>, peers: Vec<(Fr, Fr)>) -> SparseMerkleTree<Hasher> {
    let mut smt = SparseMerkleTree::new();

    peers
        .iter()
        .zip(indices)
        .for_each(|(&(local_trust, global_trust), index)| {
            smt.insert_leaf_mul(index, (local_trust, global_trust));
        });

    smt
}

fn construct_master_tree(indices: Vec<Fr>, peers: Vec<(Fr, Fr)>) -> SparseMerkleTree<Hasher> {
    let mut smt = SparseMerkleTree::new();

    peers
        .iter()
        .zip(indices)
        .for_each(|(&(sub_root_hash, score), index)| {
            smt.insert_leaf(index, (sub_root_hash, score));
        });

    smt
}
