use halo2curves::{bn256::Fr, ff::PrimeField};
use num_integer::Integer;
use num_traits::pow;
use std::{collections::HashMap, marker::PhantomData};

use crate::{field_to_bits_vec, poseidon::Hasher};

const WIDTH: usize = 5;

#[derive(Clone, Debug)]
/// MerkleTree structure
pub struct SparseMerkleTree<H>
where
    H: Hasher<WIDTH>,
{
    /// HashMap to keep the level and index of the nodes
    pub(crate) nodes: HashMap<(u32, Fr), Fr>,
    /// Default nodes
    default: Vec<Fr>,
    /// PhantomData for the hasher
    _h: PhantomData<H>,
}

impl<H> SparseMerkleTree<H>
where
    H: Hasher<WIDTH>,
{
    /// Build a MerkleTree from given leaf nodes and height
    pub fn new() -> Self {
        let num_levels = Fr::NUM_BITS as usize;

        let mut default = Vec::new();
        default.push(Fr::zero());
        for i in 1..num_levels {
            let nodes = [
                default[i - 1],
                default[i - 1],
                Fr::zero(),
                Fr::zero(),
                Fr::zero(),
            ];
            let h = H::new(nodes).finalize();
            default.push(h);
        }

        Self {
            nodes: HashMap::new(),
            default,
            _h: PhantomData,
        }
    }

    pub fn insert_leaf_single(&mut self, index: Fr, value: Fr) {
        let inputs = [value, Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()];
        let h = H::new(inputs).finalize();
        let bits = field_to_bits_vec(index);

        let mut curr_index = index * Fr::from_u128(2).invert().unwrap();
        let mut curr_node = h;
        for i in 0..Fr::NUM_BITS {
            let inputs = if bits[i as usize] {
                let key = (i, curr_index);
                let neighbour = self.nodes.get(&key).unwrap_or(&self.default[i as usize]);
                [*neighbour, curr_node, Fr::zero(), Fr::zero(), Fr::zero()]
            } else {
                let key = (i, curr_index + Fr::one());
                let neighbour = self.nodes.get(&key).unwrap_or(&self.default[i as usize]);
                [*neighbour, curr_node, Fr::zero(), Fr::zero(), Fr::zero()]
            };

            let h = H::new(inputs).finalize();
            self.nodes.insert((i + 1, curr_index), h);

            curr_node = h;
            curr_index = curr_index * Fr::from_u128(2).invert().unwrap();
        }
    }
}

// #[derive(Clone)]
// /// Path structure
// pub struct Path<const ARITY: usize, const HEIGHT: usize, const LENGTH: usize, H>
// where
// 	H: Hasher<WIDTH>,
// {
// 	/// Value that is based on for construction of the path
// 	#[allow(dead_code)]
// 	pub(crate) value: Fr,
// 	/// Array that keeps the path
// 	pub(crate) path_arr: [[Fr; ARITY]; LENGTH],
// 	/// PhantomData for the hasher
// 	_h: PhantomData<H>,
// }

// impl<const ARITY: usize, const HEIGHT: usize, const LENGTH: usize, H>
// 	Path<ARITY, HEIGHT, LENGTH, H>
// where
// 	H: Hasher<WIDTH>,
// {
// 	/// Find path for the given value to the root
// 	pub fn find_path(
// 		merkle_tree: &MerkleTree<ARITY, HEIGHT, H>, mut value_index: usize,
// 	) -> Path<ARITY, HEIGHT, LENGTH, H> {
// 		let value = merkle_tree.nodes[&0][value_index];
// 		let mut path_arr: [[Fr; ARITY]; LENGTH] = [[Fr::zero(); ARITY]; LENGTH];

// 		for level in 0..merkle_tree.height {
// 			let wrap = value_index.div_rem(&ARITY);
// 			for i in 0..ARITY {
// 				path_arr[level][i] = merkle_tree.nodes[&level][wrap.0 * ARITY + i];
// 			}
// 			value_index /= ARITY;
// 		}

// 		path_arr[merkle_tree.height][0] = merkle_tree.root;
// 		Self { value, path_arr, _h: PhantomData }
// 	}

// 	/// Sanity check for the path array
// 	pub fn verify(&self) -> bool {
// 		let mut is_satisfied = true;
// 		let mut hasher_inputs = [Fr::zero(); WIDTH];
// 		for i in 0..self.path_arr.len() - 1 {
// 			hasher_inputs[..ARITY].copy_from_slice(&self.path_arr[i][..ARITY]);
// 			let hasher = H::new(hasher_inputs);
// 			is_satisfied &= self.path_arr[i + 1].contains(&(hasher.finalize()[0]))
// 		}
// 		is_satisfied
// 	}
// }

#[cfg(test)]
mod test {
    use super::SparseMerkleTree;
    use crate::{params::poseidon_bn254_5x5::Params, poseidon::Poseidon};
    use halo2curves::{
        bn256::Fr,
        ff::{Field, PrimeField},
    };
    use rand::thread_rng;

    #[test]
    fn should_build_tree_and_find_path_arity_2() {
        // Testing build_tree and find_path functions with arity 2
        let rng = &mut thread_rng();
        let value = Fr::random(rng.clone());
        let leaves = vec![
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            value,
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
        ];
        // let merkle = MerkleTree::<2, 3, Poseidon<5, Params>>::build_tree(leaves);
        // let path = Path::<2, 3, 4, Poseidon<5, Params>>::find_path(&merkle, 4);

        // assert!(path.verify());
        // // Assert last element of the array and the root of the tree
        // assert_eq!(path.path_arr[merkle.height][0], merkle.root);
    }

    #[test]
    fn should_build_tree_and_find_path_arity_3() {
        // Testing build_tree and find_path functions with arity 3
        let rng = &mut thread_rng();
        let value = Fr::random(rng.clone());
        let leaves = vec![
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            value,
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
        ];
        // let merkle = MerkleTree::<3, 3, Poseidon<5, Params>>::build_tree(leaves);
        // let path = Path::<3, 3, 4, Poseidon<5, Params>>::find_path(&merkle, 7);

        // assert!(path.verify());
        // // Assert last element of the array and the root of the tree
        // assert_eq!(path.path_arr[merkle.height][0], merkle.root);
    }

    #[test]
    fn should_build_small_tree() {
        // Testing build_tree and find_path functions with a small array
        // let rng = &mut thread_rng();
        // let value = Fr::random(rng.clone());
        // let merkle = MerkleTree::<2, 0, Poseidon<5, Params>>::build_tree(vec![value]);
        // let path = Path::<2, 0, 1, Poseidon<5, Params>>::find_path(&merkle, 0);
        // assert!(path.verify());
        // // Assert last element of the array and the root of the tree
        // assert_eq!(path.path_arr[merkle.height][0], merkle.root);
    }
}
