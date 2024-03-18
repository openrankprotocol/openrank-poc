use halo2curves::{bn256::Fr, ff::PrimeField};
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
    pub(crate) nodes: HashMap<(u32, Fr), (Fr, Fr)>,
    /// Default nodes
    default: Vec<(Fr, Fr)>,
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
        default.push((Fr::zero(), Fr::zero()));
        for i in 1..num_levels {
            let nodes = [
                default[i - 1].0,
                Fr::zero(),
                default[i - 1].0,
                Fr::zero(),
                Fr::zero(),
            ];
            let h = H::new(nodes).finalize();
            default.push((h, Fr::zero()));
        }

        Self {
            nodes: HashMap::new(),
            default,
            _h: PhantomData,
        }
    }

    pub fn insert_leaf(&mut self, index: Fr, leaf: (Fr, Fr)) {
        let bits = field_to_bits_vec(index);

        let mut curr_index = index * Fr::from_u128(2).invert().unwrap();
        let mut curr_node = leaf;
        for i in 0..Fr::NUM_BITS {
            let inputs = if bits[i as usize] {
                let (node, value) = curr_node;
                let n_key = (i, curr_index - Fr::one());
                let (n_node, n_value) = self.nodes.get(&n_key).unwrap_or(&self.default[i as usize]);
                [*n_node, *n_value, node, value, Fr::zero()]
            } else {
                let (node, value) = curr_node;
                let n_key = (i, curr_index + Fr::one());
                let (n_node, n_value) = self.nodes.get(&n_key).unwrap_or(&self.default[i as usize]);
                [*n_node, *n_value, node, value, Fr::zero()]
            };

            let h = H::new(inputs).finalize();
            let sum = inputs[1] + inputs[3];
            self.nodes.insert((i + 1, curr_index), (h, sum));

            curr_node = (h, sum);
            curr_index = curr_index * Fr::from_u128(2).invert().unwrap();
        }
    }

    /// Find path for the given value to the root
    pub fn find_path(&self, index: Fr) -> Path<H> {
        let mut path_arr: [[Fr; 4]; Fr::NUM_BITS as usize] =
            [[Fr::zero(); 4]; Fr::NUM_BITS as usize];

        let bits = field_to_bits_vec(index);

        let mut curr_index = index * Fr::from_u128(2).invert().unwrap();
        for level in 0..Fr::NUM_BITS {
            let is_right = bits[level as usize];
            let pair = if is_right {
                let (left, l_value) = self
                    .nodes
                    .get(&(level, curr_index - Fr::one()))
                    .unwrap_or(&self.default[level as usize]);
                let (right, r_value) = self
                    .nodes
                    .get(&(level, curr_index))
                    .unwrap_or(&self.default[level as usize]);
                [*left, *l_value, *right, *r_value]
            } else {
                let (left, l_value) = self
                    .nodes
                    .get(&(level, curr_index))
                    .unwrap_or(&self.default[level as usize]);
                let (right, r_value) = self
                    .nodes
                    .get(&(level, curr_index + Fr::one()))
                    .unwrap_or(&self.default[level as usize]);
                [*left, *l_value, *right, *r_value]
            };
            path_arr[level as usize] = pair;
            curr_index = curr_index * Fr::from_u128(2).invert().unwrap();
        }

        let value = if bits[0] {
            path_arr[0][1]
        } else {
            path_arr[0][3]
        };

        Path {
            value,
            path_arr,
            _h: PhantomData,
        }
    }
}

#[derive(Clone)]
/// Path structure
pub struct Path<H>
where
    H: Hasher<WIDTH>,
{
    /// Value that is based on for construction of the path
    #[allow(dead_code)]
    pub(crate) value: Fr,
    /// Array that keeps the path
    pub(crate) path_arr: [[Fr; 4]; Fr::NUM_BITS as usize],
    /// PhantomData for the hasher
    _h: PhantomData<H>,
}

impl<H> Path<H>
where
    H: Hasher<WIDTH>,
{
    /// Sanity check for the path array
    pub fn verify(&self) -> bool {
        let mut is_satisfied = true;
        let mut hasher_inputs = [Fr::zero(); WIDTH];
        for i in 0..self.path_arr.len() - 1 {
            hasher_inputs[..4].copy_from_slice(&self.path_arr[i][..4]);
            let node = H::new(hasher_inputs).finalize();
            is_satisfied &= self.path_arr[i + 1].contains(&node)
        }
        is_satisfied
    }
}

#[cfg(test)]
mod test {
    use super::SparseMerkleTree;
    use crate::{params::poseidon_bn254_5x5::Params, poseidon::Poseidon};
    use halo2curves::{bn256::Fr, ff::Field};
    use rand::thread_rng;

    #[test]
    fn should_build_tree() {
        // Testing build_tree and find_path functions with arity 2
        let rng = &mut thread_rng();
        let node = Fr::random(rng.clone());
        let leaves = vec![
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            node,
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
        let mut merkle = SparseMerkleTree::<Poseidon<5, Params>>::new();
        for (i, leaf) in leaves.iter().enumerate() {
            let index = Fr::from(i as u64);
            merkle.insert_leaf(index, (*leaf, Fr::from(5)));
        }
        let path = merkle.find_path(Fr::from(7));

        assert!(path.verify());
    }
}
