use halo2curves::{bn256::Fr, ff::PrimeField};
use std::{collections::HashMap, marker::PhantomData};

use crate::{poseidon::Hasher, systems::field_to_bits_vec};

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
    pub fn root(&self) -> (Fr, Fr) {
        let num_levels = Fr::NUM_BITS;
        self.nodes.get(&(num_levels, Fr::zero())).unwrap().clone()
    }

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

        self.nodes.insert((0, index), leaf);

        let mut curr_index = index;
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
                [node, value, *n_node, *n_value, Fr::zero()]
            };

            let h = H::new(inputs).finalize();
            let sum = inputs[1] + inputs[3];

            curr_node = (h, sum);
            curr_index = next_index(curr_index);

            self.nodes.insert((i + 1, curr_index), curr_node);
        }
    }

    pub fn insert_leaf_mul(&mut self, index: Fr, leaf: (Fr, Fr)) {
        let bits = field_to_bits_vec(index);

        self.nodes.insert((0, index), leaf);

        let (l_value, r_value) = leaf;

        let inputs = if bits[0] {
            let n_key = (0, index - Fr::one());
            let (n_lv, n_rv) = self.nodes.get(&n_key).unwrap_or(&self.default[0]);
            [*n_lv, *n_rv, l_value, r_value, Fr::zero()]
        } else {
            let n_key = (0, index + Fr::one());
            let (n_lv, n_rv) = self.nodes.get(&n_key).unwrap_or(&self.default[0]);
            [l_value, r_value, *n_lv, *n_rv, Fr::zero()]
        };
        let h = H::new(inputs).finalize();

        let sum = inputs[0] * inputs[1] + inputs[2] * inputs[3];
        let mut curr_node = (h, sum);
        let mut curr_index = next_index(index);

        self.nodes.insert((1, curr_index), curr_node);

        for i in 1..Fr::NUM_BITS {
            let inputs = if bits[i as usize] {
                let (node, value) = curr_node;
                let n_key = (i, curr_index - Fr::one());
                let (n_node, n_value) = self.nodes.get(&n_key).unwrap_or(&self.default[i as usize]);
                [*n_node, *n_value, node, value, Fr::zero()]
            } else {
                let (node, value) = curr_node;
                let n_key = (i, curr_index + Fr::one());
                let (n_node, n_value) = self.nodes.get(&n_key).unwrap_or(&self.default[i as usize]);
                [node, value, *n_node, *n_value, Fr::zero()]
            };

            let h = H::new(inputs).finalize();
            let sum = inputs[1] + inputs[3];

            curr_node = (h, sum);
            curr_index = next_index(curr_index);

            self.nodes.insert((i + 1, curr_index), curr_node);
        }
    }

    /// Find path for the given value to the root
    pub fn find_path(&self, index: Fr) -> Path<H> {
        let mut path_arr: [[Fr; 4]; Fr::NUM_BITS as usize] =
            [[Fr::zero(); 4]; Fr::NUM_BITS as usize];

        let bits = field_to_bits_vec(index);

        let mut curr_index = index;
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
            curr_index = next_index(curr_index);
        }

        let root = self.nodes.get(&(Fr::NUM_BITS, curr_index)).unwrap();

        Path {
            index,
            path_arr,
            root: root.clone(),
            _h: PhantomData,
        }
    }

    pub fn get_leaves(&self) -> Vec<Fr> {
        let mut leaves = Vec::new();
        for (key, value) in &self.nodes {
            if key.0 == 0 {
                leaves.push(value.1);
            }
        }
        leaves
    }
}

#[derive(Clone)]
/// Path structure
pub struct Path<H>
where
    H: Hasher<WIDTH>,
{
    /// Index of the leaf node
    pub(crate) index: Fr,
    /// Root node
    pub(crate) root: (Fr, Fr),
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
        let bits = field_to_bits_vec(self.index);
        let mut is_satisfied = true;
        let mut hasher_inputs = [Fr::zero(); WIDTH];
        for i in 0..Fr::NUM_BITS as usize - 1 {
            hasher_inputs[..4].copy_from_slice(&self.path_arr[i][..4]);
            let node = H::new(hasher_inputs).finalize();
            let res_sum = self.path_arr[i][1] + self.path_arr[i][3];

            let (parent, sum) = if bits[i + 1] {
                (self.path_arr[i + 1][2], self.path_arr[i + 1][3])
            } else {
                (self.path_arr[i + 1][0], self.path_arr[i + 1][1])
            };

            let is_same_parent_node = (parent, sum) == (node, res_sum);
            is_satisfied &= is_same_parent_node;
        }

        let last_level = Fr::NUM_BITS as usize - 1;
        hasher_inputs[..4].copy_from_slice(&self.path_arr[last_level][..4]);
        let node = H::new(hasher_inputs).finalize();
        let res_sum = self.path_arr[last_level][1] + self.path_arr[last_level][3];

        let is_same_parent_node = self.root == (node, res_sum);
        is_satisfied &= is_same_parent_node;

        is_satisfied
    }

    /// Verify Multiplicative leaf path
    /// Multiplicative leaf is the leaf where
    /// the tuples are multiplied together before being added
    pub fn verify_mul(&self) -> bool {
        let bits = field_to_bits_vec(self.index);
        let mut is_satisfied = true;
        let mut hasher_inputs = [Fr::zero(); WIDTH];

        hasher_inputs[..4].copy_from_slice(&self.path_arr[0][..4]);
        let node = H::new(hasher_inputs).finalize();
        let res_sum =
            self.path_arr[0][0] * self.path_arr[0][1] + self.path_arr[0][2] * self.path_arr[0][3];

        let (parent, sum) = if bits[1] {
            (self.path_arr[1][2], self.path_arr[1][3])
        } else {
            (self.path_arr[1][0], self.path_arr[1][1])
        };

        let is_same_parent_node = (parent, sum) == (node, res_sum);
        is_satisfied &= is_same_parent_node;

        for i in 1..Fr::NUM_BITS as usize - 1 {
            hasher_inputs[..4].copy_from_slice(&self.path_arr[i][..4]);
            let node = H::new(hasher_inputs).finalize();
            let res_sum = self.path_arr[i][1] + self.path_arr[i][3];

            let (parent, sum) = if bits[i + 1] {
                (self.path_arr[i + 1][2], self.path_arr[i + 1][3])
            } else {
                (self.path_arr[i + 1][0], self.path_arr[i + 1][1])
            };

            let is_same_parent_node = (parent, sum) == (node, res_sum);
            is_satisfied &= is_same_parent_node;
        }

        let last_level = Fr::NUM_BITS as usize - 1;
        hasher_inputs[..4].copy_from_slice(&self.path_arr[last_level][..4]);
        let node = H::new(hasher_inputs).finalize();
        let res_sum = self.path_arr[last_level][1] + self.path_arr[last_level][3];

        let is_same_parent_node = self.root == (node, res_sum);
        is_satisfied &= is_same_parent_node;

        is_satisfied
    }

    pub fn root(&self) -> (Fr, Fr) {
        self.root
    }

    pub fn value(&self) -> (Fr, Fr) {
        let bits = field_to_bits_vec(self.index);
        if bits[0] {
            (self.path_arr[0][2], self.path_arr[0][3])
        } else {
            (self.path_arr[0][0], self.path_arr[0][1])
        }
    }
}

fn next_index(i: Fr) -> Fr {
    if i.is_odd().unwrap_u8() == 1 {
        (i - Fr::one()) * Fr::from(2).invert().unwrap()
    } else {
        i * Fr::from(2).invert().unwrap()
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
        let (path_root, _) = path.root();
        let (merkle_root, _) = merkle.root();

        assert!(path_root == merkle_root);
        assert!(path.verify());
    }

    #[test]
    fn should_build_mul_tree() {
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
            merkle.insert_leaf_mul(index, (*leaf, Fr::from(5)));
        }
        let path = merkle.find_path(Fr::from(7));
        let (path_root, _) = path.root();
        let (merkle_root, _) = merkle.root();

        assert!(path_root == merkle_root);
        assert!(path.verify_mul());
    }
}
