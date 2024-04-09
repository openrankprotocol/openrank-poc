use params::poseidon_bn254_5x5::Params;
use poseidon::Poseidon;

mod algo;
mod compute_node;
mod merkle_tree;
mod params;
mod poseidon;
mod settlement;
mod systems;

type Hasher = Poseidon<5, Params>;

fn main() {}
