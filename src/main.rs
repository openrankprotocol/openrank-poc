use systems::optimistic::{et_optimisitic_interactive, et_optimisitic_interactive_invalid};
use systems::pessimistic::{
    et_pessimistic, et_pessimistic_invalid, ha_pessimistic, ha_pessimistic_invalid,
};

mod algo;
mod compute_node;
mod merkle_tree;
mod params;
mod poseidon;
mod settlement;
mod systems;

fn main() {
    // EigenTrust Pessimistic
    // et_pessimistic();
    // et_pessimistic_failing();

    // EigenTrust Optimistic
    // et_optimisitic_interactive();
    // et_optimisitic_interactive_failing();

    // Hubs And Authorities pessimistic
    // ha_pessimistic();
    ha_pessimistic_invalid();
}
