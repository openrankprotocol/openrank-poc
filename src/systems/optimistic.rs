use crate::compute_node::ComputeNode;
use crate::settlement::SmartContract;
use crate::systems::compute_node_et_work;
use halo2curves::{bn256::Fr, ff::Field};
use rand::thread_rng;

#[derive(Clone, Debug)]
pub struct Challenge {
    pub(crate) from: Fr,
    pub(crate) to: Fr,
}

#[derive(Clone, Debug)]
pub struct ConsistencyChallenge {
    pub(crate) target1: Challenge,
    pub(crate) target2: Challenge,
}

pub fn et_optimisitic_interactive() {
    let mut rng = thread_rng();
    let peers = [
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
    ];
    let lt = [
        [0, 1, 4, 1, 4], // 10
        [0, 0, 4, 1, 4], // 9
        [0, 1, 0, 1, 4], // 6
        [2, 1, 5, 0, 4], // 12
        [3, 1, 4, 1, 0], // 9
    ];
    let pre_trust = [0, 0, 0, 3, 7];

    let mut sc = SmartContract::new();

    // Compute node does the work
    let (lt_f, res_f, res_br, res_final_br) = compute_node_et_work(lt, pre_trust);
    let compute_node = ComputeNode::new(
        peers.to_vec(),
        lt_f.map(|lt_arr| lt_arr.to_vec()).to_vec(),
        res_f.to_vec(),
        res_br.to_vec(),
        res_final_br.to_vec(),
    );

    // Compute node sumbits data to a smart contract
    let sc_data = compute_node.sc_data();
    sc.post_data(sc_data);

    // Challenger submits a challenge
    let challenge_validity = Challenge {
        from: peers[0], // wrong at the incoming arc from 'from'/peer[0]
        to: peers[3],   // this peers score is wrong
    };
    let challange_consistency = ConsistencyChallenge {
        target1: challenge_validity.clone(),
        // Different location
        target2: Challenge {
            from: peers[0],
            to: peers[4],
        },
    };
    sc.post_challenge(challenge_validity.clone(), challange_consistency.clone());

    let precision = 6;
    // The submitter posts a response to the challenge
    let validity_proof = compute_node.compute_validity_proof(challenge_validity, precision);
    let consistency_proof = compute_node.compute_consistency_proof(challange_consistency);
    sc.post_response(validity_proof, consistency_proof); // proof is also verified here
}

pub fn et_optimisitic_interactive_failing() {
    let mut rng = thread_rng();
    let peers = [
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
        Fr::random(&mut rng),
    ];
    let lt = [
        [0, 1, 4, 1, 4], // 10
        [0, 0, 4, 1, 4], // 9
        [0, 1, 0, 1, 4], // 6
        [2, 1, 5, 0, 4], // 12
        [3, 1, 4, 1, 0], // 9
    ];
    let pre_trust = [0, 0, 0, 3, 7];

    let mut sc = SmartContract::new();

    // Compute node does the work
    let (lt_f, mut res_f, res_br, res_final_br) = compute_node_et_work(lt, pre_trust);

    // Modify one score, make it invalid
    res_f[1] = Fr::zero();
    let compute_node = ComputeNode::new(
        peers.to_vec(),
        lt_f.map(|lt_arr| lt_arr.to_vec()).to_vec(),
        res_f.to_vec(),
        res_br.to_vec(),
        res_final_br.to_vec(),
    );

    // Compute node sumbits data to a smart contract
    let sc_data = compute_node.sc_data();
    sc.post_data(sc_data);

    // Challenger submits a challenge
    let challenge_validity = Challenge {
        from: peers[1], // wrong at the incoming arc from 'from'/peer[1]
        to: peers[3],   // this peers score is wrong
    };
    let challange_consistency = ConsistencyChallenge {
        target1: challenge_validity.clone(),
        // Different location
        target2: Challenge {
            from: peers[1],
            to: peers[4],
        },
    };
    sc.post_challenge(challenge_validity.clone(), challange_consistency.clone());

    let precision = 6;
    // The submitter posts a response to the challenge
    let validity_proof = compute_node.compute_validity_proof(challenge_validity, precision);
    let consistency_proof = compute_node.compute_consistency_proof(challange_consistency);
    sc.post_response(validity_proof, consistency_proof); // proof is also verified here
}
