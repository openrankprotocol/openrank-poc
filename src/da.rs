use halo2curves::bn256::Fr;

use crate::{compute_node::ComputeTreeFraudProof, Challenge};

pub struct SmartContract {
    data: Option<[Fr; 2]>,
    challenge: Option<Challenge>,
    response: Option<ComputeTreeFraudProof>,
}

impl SmartContract {
    pub fn new() -> Self {
        Self {
            data: None,
            challenge: None,
            response: None,
        }
    }

    pub fn post_data(&mut self, data: [Fr; 2]) {
        self.data = Some(data);
    }

    pub fn post_challenge(&mut self, challenge: Challenge) {
        self.challenge = Some(challenge);
    }

    pub fn post_response(&mut self, response: ComputeTreeFraudProof) {
        self.response = Some(response)
    }
}
