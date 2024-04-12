use halo2curves::bn256::Fr;

use crate::{
    compute_node::{ConsistencyProof, EtComputeTreeValidityProof, HaComputeTreeValidityProof},
    systems::optimistic::{Challenge, ConsistencyChallenge},
};

pub struct EtSmartContract {
    data: Option<[Fr; 2]>,
    challenge_validity: Option<Challenge>,
    challenge_consistency: Option<ConsistencyChallenge>,
    response_validity: Option<EtComputeTreeValidityProof>,
    response_consistency: Option<ConsistencyProof>,
}

impl EtSmartContract {
    pub fn new() -> Self {
        Self {
            data: None,
            challenge_validity: None,
            challenge_consistency: None,
            response_validity: None,
            response_consistency: None,
        }
    }

    pub fn post_data(&mut self, data: [Fr; 2]) {
        self.data = Some(data);
    }

    pub fn post_challenge(
        &mut self,
        validity_challenge: Challenge,
        consistency_challenge: ConsistencyChallenge,
    ) {
        self.challenge_validity = Some(validity_challenge);
        self.challenge_consistency = Some(consistency_challenge);
    }

    pub fn post_response(
        &mut self,
        validity_proof: EtComputeTreeValidityProof,
        consistency_proof: ConsistencyProof,
    ) {
        self.response_validity = Some(validity_proof);
        self.response_consistency = Some(consistency_proof);
        self.verify_fraud_proof();
    }

    pub fn verify_fraud_proof(&self) {
        let res1 = self
            .response_validity
            .as_ref()
            .unwrap()
            .verify(self.data.unwrap(), self.challenge_validity.clone().unwrap());

        let res2 = self.response_consistency.as_ref().unwrap().verify(
            self.data.unwrap(),
            self.challenge_consistency.clone().unwrap(),
        );

        assert!(res1 && res2);
    }
}

pub struct HaSmartContract {
    data: Option<[Fr; 3]>,
    challenge_validity: Option<Challenge>,
    response_validity: Option<HaComputeTreeValidityProof>,
}

impl HaSmartContract {
    pub fn new() -> Self {
        Self {
            data: None,
            challenge_validity: None,
            response_validity: None,
        }
    }

    pub fn post_data(&mut self, data: [Fr; 3]) {
        self.data = Some(data);
    }

    pub fn post_challenge(&mut self, validity_challenge: Challenge) {
        self.challenge_validity = Some(validity_challenge);
    }

    pub fn post_response(&mut self, validity_proof: HaComputeTreeValidityProof) {
        self.response_validity = Some(validity_proof);
        self.verify_fraud_proof();
    }

    pub fn verify_fraud_proof(&self) {
        let res1 = self
            .response_validity
            .as_ref()
            .unwrap()
            .verify(self.data.unwrap(), self.challenge_validity.clone().unwrap());

        assert!(res1);
    }
}
