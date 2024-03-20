use halo2curves::bn256::Fr;

const NUM_NEIGHBOURS: usize = 5;
const NUM_ITER: usize = 30;

fn validate_lt(lt: [[Fr; NUM_NEIGHBOURS]; NUM_NEIGHBOURS]) {
    // Compute sum of incoming distrust
    for i in 0..NUM_NEIGHBOURS {
        for j in 0..NUM_NEIGHBOURS {
            // Make sure we are not giving score to ourselves
            if i == j {
                assert_eq!(lt[i][j], Fr::zero());
            }
        }
    }
}

fn normalise(
    lt_vec: [Fr; NUM_NEIGHBOURS],
    pre_trust: [Fr; NUM_NEIGHBOURS],
) -> [Fr; NUM_NEIGHBOURS] {
    let sum: Fr = lt_vec.iter().sum();
    if sum == Fr::zero() {
        return pre_trust;
    }
    lt_vec.map(|x| x * sum.invert().unwrap())
}

fn vec_add(s: [Fr; NUM_NEIGHBOURS], y: [Fr; NUM_NEIGHBOURS]) -> [Fr; NUM_NEIGHBOURS] {
    let mut out: [Fr; NUM_NEIGHBOURS] = [Fr::zero(); NUM_NEIGHBOURS];
    for i in 0..NUM_NEIGHBOURS {
        out[i] = s[i] + y[i];
    }
    out
}

pub fn positive_run(
    domain: String,
    mut lt: [[Fr; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
    pre_trust: [Fr; NUM_NEIGHBOURS],
) -> [Fr; NUM_NEIGHBOURS] {
    println!();
    println!("{} - Trust:", domain);

    validate_lt(lt);
    for i in 0..NUM_NEIGHBOURS {
        lt[i] = normalise(lt[i], pre_trust);
    }

    let mut s = pre_trust.clone();
    let pre_trust_weight = Fr::one() * Fr::from(2).invert().unwrap();
    let pre_trusted_scores = pre_trust.map(|x| x * pre_trust_weight);

    for _ in 0..NUM_ITER {
        let mut new_s = [Fr::zero(); 5];

        // Compute sum of incoming weights
        for i in 0..NUM_NEIGHBOURS {
            for j in 0..NUM_NEIGHBOURS {
                new_s[i] += lt[j][i] * s[j];
            }
        }

        let global_scores = new_s.map(|x| (Fr::one() - pre_trust_weight) * x);
        let current_s = vec_add(pre_trusted_scores, global_scores);

        s = current_s;
    }

    s
}
