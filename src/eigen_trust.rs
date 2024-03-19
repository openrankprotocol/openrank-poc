const NUM_NEIGHBOURS: usize = 5;
const NUM_ITER: usize = 30;
const PRE_TRUST_WEIGHT: f32 = 0.5;

fn validate_lt(lt: [[f32; NUM_NEIGHBOURS]; NUM_NEIGHBOURS]) {
    // Compute sum of incoming distrust
    for i in 0..NUM_NEIGHBOURS {
        for j in 0..NUM_NEIGHBOURS {
            // Make sure we are not giving score to ourselves
            if i == j {
                assert_eq!(lt[i][j], 0.);
            }
            assert!(lt[i][j] >= 0.);
        }
    }
}

fn normalise(
    lt_vec: [f32; NUM_NEIGHBOURS],
    pre_trust: [f32; NUM_NEIGHBOURS],
) -> [f32; NUM_NEIGHBOURS] {
    let sum: f32 = lt_vec.iter().sum();
    if sum == 0. {
        return pre_trust;
    }
    lt_vec.map(|x| x / sum)
}

fn vec_add(s: [f32; NUM_NEIGHBOURS], y: [f32; NUM_NEIGHBOURS]) -> [f32; NUM_NEIGHBOURS] {
    let mut out: [f32; NUM_NEIGHBOURS] = [0.; NUM_NEIGHBOURS];
    for i in 0..NUM_NEIGHBOURS {
        out[i] = s[i] + y[i];
    }
    out
}

fn positive_run(
    domain: String,
    mut lt: [[f32; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
    pre_trust: [f32; NUM_NEIGHBOURS],
) -> [f32; NUM_NEIGHBOURS] {
    println!();
    println!("{} - Trust:", domain);

    validate_lt(lt);
    for i in 0..NUM_NEIGHBOURS {
        lt[i] = normalise(lt[i], pre_trust);
    }

    let mut s = pre_trust.clone();
    let pre_trusted_scores = pre_trust.map(|x| x * PRE_TRUST_WEIGHT);

    println!("start: [{}]", s.map(|v| format!("{:>9.4}", v)).join(", "));
    for _ in 0..NUM_ITER {
        let mut new_s = [0.; 5];

        // Compute sum of incoming weights
        for i in 0..NUM_NEIGHBOURS {
            for j in 0..NUM_NEIGHBOURS {
                new_s[i] += lt[j][i] * s[j];
            }
        }

        let global_scores = new_s.map(|x| (1. - PRE_TRUST_WEIGHT) * x);
        let current_s = vec_add(pre_trusted_scores, global_scores);

        s = current_s;
    }
    println!("end: [{}]", s.map(|v| format!("{:>9.4}", v)).join(", "));

    s
}
