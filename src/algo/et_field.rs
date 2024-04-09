use halo2curves::bn256::Fr;

const NUM_NEIGHBOURS: usize = 5;

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

fn normalise(lt_vec: [Fr; NUM_NEIGHBOURS]) -> [Fr; NUM_NEIGHBOURS] {
    let sum: Fr = lt_vec.iter().sum();
    lt_vec.map(|x| x * sum.invert().unwrap())
}

fn vec_add(s: [Fr; NUM_NEIGHBOURS], y: [Fr; NUM_NEIGHBOURS]) -> [Fr; NUM_NEIGHBOURS] {
    let mut out: [Fr; NUM_NEIGHBOURS] = [Fr::zero(); NUM_NEIGHBOURS];
    for i in 0..NUM_NEIGHBOURS {
        out[i] = s[i] + y[i];
    }
    out
}

pub fn positive_run<const NUM_ITER: usize>(
    mut lt: [[Fr; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
    seed: [Fr; NUM_NEIGHBOURS],
) -> [Fr; NUM_NEIGHBOURS] {
    validate_lt(lt);
    for i in 0..NUM_NEIGHBOURS {
        lt[i] = normalise(lt[i]);
    }

    let mut s = seed.clone();

    for _ in 0..NUM_ITER {
        let mut new_s = [Fr::zero(); 5];

        // Compute sum of incoming weights
        for i in 0..NUM_NEIGHBOURS {
            for j in 0..NUM_NEIGHBOURS {
                new_s[i] += lt[j][i] * s[j];
            }
        }

        s = new_s;
    }

    s
}
