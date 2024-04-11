pub fn normalise_sqrt<const N: usize>(vector: [f32; N]) -> [f32; N] {
    let sum: f32 = vector.iter().map(|x| x.powf(2.)).sum();
    if sum == 0. {
        return [0.; N];
    }
    vector.map(|x| x / sum.sqrt())
}

pub fn transpose<const N: usize>(s: [[f32; N]; N]) -> [[f32; N]; N] {
    let mut new_s: [[f32; N]; N] = [[0.; N]; N];
    for i in 0..N {
        for j in 0..N {
            new_s[i][j] = s[j][i];
        }
    }
    new_s
}

pub fn normalise(scores: [f32; NUM_NEIGHBOURS]) -> [f32; NUM_NEIGHBOURS] {
    let sum: f32 = scores.clone().into_iter().sum();
    scores.map(|x| x / sum)
}

const NUM_NEIGHBOURS: usize = 5;

pub fn run<const NUM_ITER: usize>(
    am: [[f32; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
    initial_state_hubs: [f32; NUM_NEIGHBOURS],
    initial_state_auth: [f32; NUM_NEIGHBOURS],
) -> ([f32; NUM_NEIGHBOURS], [f32; NUM_NEIGHBOURS]) {
    let mut s_hubs = initial_state_hubs.clone();
    let mut s_auth = initial_state_auth.clone();
    let transposed_am = transpose(am);

    for _ in 0..NUM_ITER {
        let mut new_s_hubs = [0.; 5];
        let mut new_s_auth = [0.; 5];

        // Hubs
        for i in 0..NUM_NEIGHBOURS {
            for j in 0..NUM_NEIGHBOURS {
                new_s_hubs[i] += am[j][i] * s_auth[j];
            }
        }
        // Authorities
        for i in 0..NUM_NEIGHBOURS {
            for j in 0..NUM_NEIGHBOURS {
                new_s_auth[i] += transposed_am[j][i] * s_hubs[j];
            }
        }

        let final_s_hubs = normalise_sqrt(new_s_hubs);
        let final_s_auth = normalise_sqrt(new_s_auth);

        s_hubs = final_s_hubs;
        s_auth = final_s_auth;
    }

    (s_hubs, s_auth)
}

pub fn run_job() {
    // From hubs to authorities
    let adjacency_matrix: [[f32; NUM_NEIGHBOURS]; NUM_NEIGHBOURS] = [
        [0., 1., 0., 1., 0.],
        [0., 0., 0., 1., 0.],
        [1., 0., 0., 1., 1.],
        [0., 1., 0., 0., 0.],
        [0., 1., 0., 1., 0.],
    ];
    let initial_state_hubs = [32., 0.0, 22., 0.0, 66.];
    let initial_state_auth = [32., 11., 14., 1., 33.];
    run::<30>(adjacency_matrix, initial_state_hubs, initial_state_auth);
}
