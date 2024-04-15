use rand_core::OsRng;
use libpep::arithmetic::{G, GroupElement, ScalarNonZero};
use libpep::elgamal::{decrypt, encrypt};
use libpep::primitives::rsk_from_to;

fn transcrypt(n: usize, l: usize) {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);

    // public key
    let gy = y * G;

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    let s_froms = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));
    let s_tos = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));
    let k_froms = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));
    let k_tos = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));

    let k_from = k_froms.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);
    let k_to = k_tos.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);

    let s_from = s_froms.iter().fold(ScalarNonZero::one(), |acc, s| acc * s);
    let s_to = s_tos.iter().fold(ScalarNonZero::one(), |acc, s| acc * s);

    let s = s_from.invert() * s_to;

    // START BENCHMARK
    for j in 0.. l {
        let mut value = encrypt(&m, &(k_from*gy), &mut OsRng);

        // encrypt/decrypt this value
        for i in 0..n {
            value = rsk_from_to(&value, &s_froms[i], &s_tos[i], &k_froms[i], &k_tos[i]);
        }

        let decrypted = decrypt(&value, &(k_to*y));
        debug_assert_eq!(s * m, decrypted);

    }
    // END BENCHMARK
}


#[test]
fn n_pep_energy() {
    let n = 2;
    let l = 1000;
    transcrypt(n, l);
}