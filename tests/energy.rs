use libaes::Cipher;
use rand::Rng;
use rand_core::OsRng;
use libpep::arithmetic::{G, GroupElement, ScalarNonZero};
use libpep::elgamal::{decrypt, encrypt};
use libpep::primitives::{rekey_from_to, rsk_from_to};

fn get_ina() -> Option<f64> {
    let url = std::env::var("ENERGY_STATS").ok()?;
    let agent: ureq::Agent = ureq::AgentBuilder::new()
      .user_agent(&format!("{} {}/{}", env!("CARGO_PKG_NAME"), buildinfy::build_reference().unwrap_or_default(), buildinfy::build_pipeline_id_per_project().unwrap_or_default()))
      .timeout_read(std::time::Duration::from_secs(60))
      .timeout_write(std::time::Duration::from_secs(5))
      .build();
    let resp = agent.get(&url).call().ok()?;
    resp.header("X-Electricity-Consumed-Total")?.parse().ok()
}


fn transcrypt_id(n: usize, l: usize, m: usize) {
    let mut rng = OsRng;

    // system params
    let y = ScalarNonZero::random(&mut rng); // global private
    let gy = y * G; // global public

    // random message
    let data = GroupElement::random(&mut rng);

    // factors
    let s_from_s = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));
    let s_to_s = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));
    let k_from_s = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));
    let k_to_s = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));

    let k_from = k_from_s.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);
    let k_to = k_to_s.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);

    let s_from = s_from_s.iter().fold(ScalarNonZero::one(), |acc, s| acc * s);
    let s_to = s_to_s.iter().fold(ScalarNonZero::one(), |acc, s| acc * s);

    let s = s_from.invert() * s_to;

    // START BENCHMARK
    let before = get_ina();

    for _ in 0.. l {
        for _ in 0..m {
            let mut value = encrypt(&data, &(k_from * gy), &mut OsRng); // initial encryption

            // transcryption
            for i in 0..n {
                value = rsk_from_to(&value, &s_from_s[i], &s_to_s[i], &k_from_s[i], &k_to_s[i]);
            }

            let decrypted = decrypt(&value, &(k_to * y)); // final decryption
            debug_assert_eq!(s * data, decrypted);
        }
    }
    // END BENCHMARK
    let after = get_ina();
    if let (Some(before), Some(after)) = (before, after) {
        eprintln!("energy {} J", after - before);
    }
}

fn transcrypt_data(n: usize, l: usize, m: usize) {
    let mut rng = OsRng;

    // system params
    let y = ScalarNonZero::random(&mut rng); // global private
    let gy = y * G; // global public

    // random message
    let data = GroupElement::random(&mut rng);

    // factors
    let k_from_s = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));
    let k_to_s = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));

    let k_from = k_from_s.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);
    let k_to = k_to_s.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);

    // START BENCHMARK
    let before = get_ina();

    for _ in 0.. l {
        for _ in 0..m {
            let mut value = encrypt(&data, &(k_from * gy), &mut OsRng); // initial encryption

            // transcryption
            for i in 0..n {
                value = rekey_from_to(&value, &k_from_s[i], &k_to_s[i]);
            }

            let decrypted = decrypt(&value, &(k_to * y)); // final decryption
            debug_assert_eq!(data, decrypted);
        }
    }
    // END BENCHMARK
    let after = get_ina();
    if let (Some(before), Some(after)) = (before, after) {
        eprintln!("energy {} J", after - before);
    }

}

fn tunnels(n: usize, l: usize, m: usize) {

    // START BENCHMARK
    let before = get_ina();

    for _ in 0..l {
        let mut key = [0u8; 32];
        rand::thread_rng().fill(&mut key[..]);

        let iv = [0u8; 16];
        rand::thread_rng().fill(&mut key[..]);

        for _ in 0 .. m {

            let data_length = 32 * m;
            let mut data = vec![0u8; data_length];
            rand::thread_rng().fill(&mut data[..]);

            let cipher = Cipher::new_256(&key);

            // sender
            let mut encrypted = cipher.cbc_encrypt(&iv, &data);

            // n-tiers
            for _ in 0..n {
                let decrypted = cipher.cbc_decrypt(&iv, &encrypted);
                let clone = decrypted.clone();

                encrypted = cipher.cbc_encrypt(&iv, &clone);
                encrypted = encrypted.clone();
            }
            let received = cipher.cbc_decrypt(&iv, &encrypted);
            debug_assert_eq!(data, received);
        }
    }
    // END BENCHMARK
    let after = get_ina();
    if let (Some(before), Some(after)) = (before, after) {
        eprintln!("energy {} J", after - before);
    }
}

#[test]
fn energy_analysis_id_pep() {
    let l = 10000; // experiment length iterations
    let n = 3; // number of tiers
    let m = 1; // number of blocks / data length (multiples of 32 bytes)

    transcrypt_id(n, l, m);
}

#[test]
fn energy_analysis_data_pep() {
    let l = 10000; // experiment length iterations
    let n = 3; // number of tiers
    let m = 10; // number of blocks / data length (multiples of 32 bytes)

    transcrypt_data(n, l, m);
}

#[test]
fn energy_analysis_id_tunnels() {
    let l = 10000; // experiment length iterations
    let n = 3; // number of tiers
    let m = 1; // number of blocks / data length (multiples of 32 bytes)

    tunnels(n, l, m);
}

#[test]
fn energy_analysis_data_tunnels() {
    let l = 10000; // experiment length iterations
    let n = 3; // number of tiers
    let m = 10; // number of blocks / data length (multiples of 32 bytes)

    tunnels(n, l, m);
}
