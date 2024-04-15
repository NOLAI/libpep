use aes::{Aes256};
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use rand_core::OsRng;
use libpep::arithmetic::{G, GroupElement, ScalarNonZero};
use libpep::elgamal::{decrypt, encrypt};
use libpep::primitives::{rekey_from_to, rsk_from_to};

fn transcrypt_rsk(n: usize, l: usize, m: usize) {
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
}

fn transcrypt_rekey(n: usize, l: usize, m: usize) {
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
}

fn tunnels(n: usize, l: usize, m: usize) {
    let mut rng = OsRng;
    let key = GenericArray::from(GroupElement::random(&mut rng).encode());
    let cipher = Aes256::new(&key);

    let mut data = GenericArray::from([42u8; 16]);
    let mut value = data.clone();

    // START BENCHMARK
    for _ in 0..l {
        for _ in 0 .. 2*m { // 2*m blocks because blocks are 16 bytes, not 32
            // sender
            cipher.encrypt_block(&mut value);

            // n-tiers
            for _ in 0..n {
                cipher.decrypt_block(&mut value);
                cipher.encrypt_block(&mut value);
            }

            // receiver
            cipher.decrypt_block(&mut value);
            debug_assert_eq!(data.as_slice(), value.as_slice());
        }
    }
    // END BENCHMARK
}


#[test]
fn n_pep_energy_id() {
    let n = 2;
    let l = 1000;
    let m = 1; // aantal blokken van 32 bytes
    transcrypt_rsk(n, l, m); // single identifier, just under 32 bytes
}

#[test]
fn n_pep_energy_data() {
    let n = 2;
    let l = 1000;
    let m = 1; // aantal blokken van 32 bytes
    transcrypt_rekey(n, l, m); // single data points, just under 32 bytes
}

#[test]
fn tunnels_energy() {
    let n = 2;
    let l = 1000;
    let m = 1; // aantal blokken van 32 bytes
    tunnels(n, l, m); // single identifier, just under 32 bytes
}
