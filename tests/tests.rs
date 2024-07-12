use libpep::arithmetic::*;
use libpep::elgamal::*;
use libpep::primitives::*;
use rand_core::OsRng;

#[test]
fn elgamal_encryption() {
    let mut rng = OsRng;
    // secret key
    let s = ScalarNonZero::random(&mut rng);
    // public key
    let p = s * G;

    // choose a random value to encrypt
    let value = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&value, &p, &mut OsRng);
    let decrypted = decrypt(&encrypted, &s);

    assert_eq!(value, decrypted);

    let encoded = encrypted.encode();
    let decoded = ElGamal::decode(&encoded);

    assert_eq!(Some(encrypted), decoded);
}

#[test]
fn pep_rekey() {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let k = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &gy, &mut OsRng);

    let rekeyed = rekey(&encrypted, &k);

    let decrypted = decrypt(&rekeyed, &(k * y));

    assert_eq!(m, decrypted);
}

#[test]
fn pep_reshuffle() {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let s = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &gy, &mut OsRng);

    let reshuffled = reshuffle(&encrypted, &s);

    let decrypted = decrypt(&reshuffled, &y);

    assert_eq!((s * m), decrypted);
}

#[test]
fn pep_rsk() {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let k = ScalarNonZero::random(&mut rng);
    let s = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &gy, &mut OsRng);

    let rsked = rsk(&encrypted, &s, &k);

    let decrypted = decrypt(&rsked, &(k * y));

    assert_eq!((s * m), decrypted);
}

#[test]
fn pep_rekey_from_to() {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let k_from = ScalarNonZero::random(&mut rng);
    let k_to = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &(k_from * gy), &mut OsRng);

    let rekeyed = rekey_from_to(&encrypted, &k_from, &k_to);

    let decrypted = decrypt(&rekeyed, &(k_to * y));

    assert_eq!(m, decrypted);
}

#[test]
fn pep_reshuffle_from_to() {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let s_from = ScalarNonZero::random(&mut rng);
    let s_to = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &gy, &mut OsRng);

    let reshuffled = reshuffle_from_to(&encrypted, &s_from, &s_to);

    let decrypted = decrypt(&reshuffled, &y);

    assert_eq!(s_from.invert() * s_to * m, decrypted);
}

#[test]
fn pep_rsk_from_to() {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let s_from = ScalarNonZero::random(&mut rng);
    let s_to = ScalarNonZero::random(&mut rng);
    let k_from = ScalarNonZero::random(&mut rng);
    let k_to = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &(k_from * gy), &mut OsRng);

    let rsked = rsk_from_to(&encrypted, &s_from, &s_to, &k_from, &k_to);

    let decrypted = decrypt(&rsked, &(k_to * y));

    assert_eq!(s_from.invert() * s_to * m, decrypted);
}

#[test]
fn n_pep_rsk_from_to() {
    let n = 2;
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

    let encrypted = encrypt(&m, &(k_from * gy), &mut OsRng);

    let mut rsked = encrypted.clone();

    // encrypt/decrypt this value
    for i in 0..n {
        rsked = rsk_from_to(&rsked, &s_froms[i], &s_tos[i], &k_froms[i], &k_tos[i]);
    }

    let decrypted = decrypt(&rsked, &(k_to * y));

    assert_eq!(s * m, decrypted);
}

#[test]
fn pep_assumptions() {
    let mut rng = OsRng;
    // secret key of system
    let sk = ScalarNonZero::random(&mut rng);
    // public key of system
    let pk = sk * G;

    // secret key of service provider
    let sj = ScalarNonZero::random(&mut rng);
    let yj = sj * sk;
    assert_eq!(yj * G, sj * pk);

    // Lemma 2: RS(RK(..., k), n) == RK(RS(..., n), k)
    let value = GroupElement::random(&mut rng);
    let encrypted = encrypt(&value, &pk, &mut OsRng);
    let k = ScalarNonZero::random(&mut rng);
    let n = ScalarNonZero::random(&mut rng);
    assert_eq!(
        reshuffle(&rekey(&encrypted, &k), &n),
        rekey(&reshuffle(&encrypted, &n), &k)
    );
    assert_eq!(
        reshuffle(&rekey(&encrypted, &k), &n),
        rsk(&encrypted, &n, &k)
    );
}