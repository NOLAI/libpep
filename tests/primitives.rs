use libpep::internal::arithmetic::*;
use libpep::low_level::elgamal::*;
use libpep::low_level::primitives::*;
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

    assert_eq!(s * m, decrypted);
}

#[test]
fn pep_rsk() {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let s = ScalarNonZero::random(&mut rng);
    let k = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &gy, &mut OsRng);

    let rsked = rsk(&encrypted, &s, &k);

    assert_eq!(rsked, rekey(&reshuffle(&encrypted, &s), &k));

    let decrypted = decrypt(&rsked, &(k * y));

    assert_eq!(s * m, decrypted);
}

#[test]
fn pep_rrsk() {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let r = ScalarNonZero::random(&mut rng);
    let s = ScalarNonZero::random(&mut rng);
    let k = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &gy, &mut OsRng);

    #[cfg(feature = "elgamal3")]
    let rrsked = rrsk(&encrypted, &r, &s, &k);
    #[cfg(not(feature = "elgamal3"))]
    let rrsked = rrsk(&encrypted, &gy, &r, &s, &k);

    #[cfg(feature = "elgamal3")]
    assert_eq!(
        rrsked,
        rekey(&reshuffle(&rerandomize(&encrypted, &r), &s), &k)
    );
    #[cfg(not(feature = "elgamal3"))]
    assert_eq!(
        rrsked,
        rekey(&reshuffle(&rerandomize(&encrypted, &gy, &r), &s), &k)
    );

    let decrypted = decrypt(&rrsked, &(k * y));

    assert_eq!(s * m, decrypted);
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

    let rekeyed = rekey2(&encrypted, &k_from, &k_to);

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

    let reshuffled = reshuffle2(&encrypted, &s_from, &s_to);

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

    let rsked = rsk2(&encrypted, &s_from, &s_to, &k_from, &k_to);

    let decrypted = decrypt(&rsked, &(k_to * y));

    assert_eq!(s_from.invert() * s_to * m, decrypted);
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
