use rand_core::OsRng;
use libpep::arithmetic::{G, GroupElement, ScalarNonZero};
use libpep::elgamal::{decrypt, encrypt};
use libpep::primitives::*;
use libpep::proved::*;

#[test]
fn pep_factor_verifiers_proof() {
    let mut rng = OsRng;

    let x = ScalarNonZero::random(&mut rng);
    let (verifiers, proof) = FactorVerifiers::new(&x, &mut rng);
    assert!(&proof.verify(&verifiers))
}


#[cfg(not(feature = "elgamal2"))]
#[test]
fn pep_proved_rerandomize() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let s = ScalarNonZero::random(&mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedRerandomize::new(&msg, &s, &mut rng);

    let checked = proved.verified_reconstruct(&msg);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(gm, decrypt(checked.as_ref().unwrap(), &y));
    assert_eq!(&rerandomize(&msg, &s), checked.as_ref().unwrap());
}

#[test]
fn pep_proved_reshuffle() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let n = ScalarNonZero::random(&mut rng);

    let (verifiers, _) = FactorVerifiers::new(&n, &mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedReshuffle::new(&msg, &n, &mut rng);

    let checked = proved.verified_reconstruct(&msg, &verifiers);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(n * gm, decrypt(checked.as_ref().unwrap(), &y));
    assert_eq!(&reshuffle(&msg, &n), checked.as_ref().unwrap());
}

#[test]
fn pep_proved_rekey() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let k = ScalarNonZero::random(&mut rng);

    let (verifiers, _) = FactorVerifiers::new(&k, &mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedRekey::new(&msg, &k, &mut rng);
    let checked = proved.verified_reconstruct(&msg, &verifiers);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(gm, decrypt(checked.as_ref().unwrap(), &(k * y)));
}

#[test]
fn pep_proved_reshuffle_from_to() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let s_from = ScalarNonZero::random(&mut rng);
    let s_to = ScalarNonZero::random(&mut rng);

    let (verifiers_from, _) = FactorVerifiers::new(&s_from, &mut rng);
    let (verifiers_to, _) = FactorVerifiers::new(&s_to, &mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedReshuffleFromTo::new(&msg, &s_from, &s_to, &mut rng);

    let checked = proved.verified_reconstruct(&msg, &verifiers_from, &verifiers_to);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(
        s_from.invert() * s_to * gm,
        decrypt(checked.as_ref().unwrap(), &y)
    );
    assert_eq!(
        &reshuffle_from_to(&msg, &s_from, &s_to),
        checked.as_ref().unwrap()
    );
}
#[test]
fn pep_proved_rekey_from_to() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let k_from = ScalarNonZero::random(&mut rng);
    let k_to = ScalarNonZero::random(&mut rng);

    let (verifiers_from, _) = FactorVerifiers::new(&k_from, &mut rng);
    let (verifiers_to, _) = FactorVerifiers::new(&k_to, &mut rng);

    let msg = encrypt(&gm, &(k_from * gy), &mut rng);

    let proved = ProvedRekeyFromTo::new(&msg, &k_from, &k_to, &mut rng);

    let checked = proved.verified_reconstruct(&msg, &verifiers_from, &verifiers_to);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(gm, decrypt(checked.as_ref().unwrap(), &(k_to * y)));
    assert_eq!(&rekey_from_to(&msg, &k_from, &k_to), checked.as_ref().unwrap());
}
#[test]
fn pep_proved_rsk() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let n = ScalarNonZero::random(&mut rng);
    let k = ScalarNonZero::random(&mut rng);

    let (verifiers_n, _) = FactorVerifiers::new(&n, &mut rng);
    let (verifiers_k, _) = FactorVerifiers::new(&k, &mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedRSK::new(&msg, &n, &k, &mut rng);

    let checked = proved.verified_reconstruct(&msg, &verifiers_n, &verifiers_k);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(n * gm, decrypt(checked.as_ref().unwrap(), &(k * y)));
    assert_eq!(&rsk(&msg, &n, &k), checked.as_ref().unwrap());
}
#[test]
fn pep_proved_rsk_from_to() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let s_from = ScalarNonZero::random(&mut rng);
    let s_to = ScalarNonZero::random(&mut rng);
    let k_from = ScalarNonZero::random(&mut rng);
    let k_to = ScalarNonZero::random(&mut rng);

    let (verifiers_s_from, _) = FactorVerifiers::new(&s_from, &mut rng);
    let (verifiers_s_to, _) = FactorVerifiers::new(&s_to, &mut rng);
    let (verifiers_k_from, _) = FactorVerifiers::new(&k_from, &mut rng);
    let (verifiers_k_to, _) = FactorVerifiers::new(&k_to, &mut rng);

    let msg = encrypt(&gm, &(k_from * gy), &mut rng);

    let proved = ProvedRSKFromTo::new(&msg, &s_from, &s_to, &k_from, &k_to, &mut rng);

    let checked = proved.verified_reconstruct(
        &msg,
        &verifiers_s_from,
        &verifiers_s_to,
        &verifiers_k_from,
        &verifiers_k_to,
    );

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(
        s_from.invert() * s_to * gm,
        decrypt(checked.as_ref().unwrap(), &(k_to * y))
    );
    assert_eq!(
        &rsk_from_to(&msg, &s_from, &s_to, &k_from, &k_to),
        checked.as_ref().unwrap()
    );
}
