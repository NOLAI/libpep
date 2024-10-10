use libpep::arithmetic::{GroupElement, ScalarNonZero, G};
use libpep::elgamal::{decrypt, encrypt};
use libpep::primitives::*;
use libpep::proved::*;
use rand_core::OsRng;

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
    let r = ScalarNonZero::random(&mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedRerandomize::new(&msg, &r, &mut rng);

    let checked = proved.verified_reconstruct(&msg);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(gm, decrypt(checked.as_ref().unwrap(), &y));
    assert_eq!(&rerandomize(&msg, &r), checked.as_ref().unwrap());
}

#[test]
fn pep_proved_reshuffle() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);

    let s = ScalarNonZero::random(&mut rng);
    let (verifiers, proved_n) = PseudonymizationFactorVerifiers::new(&s, &mut rng);
    assert!(proved_n.verify(&verifiers));

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedReshuffle::new(&msg, &s, &mut rng);

    let checked = proved.verified_reconstruct(&msg, &verifiers);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(s * gm, decrypt(checked.as_ref().unwrap(), &y));
    assert_eq!(&reshuffle(&msg, &s), checked.as_ref().unwrap());
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
    let (verifiers, proved_k) = RekeyFactorVerifiers::new(&k, &mut rng);
    assert!(proved_k.verify(&verifiers));

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedRekey::new(&msg, &k, &mut rng);
    let checked = proved.verified_reconstruct(&msg, &verifiers);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(gm, decrypt(checked.as_ref().unwrap(), &(k * y)));
}
#[test]
fn pep_proved_rsk() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);

    let s = ScalarNonZero::random(&mut rng);
    let k = ScalarNonZero::random(&mut rng);

    let (verifiers_s, proved_s) = PseudonymizationFactorVerifiers::new(&s, &mut rng);
    let (verifiers_k, proved_k) = RekeyFactorVerifiers::new(&k, &mut rng);
    assert!(proved_s.verify(&verifiers_s));
    assert!(proved_k.verify(&verifiers_k));

    let rsk_proof = RSKFactorsProof::new(&s, &k, &mut rng);
    assert!(rsk_proof.verify(&verifiers_s, &verifiers_k));

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedRSK::new(&msg, &s, &k, &mut rng);

    let checked = proved.verified_reconstruct(&msg, &rsk_proof, &verifiers_s, &verifiers_k);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(s * gm, decrypt(checked.as_ref().unwrap(), &(k * y)));
    assert_eq!(&rsk(&msg, &s, &k), checked.as_ref().unwrap());
}

#[test]
fn pep_proved_reshuffle2() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);

    let s_from = ScalarNonZero::random(&mut rng);
    let s_to = ScalarNonZero::random(&mut rng);

    let (verifiers_from, proved_s_from) = PseudonymizationFactorVerifiers::new(&s_from, &mut rng);
    let (verifiers_to, proved_s_to) = PseudonymizationFactorVerifiers::new(&s_to, &mut rng);
    assert!(proved_s_from.verify(&verifiers_from));
    assert!(proved_s_to.verify(&verifiers_to));

    let reshuffle_proof = Reshuffle2FactorsProof::new(&s_from, &s_to, &mut rng);
    assert!(reshuffle_proof.verify(&verifiers_from, &verifiers_to));

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedReshuffle::new2(&msg, &s_from, &s_to, &mut rng);

    let checked = proved.verified_reconstruct2(&msg, &reshuffle_proof);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(
        s_from.invert() * s_to * gm,
        decrypt(checked.as_ref().unwrap(), &y)
    );
    assert_eq!(&reshuffle2(&msg, &s_from, &s_to), checked.as_ref().unwrap());
}
#[test]
fn pep_proved_rekey2() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);

    let k_from = ScalarNonZero::random(&mut rng);
    let k_to = ScalarNonZero::random(&mut rng);

    let (verifiers_from, proved_k_from) = RekeyFactorVerifiers::new(&k_from, &mut rng);
    let (verifiers_to, proved_k_to) = RekeyFactorVerifiers::new(&k_to, &mut rng);
    assert!(proved_k_from.verify(&verifiers_from));
    assert!(proved_k_to.verify(&verifiers_to));

    let rekey_proof = Rekey2FactorsProof::new(&k_from, &k_to, &mut rng);
    assert!(rekey_proof.verify(&verifiers_from, &verifiers_to));

    let msg = encrypt(&gm, &(k_from * gy), &mut rng);

    let proved = ProvedRekey::new2(&msg, &k_from, &k_to, &mut rng);

    let checked = proved.verified_reconstruct2(&msg, &rekey_proof);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(gm, decrypt(checked.as_ref().unwrap(), &(k_to * y)));
    assert_eq!(&rekey2(&msg, &k_from, &k_to), checked.as_ref().unwrap());
}
#[test]
fn pep_proved_rsk2() {
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

    let (verifiers_s_from, proved_s_from) = PseudonymizationFactorVerifiers::new(&s_from, &mut rng);
    let (verifiers_s_to, proved_s_to) = PseudonymizationFactorVerifiers::new(&s_to, &mut rng);
    let (verifiers_k_from, proved_k_from) = RekeyFactorVerifiers::new(&k_from, &mut rng);
    let (verifiers_k_to, proved_k_to) = RekeyFactorVerifiers::new(&k_to, &mut rng);

    assert!(proved_s_from.verify(&verifiers_s_from));
    assert!(proved_s_to.verify(&verifiers_s_to));
    assert!(proved_k_from.verify(&verifiers_k_from));
    assert!(proved_k_to.verify(&verifiers_k_to));

    let reshuffle_proof = Reshuffle2FactorsProof::new(&s_from, &s_to, &mut rng);
    let rekey_proof = Rekey2FactorsProof::new(&k_from, &k_to, &mut rng);
    let rsk_proof = RSK2FactorsProof::new(&s_from, &s_to, &k_from, &k_to, &mut rng);

    assert!(reshuffle_proof.verify(&verifiers_s_from, &verifiers_s_to));
    assert!(rekey_proof.verify(&verifiers_k_from, &verifiers_k_to));
    assert!(rsk_proof.verify(&reshuffle_proof, &rekey_proof));

    let msg = encrypt(&gm, &(k_from * gy), &mut rng);

    let proved = ProvedRSK::new2(&msg, &s_from, &s_to, &k_from, &k_to, &mut rng);

    let checked = proved.verified_reconstruct2(&msg, &rsk_proof);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(
        s_from.invert() * s_to * gm,
        decrypt(checked.as_ref().unwrap(), &(k_to * y))
    );
    assert_eq!(
        &rsk2(&msg, &s_from, &s_to, &k_from, &k_to),
        checked.as_ref().unwrap()
    );
}
