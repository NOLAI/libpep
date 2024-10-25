use libpep::arithmetic::{GroupElement, ScalarNonZero, G};
use libpep::zkps::{create_proof, sign, sign_unlinkable, verify, verify_proof};
use rand_core::OsRng;

#[test]
fn elgamal_signature() {
    let mut rng = OsRng;
    // secret key
    let s = ScalarNonZero::random(&mut rng);
    let s2 = ScalarNonZero::random(&mut rng);
    // public key
    let gp = s * G;

    let v = GroupElement::random(&mut rng);
    let mut signature = sign(&v, &s, &mut rng);
    assert!(verify(&v, &signature, &gp));

    signature = sign(&v, &s2, &mut rng);
    assert!(!verify(&v, &signature, &gp));
}

#[test]
fn pep_schnorr_basic_offline() {
    let mut rng = OsRng;
    // given a secret a and public M, proof that a certain triplet (A, M, N) is actually calculated by (a*G, M, a * M)
    // using Fiat-Shamir transform

    // prover
    let a = ScalarNonZero::random(&mut rng);
    let gm = GroupElement::random(&mut rng);

    let (ga, p) = create_proof(&a, &gm, &mut rng);
    assert_eq!(a * gm, *p);

    // verifier
    assert!(verify_proof(&ga, &gm, &p));
}

#[test]
fn elgamal_signature_unlinkable() {
    let mut rng = OsRng;
    // secret key
    let s = ScalarNonZero::random(&mut rng);
    // public key
    let gp = s * G;

    let v = GroupElement::random(&mut rng);
    let sig1 = sign_unlinkable(&v, &s);
    assert!(verify(&v, &sig1, &gp));

    let sig2 = sign_unlinkable(&v, &s);
    assert!(verify(&v, &sig2, &gp));
    assert_eq!(sig1.encode_hex(), sig2.encode_hex());
}
