//! High-level integration tests for verifiable transcryption.

#![cfg(feature = "verifiable")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::client::{decrypt, encrypt};
use libpep::data::simple::*;
use libpep::data::traits::{VerifiablePseudonymizable, VerifiableRekeyable};
use libpep::factors::contexts::*;
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
#[cfg(not(feature = "elgamal3"))]
use libpep::keys::PublicKey;
use libpep::keys::*;
use libpep::transcryptor::Transcryptor;
use libpep::verifier::Verifier;

#[test]
fn test_verifiable_pseudonymization_simple() {
    let rng = &mut rand::rng();

    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("domain1");
    let domain2 = PseudonymizationDomain::from("domain2");
    let session1 = EncryptionContext::from("session1");
    let session2 = EncryptionContext::from("session2");

    let (pseudonym_session1_public, _) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);
    let (_, pseudonym_session2_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session2, &enc_secret);

    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &pseudonym_session1_public, rng);

    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());
    let info = transcryptor.pseudonymization_info(&domain1, &domain2, &session1, &session2);
    let commitments = Transcryptor::pseudonymization_commitment(&info);

    #[cfg(feature = "elgamal3")]
    let operation_proof = enc_pseudo.verifiable_pseudonymize(&info, rng);
    #[cfg(not(feature = "elgamal3"))]
    let operation_proof =
        enc_pseudo.verifiable_pseudonymize(&info, &pseudonym_session1_public, rng);
    let result = EncryptedPseudonym::from_value(operation_proof.result());

    let verifier = Verifier::new();
    #[cfg(feature = "elgamal3")]
    assert!(verifier.verify_pseudonymization(&enc_pseudo, &result, &operation_proof, &commitments));
    #[cfg(not(feature = "elgamal3"))]
    assert!(verifier.verify_pseudonymization(
        &enc_pseudo,
        &result,
        &operation_proof,
        pseudonym_session1_public.value(),
        &commitments,
    ));

    #[cfg(feature = "elgamal3")]
    let _ = decrypt(&result, &pseudonym_session2_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let _ = decrypt(&result, &pseudonym_session2_secret);
}

#[test]
fn test_verifiable_pseudonym_rekey() {
    let rng = &mut rand::rng();

    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let session1 = EncryptionContext::from("session1");
    let session2 = EncryptionContext::from("session2");

    let (pseudonym_session1_public, pseudonym_session1_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);
    let (_, pseudonym_session2_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session2, &enc_secret);

    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &pseudonym_session1_public, rng);

    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());
    let info = transcryptor.pseudonym_rekey_info(&session1, &session2);
    let commitments = Transcryptor::pseudonym_rekey_commitment(&info);

    let operation_proof = enc_pseudo.verifiable_rekey(&info, rng);
    let result = EncryptedPseudonym::from_value(operation_proof.result(enc_pseudo.value()));

    let verifier = Verifier::new();
    assert!(verifier.verify_pseudonym_rekey(&enc_pseudo, &result, &operation_proof, &commitments));

    #[cfg(feature = "elgamal3")]
    let decrypted =
        decrypt(&result, &pseudonym_session2_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = decrypt(&result, &pseudonym_session2_secret);
    #[cfg(feature = "elgamal3")]
    let original_decrypted =
        decrypt(&enc_pseudo, &pseudonym_session1_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let original_decrypted = decrypt(&enc_pseudo, &pseudonym_session1_secret);
    assert_eq!(decrypted, original_decrypted);
}

#[test]
fn test_verifiable_attribute_rekey() {
    let rng = &mut rand::rng();

    let (_attribute_global_public, attribute_global_secret) = make_attribute_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let session1 = EncryptionContext::from("session1");
    let session2 = EncryptionContext::from("session2");

    let (attribute_session1_public, attribute_session1_secret) =
        make_attribute_session_keys(&attribute_global_secret, &session1, &enc_secret);
    let (_, attribute_session2_secret) =
        make_attribute_session_keys(&attribute_global_secret, &session2, &enc_secret);

    let attr = Attribute::random(rng);
    let enc_attr = encrypt(&attr, &attribute_session1_public, rng);

    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());
    let info = transcryptor.attribute_rekey_info(&session1, &session2);
    let commitments = Transcryptor::attribute_rekey_commitment(&info);

    let operation_proof = enc_attr.verifiable_rekey(&info, rng);
    let result = EncryptedAttribute::from_value(operation_proof.result(enc_attr.value()));

    let verifier = Verifier::new();
    assert!(verifier.verify_attribute_rekey(&enc_attr, &result, &operation_proof, &commitments));

    #[cfg(feature = "elgamal3")]
    let decrypted =
        decrypt(&result, &attribute_session2_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = decrypt(&result, &attribute_session2_secret);
    #[cfg(feature = "elgamal3")]
    let original_decrypted =
        decrypt(&enc_attr, &attribute_session1_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let original_decrypted = decrypt(&enc_attr, &attribute_session1_secret);
    assert_eq!(decrypted, original_decrypted);
}

#[test]
fn test_verifier_cache_pseudonymization() {
    let rng = &mut rand::rng();

    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("domain1");
    let domain2 = PseudonymizationDomain::from("domain2");
    let domain3 = PseudonymizationDomain::from("domain3");
    let session1 = EncryptionContext::from("session1");
    let session2 = EncryptionContext::from("session2");

    let (pseudonym_session1_public, _) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);

    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());
    let info = transcryptor.pseudonymization_info(&domain1, &domain2, &session1, &session2);
    let commitments = Transcryptor::pseudonymization_commitment(&info);

    let mut verifier = Verifier::new();
    let transcryptor_id = String::from("transcryptor1");
    verifier.register_pseudonymization_commitments(
        &transcryptor_id,
        &domain1,
        &domain2,
        &session1,
        &session2,
        commitments,
    );

    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &pseudonym_session1_public, rng);
    #[cfg(feature = "elgamal3")]
    let operation_proof = enc_pseudo.verifiable_pseudonymize(&info, rng);
    #[cfg(not(feature = "elgamal3"))]
    let operation_proof =
        enc_pseudo.verifiable_pseudonymize(&info, &pseudonym_session1_public, rng);
    let result = EncryptedPseudonym::from_value(operation_proof.result());

    #[cfg(feature = "elgamal3")]
    assert!(verifier.verify_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &result,
        &operation_proof,
        &domain1,
        &domain2,
        &session1,
        &session2,
    ));
    #[cfg(not(feature = "elgamal3"))]
    assert!(verifier.verify_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &result,
        &operation_proof,
        pseudonym_session1_public.value(),
        &domain1,
        &domain2,
        &session1,
        &session2,
    ));

    // Wrong transition (different target domain) should not be in the cache.
    #[cfg(feature = "elgamal3")]
    assert!(!verifier.verify_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &result,
        &operation_proof,
        &domain1,
        &domain3,
        &session1,
        &session2,
    ));
    #[cfg(not(feature = "elgamal3"))]
    assert!(!verifier.verify_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &result,
        &operation_proof,
        pseudonym_session1_public.value(),
        &domain1,
        &domain3,
        &session1,
        &session2,
    ));

    verifier.clear_cache();
    assert!(verifier.cache().is_empty());
}
