//! Tests for verifiable transcryption operations.

#![cfg(feature = "verifiable")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::client::{decrypt, encrypt};
use libpep::data::simple::*;
use libpep::data::traits::{VerifiablePseudonymizable, VerifiableRekeyable, VerifiableTranscryptable};
use libpep::factors::contexts::*;
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use libpep::keys::*;
use libpep::transcryptor::Transcryptor;
use libpep::verifier::Verifier;

#[test]
fn test_verifiable_pseudonymization_simple() {
    let rng = &mut rand::rng();

    // Setup
    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("domain1");
    let domain2 = PseudonymizationDomain::from("domain2");
    let session1 = EncryptionContext::from("session1");
    let session2 = EncryptionContext::from("session2");

    let (pseudonym_session1_public, _pseudonym_session1_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);
    let (_pseudonym_session2_public, pseudonym_session2_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session2, &enc_secret);

    // Client: Encrypt a pseudonym
    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &pseudonym_session1_public, rng);

    // Transcryptor: Generate secret info and public commitments
    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());
    let info = transcryptor.pseudonymization_info(&domain1, &domain2, &session1, &session2);
    let commitments = Transcryptor::pseudonymization_commitments(&info, rng);

    // Transcryptor: Perform verifiable pseudonymization
    let operation_proof = enc_pseudo.verifiable_pseudonymize(&info, rng);
    let factors_proof = Transcryptor::pseudonymization_factors_proof(&info, rng);
    let result = EncryptedPseudonym::from_value(operation_proof.result());

    // Verifier: Verify commitments and operation (uses only public data)
    let verifier = Verifier::new();
    assert!(verifier.verify_pseudonymization_commitments(&commitments));
    assert!(verifier.verify_pseudonymization(
        &enc_pseudo,
        &result,
        &operation_proof,
        &factors_proof,
        &commitments,
    ));

    // Client: Decrypt result
    #[cfg(feature = "elgamal3")]
    let _decrypted =
        decrypt(&result, &pseudonym_session2_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let _decrypted = decrypt(&result, &pseudonym_session2_secret);
}

#[test]
fn test_verifiable_pseudonym_rekey() {
    let rng = &mut rand::rng();

    // Setup
    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let session1 = EncryptionContext::from("session1");
    let session2 = EncryptionContext::from("session2");

    let (pseudonym_session1_public, pseudonym_session1_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);
    let (_pseudonym_session2_public, pseudonym_session2_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session2, &enc_secret);

    // Client: Encrypt a pseudonym
    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &pseudonym_session1_public, rng);

    // Transcryptor: Generate secret rekey info and public commitments
    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());
    let info = transcryptor.pseudonym_rekey_info(&session1, &session2);
    let commitments = Transcryptor::pseudonym_rekey_commitments(&info, rng);

    // Transcryptor: Perform verifiable rekey
    let operation_proof = enc_pseudo.verifiable_rekey(&info, rng);
    let result = EncryptedPseudonym::from_value(operation_proof.result(&enc_pseudo.value()));

    // Verifier: Verify commitments and operation
    let verifier = Verifier::new();
    assert!(verifier.verify_rekey_commitments(&commitments));
    assert!(verifier.verify_pseudonym_rekey(
        &enc_pseudo,
        &result,
        &operation_proof,
        &commitments,
    ));

    // Client: Verify result decrypts correctly (same plaintext, different session)
    #[cfg(feature = "elgamal3")]
    let decrypted = decrypt(&result, &pseudonym_session2_secret).expect("decryption should succeed");
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

    // Setup
    let (_attribute_global_public, attribute_global_secret) = make_attribute_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let session1 = EncryptionContext::from("session1");
    let session2 = EncryptionContext::from("session2");

    let (attribute_session1_public, attribute_session1_secret) =
        make_attribute_session_keys(&attribute_global_secret, &session1, &enc_secret);
    let (_attribute_session2_public, attribute_session2_secret) =
        make_attribute_session_keys(&attribute_global_secret, &session2, &enc_secret);

    // Client: Encrypt an attribute
    let attr = Attribute::random(rng);
    let enc_attr = encrypt(&attr, &attribute_session1_public, rng);

    // Transcryptor: Generate secret rekey info and public commitments
    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());
    let info = transcryptor.attribute_rekey_info(&session1, &session2);
    let commitments = Transcryptor::attribute_rekey_commitments(&info, rng);

    // Transcryptor: Perform verifiable rekey
    let operation_proof = enc_attr.verifiable_rekey(&info, rng);
    let result = EncryptedAttribute::from_value(operation_proof.result(&enc_attr.value()));

    // Verifier: Verify commitments and operation
    let verifier = Verifier::new();
    assert!(verifier.verify_rekey_commitments(&commitments));
    assert!(verifier.verify_attribute_rekey(
        &enc_attr,
        &result,
        &operation_proof,
        &commitments,
    ));

    // Client: Verify result decrypts correctly
    #[cfg(feature = "elgamal3")]
    let decrypted = decrypt(&result, &attribute_session2_secret).expect("decryption should succeed");
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
fn test_verification_fails_with_wrong_commitments() {
    let rng = &mut rand::rng();

    // Setup
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

    // Client: Encrypt a pseudonym
    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &pseudonym_session1_public, rng);

    // Transcryptor: Generate correct and wrong commitments
    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());
    let info = transcryptor.pseudonymization_info(&domain1, &domain2, &session1, &session2);
    let commitments = Transcryptor::pseudonymization_commitments(&info, rng);

    let wrong_info = transcryptor.pseudonymization_info(&domain1, &domain3, &session1, &session2);
    let wrong_commitments = Transcryptor::pseudonymization_commitments(&wrong_info, rng);

    // Transcryptor: Perform operation with correct info
    let operation_proof = enc_pseudo.verifiable_pseudonymize(&info, rng);
    let factors_proof = Transcryptor::pseudonymization_factors_proof(&info, rng);
    let result = EncryptedPseudonym::from_value(operation_proof.result());

    // Verifier: Create mixed (incorrect) commitments
    use libpep::factors::ProvedPseudonymizationCommitments;
    let mixed_commitments = ProvedPseudonymizationCommitments {
        reshuffle_commitments: commitments.reshuffle_commitments,
        reshuffle_proof: wrong_commitments.reshuffle_proof,
        rekey_commitments: commitments.rekey_commitments,
        rekey_proof: wrong_commitments.rekey_proof,
    };

    // Verifier: Verification with mixed commitments should fail
    let verifier = Verifier::new();
    assert!(!verifier.verify_pseudonymization_commitments(&mixed_commitments));

    // Verifier: Verification with correct commitments should succeed
    assert!(verifier.verify_pseudonymization(
        &enc_pseudo,
        &result,
        &operation_proof,
        &factors_proof,
        &commitments,
    ));
}

#[test]
fn test_transcryptor_generic_verifiable_methods() {
    let rng = &mut rand::rng();

    // Setup
    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("domain1");
    let domain2 = PseudonymizationDomain::from("domain2");
    let session1 = EncryptionContext::from("session1");
    let session2 = EncryptionContext::from("session2");

    let (pseudonym_session1_public, _) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);

    // Client: Encrypt a pseudonym
    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &pseudonym_session1_public, rng);

    // Transcryptor: Generate info and commitments
    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());
    let info = transcryptor.pseudonymization_info(&domain1, &domain2, &session1, &session2);
    let commitments = Transcryptor::pseudonymization_commitments(&info, rng);

    // Transcryptor: Use generic verifiable_pseudonymize method
    let operation_proof = transcryptor.verifiable_pseudonymize(&enc_pseudo, &info, rng);
    let factors_proof = Transcryptor::pseudonymization_factors_proof(&info, rng);
    let result = EncryptedPseudonym::from_value(operation_proof.result());

    // Verifier: Verify commitments and operation
    let verifier = Verifier::new();
    assert!(verifier.verify_pseudonymization_commitments(&commitments));
    assert!(verifier.verify_pseudonymization(
        &enc_pseudo,
        &result,
        &operation_proof,
        &factors_proof,
        &commitments,
    ));
}

#[test]
fn test_verifiable_long_pseudonym_pseudonymization() {
    let rng = &mut rand::rng();

    // Setup keys and secrets
    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());
    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());

    let domain1 = PseudonymizationDomain::from("domain1");
    let domain2 = PseudonymizationDomain::from("domain2");
    let session1 = EncryptionContext::from("session1");
    let session2 = EncryptionContext::from("session2");

    let (pseudonym_session1_public, _) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);
    let (_, pseudonym_session2_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session2, &enc_secret);

    // Create and encrypt a long pseudonym (multi-block)
    use libpep::data::long::LongPseudonym;

    let data = b"This is a long pseudonym that spans multiple blocks!";
    let long_pseudo = LongPseudonym::from_bytes_padded(data);
    let enc_long_pseudo = encrypt(&long_pseudo, &pseudonym_session1_public, rng);

    // Generate secret info and public commitments
    let info = transcryptor.pseudonymization_info(&domain1, &domain2, &session1, &session2);
    let commitments = Transcryptor::pseudonymization_commitments(&info, rng);

    // Perform verifiable pseudonymization
    let operation_proofs = enc_long_pseudo.verifiable_pseudonymize(&info, rng);
    let factors_proof = Transcryptor::pseudonymization_factors_proof(&info, rng);

    // Extract results from proofs
    use libpep::data::long::LongEncryptedPseudonym;
    let result = LongEncryptedPseudonym(
        operation_proofs
            .iter()
            .map(|proof| EncryptedPseudonym::from_value(proof.result()))
            .collect(),
    );

    // Verify
    let verifier = Verifier::new();
    assert!(verifier.verify_pseudonymization_commitments(&commitments));
    assert!(verifier.verify_pseudonymization_long(
        &enc_long_pseudo.0,
        &result.0,
        &operation_proofs,
        &factors_proof,
        &commitments,
    ));

    // Verify result decrypts correctly
    #[cfg(feature = "elgamal3")]
    let _decrypted = decrypt(&result, &pseudonym_session2_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let _decrypted = decrypt(&result, &pseudonym_session2_secret);

    // Note: After pseudonymization (domain change), the pseudonym is no longer in the
    // original format and cannot be converted back to the original bytes.
    // The important thing is that the operation is verifiable and decryption succeeds.
}

#[test]
fn test_verifiable_record_transcryption() {
    let rng = &mut rand::rng();

    // Setup
    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let (_attribute_global_public, attribute_global_secret) = make_attribute_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());
    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());

    let domain1 = PseudonymizationDomain::from("domain1");
    let domain2 = PseudonymizationDomain::from("domain2");
    let session1 = EncryptionContext::from("session1");
    let session2 = EncryptionContext::from("session2");

    // Create session keys
    let (pseudonym_session1_public, _) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);
    let (attribute_session1_public, _) =
        make_attribute_session_keys(&attribute_global_secret, &session1, &enc_secret);
    let (_, pseudonym_session2_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session2, &enc_secret);
    let (_, attribute_session2_secret) =
        make_attribute_session_keys(&attribute_global_secret, &session2, &enc_secret);

    let session1_keys = libpep::keys::SessionKeys {
        pseudonym: libpep::keys::PseudonymSessionKeys {
            public: pseudonym_session1_public,
            secret: pseudonym_session2_secret.clone(),
        },
        attribute: libpep::keys::AttributeSessionKeys {
            public: attribute_session1_public,
            secret: attribute_session2_secret.clone(),
        },
    };

    // Create a record with pseudonyms and attributes
    use libpep::data::records::{EncryptedRecord, Record};
    let record = Record::new(
        vec![Pseudonym::random(rng), Pseudonym::random(rng)],
        vec![Attribute::random(rng), Attribute::random(rng), Attribute::random(rng)],
    );

    let enc_record = encrypt(&record, &session1_keys, rng);

    // Generate transcryption info and commitments
    let transcryption_info = transcryptor.transcryption_info(&domain1, &domain2, &session1, &session2);
    let pseudonym_commitments = Transcryptor::pseudonymization_commitments(&transcryption_info.pseudonym, rng);
    let attribute_commitments = Transcryptor::attribute_rekey_commitments(&transcryption_info.attribute, rng);

    // Perform verifiable transcryption
    use libpep::data::traits::VerifiableTranscryptable;
    let proof = enc_record.verifiable_transcrypt(&transcryption_info, rng);

    // Extract result from proof
    let result = EncryptedRecord::new(
        proof.pseudonym_operation_proofs.iter()
            .map(|p| EncryptedPseudonym::from_value(p.result()))
            .collect(),
        proof.attribute_operation_proofs.iter()
            .zip(enc_record.attributes.iter())
            .map(|(p, orig)| EncryptedAttribute::from_value(p.result(orig.value())))
            .collect(),
    );

    // Verify
    let verifier = Verifier::new();
    assert!(verifier.verify_pseudonymization_commitments(&pseudonym_commitments));
    assert!(verifier.verify_rekey_commitments(&attribute_commitments));
    assert!(verifier.verify_record_transcryption(
        &enc_record,
        &result,
        &proof,
        &pseudonym_commitments,
        &attribute_commitments,
    ));

    // Verify the record can be decrypted (though we can't verify correctness without proper keys)
    let session2_keys = libpep::keys::SessionKeys {
        pseudonym: libpep::keys::PseudonymSessionKeys {
            public: pseudonym_session1_public,
            secret: pseudonym_session2_secret,
        },
        attribute: libpep::keys::AttributeSessionKeys {
            public: attribute_session1_public,
            secret: attribute_session2_secret,
        },
    };

    #[cfg(feature = "elgamal3")]
    let _decrypted = decrypt(&result, &session2_keys).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let _decrypted = decrypt(&result, &session2_keys);
}

#[test]
fn test_verifier_cache() {
    let rng = &mut rand::rng();

    // Setup
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

    // Transcryptor: Generate info and commitments
    let transcryptor = Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());
    let info = transcryptor.pseudonymization_info(&domain1, &domain2, &session1, &session2);
    let commitments = Transcryptor::pseudonymization_commitments(&info, rng);

    // Verifier: Register commitments in cache
    let mut verifier = Verifier::new();
    assert!(verifier.cache().is_empty());
    assert_eq!(verifier.cache().total_count(), 0);

    let transcryptor_id = String::from("transcryptor1");
    verifier.register_pseudonymization_commitments(
        &transcryptor_id, &domain1, &domain2, &session1, &session2, commitments
    );

    assert!(!verifier.cache().is_empty());
    assert!(verifier.cache().total_count() >= 2);
    assert!(verifier.cache().total_count() <= 4);

    // Verifier: Check cache contents
    assert!(verifier.has_reshuffle_commitments(&transcryptor_id, &domain1));
    assert!(verifier.has_pseudonym_rekey_commitments(&transcryptor_id, &session1));
    assert!(!verifier.has_reshuffle_commitments(&transcryptor_id, &domain3));

    // Client: Encrypt data
    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &pseudonym_session1_public, rng);

    // Transcryptor: Perform operation
    let operation_proof = enc_pseudo.verifiable_pseudonymize(&info, rng);
    let factors_proof = Transcryptor::pseudonymization_factors_proof(&info, rng);
    let result = EncryptedPseudonym::from_value(operation_proof.result());

    // Verifier: Verify using cached commitments
    assert!(verifier.verify_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &result,
        &operation_proof,
        &factors_proof,
        &domain1,
        &domain2,
        &session1,
        &session2,
    ));

    // Verifier: Verification with wrong domains should fail (not in cache)
    assert!(!verifier.verify_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &result,
        &operation_proof,
        &factors_proof,
        &domain1,
        &domain3,
        &session1,
        &session2,
    ));

    // Verifier: Clear cache
    verifier.clear_cache();
    assert!(verifier.cache().is_empty());
    assert_eq!(verifier.cache().total_count(), 0);
}


#[test]
fn test_two_transcryptors_with_verification() {
    // Demonstrates distributed transcryption with two transcryptors performing
    // commutative partial transformations on the same domain transition (A→B).

    use libpep::client::distributed::{make_attribute_session_key, make_pseudonym_session_key};
    use libpep::data::records::EncryptedRecord;
    use libpep::keys::distribution::make_distributed_global_keys;
    use libpep::transcryptor::DistributedTranscryptor;

    let rng = &mut rand::rng();

    let enc_secret1 = EncryptionSecret::from("encryption1".into());
    let enc_secret2 = EncryptionSecret::from("encryption2".into());

    // Setup distributed system with 2 transcryptors
    let (_global_public_keys, blinded_global_keys, blinding_factors) =
        make_distributed_global_keys(2, rng);

    let transcryptor1 = DistributedTranscryptor::new(
        PseudonymizationSecret::from("secret1".into()),
        enc_secret1.clone(),
        blinding_factors[0],
    );
    let transcryptor2 = DistributedTranscryptor::new(
        PseudonymizationSecret::from("secret2".into()),
        enc_secret2.clone(),
        blinding_factors[1],
    );

    let domain_a = PseudonymizationDomain::from("domain_a");
    let domain_b = PseudonymizationDomain::from("domain_b");
    let session1 = EncryptionContext::from("session1");
    let session2 = EncryptionContext::from("session2");

    // Setup: Reconstruct session1 keys from both transcryptors' shares
    let session1_shares = vec![
        transcryptor1.session_key_shares(&session1),
        transcryptor2.session_key_shares(&session1),
    ];

    let (pseudonym_session1_public, _pseudonym_session1_secret) =
        make_pseudonym_session_key(
            blinded_global_keys.pseudonym,
            &session1_shares.iter().map(|s| s.pseudonym).collect::<Vec<_>>(),
        );
    let (attribute_session1_public, _attribute_session1_secret) =
        make_attribute_session_key(
            blinded_global_keys.attribute,
            &session1_shares.iter().map(|s| s.attribute).collect::<Vec<_>>(),
        );

    // Client: Encrypt data and create record
    let pseudo = Pseudonym::random(rng);
    let attr = Attribute::random(rng);
    let enc_pseudo = encrypt(&pseudo, &pseudonym_session1_public, rng);
    let enc_attr = encrypt(&attr, &attribute_session1_public, rng);

    let record = EncryptedRecord {
        pseudonyms: vec![enc_pseudo],
        attributes: vec![enc_attr],
    };

    // Transcryptor1: Generate commitments and perform partial transformation
    let info1 = transcryptor1.transcryption_info(&domain_a, &domain_b, &session1, &session2);
    let pseudonym_commitments1 =
        Transcryptor::pseudonymization_commitments(&info1.pseudonym, rng);
    let attribute_commitments1 =
        Transcryptor::attribute_rekey_commitments(&info1.attribute, rng);

    let proof1 = record.verifiable_transcrypt(&info1, rng);
    let result1 = EncryptedRecord::new(
        proof1
            .pseudonym_operation_proofs
            .iter()
            .map(|p| EncryptedPseudonym::from_value(p.result()))
            .collect(),
        proof1
            .attribute_operation_proofs
            .iter()
            .zip(record.attributes.iter())
            .map(|(p, orig)| EncryptedAttribute::from_value(p.result(orig.value())))
            .collect(),
    );

    // Verifier: Register and verify transcryptor1's work
    let mut verifier = Verifier::new();
    let transcryptor1_id = String::from("transcryptor1");

    verifier.register_pseudonymization_commitments(
        &transcryptor1_id,
        &domain_a,
        &domain_b,
        &session1,
        &session2,
        pseudonym_commitments1,
    );
    verifier.register_attribute_rekey_commitments(&transcryptor1_id, &session1, &session2, attribute_commitments1);

    assert!(verifier.verify_pseudonymization_commitments(&pseudonym_commitments1));
    assert!(verifier.verify_rekey_commitments(&attribute_commitments1));
    assert!(verifier.verify_record_transcryption(
        &record,
        &result1,
        &proof1,
        &pseudonym_commitments1,
        &attribute_commitments1,
    ));

    // Transcryptor2: Generate commitments and perform another partial transformation
    let info2 = transcryptor2.transcryption_info(&domain_a, &domain_b, &session1, &session2);
    let pseudonym_commitments2 =
        Transcryptor::pseudonymization_commitments(&info2.pseudonym, rng);
    let attribute_commitments2 =
        Transcryptor::attribute_rekey_commitments(&info2.attribute, rng);

    let proof2 = result1.verifiable_transcrypt(&info2, rng);
    let result2 = EncryptedRecord::new(
        proof2
            .pseudonym_operation_proofs
            .iter()
            .map(|p| EncryptedPseudonym::from_value(p.result()))
            .collect(),
        proof2
            .attribute_operation_proofs
            .iter()
            .zip(result1.attributes.iter())
            .map(|(p, orig)| EncryptedAttribute::from_value(p.result(orig.value())))
            .collect(),
    );

    // Verifier: Verify transcryptor2's work
    let verifier2 = Verifier::new();
    assert!(verifier2.verify_pseudonymization_commitments(&pseudonym_commitments2));
    assert!(verifier2.verify_rekey_commitments(&attribute_commitments2));
    assert!(verifier2.verify_record_transcryption(
        &result1,
        &result2,
        &proof2,
        &pseudonym_commitments2,
        &attribute_commitments2,
    ));

    // Client: Decrypt final result using reconstructed session2 keys
    #[cfg(feature = "elgamal3")]
    {
        let session2_shares = vec![
            transcryptor1.session_key_shares(&session2),
            transcryptor2.session_key_shares(&session2),
        ];

        let (_pseudonym_session2_public, pseudonym_session2_secret) =
            make_pseudonym_session_key(
                blinded_global_keys.pseudonym,
                &session2_shares.iter().map(|s| s.pseudonym).collect::<Vec<_>>(),
            );
        let (_attribute_session2_public, attribute_session2_secret) =
            make_attribute_session_key(
                blinded_global_keys.attribute,
                &session2_shares.iter().map(|s| s.attribute).collect::<Vec<_>>(),
            );

        let _final_pseudo =
            decrypt(&result2.pseudonyms[0], &pseudonym_session2_secret).expect("decrypt final pseudonym failed");
        let final_attr =
            decrypt(&result2.attributes[0], &attribute_session2_secret).expect("decrypt final attribute failed");
        assert_eq!(final_attr, attr);
    }
}

