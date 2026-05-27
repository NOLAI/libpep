//! High-level integration tests for verifiable transcryption.

#![cfg(feature = "verifiable")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::client::{decrypt, encrypt};
use libpep::data::simple::*;
use libpep::data::verifiable::traits::{VerifiablePseudonymizable, VerifiableRekeyable};
use libpep::factors::contexts::*;
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
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

    let verifier = Verifier::new();
    #[cfg(feature = "elgamal3")]
    let result: EncryptedPseudonym = verifier
        .verified_reconstruct_pseudonymization(&enc_pseudo, &operation_proof, &commitments)
        .expect("verify");
    #[cfg(not(feature = "elgamal3"))]
    let result: EncryptedPseudonym = verifier
        .verified_reconstruct_pseudonymization(
            &enc_pseudo,
            &operation_proof,
            &pseudonym_session1_public,
            &commitments,
        )
        .expect("verify");

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

    let verifier = Verifier::new();
    let result: EncryptedPseudonym = verifier
        .verified_reconstruct_rekey(&enc_pseudo, &operation_proof, &commitments)
        .expect("verify");

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

    let verifier = Verifier::new();
    let result: EncryptedAttribute = verifier
        .verified_reconstruct_rekey(&enc_attr, &operation_proof, &commitments)
        .expect("verify");

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
    verifier
        .register_pseudonymization_commitments(
            &transcryptor_id,
            &domain1,
            &domain2,
            &session1,
            &session2,
            commitments,
        )
        .expect("commitments should not be weak");

    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &pseudonym_session1_public, rng);
    #[cfg(feature = "elgamal3")]
    let operation_proof = enc_pseudo.verifiable_pseudonymize(&info, rng);
    #[cfg(not(feature = "elgamal3"))]
    let operation_proof =
        enc_pseudo.verifiable_pseudonymize(&info, &pseudonym_session1_public, rng);

    #[cfg(feature = "elgamal3")]
    let result: Option<EncryptedPseudonym> = verifier.verified_reconstruct_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &operation_proof,
        &domain1,
        &domain2,
        &session1,
        &session2,
    );
    #[cfg(not(feature = "elgamal3"))]
    let result: Option<EncryptedPseudonym> = verifier.verified_reconstruct_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &operation_proof,
        &pseudonym_session1_public,
        &domain1,
        &domain2,
        &session1,
        &session2,
    );
    assert!(result.is_some());

    // Wrong transition (different target domain) should not be in the cache.
    #[cfg(feature = "elgamal3")]
    let bad: Option<EncryptedPseudonym> = verifier.verified_reconstruct_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &operation_proof,
        &domain1,
        &domain3,
        &session1,
        &session2,
    );
    #[cfg(not(feature = "elgamal3"))]
    let bad: Option<EncryptedPseudonym> = verifier.verified_reconstruct_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &operation_proof,
        &pseudonym_session1_public,
        &domain1,
        &domain3,
        &session1,
        &session2,
    );
    assert!(bad.is_none());

    verifier.clear_cache();
    assert!(verifier.cache().is_empty());
}

/// Distributed verifiable batch transcryption: client A → 3 transcryptors → client B.
///
/// Mirrors the non-verifiable `n_pep_batch_distributed` scenario in
/// `tests/distributed.rs`, but every transcryptor produces a hoisted
/// [`VerifiableRRSKBatch`] proof and *the next transcryptor verifies the
/// previous one's proof* before applying its own transcryption.
#[cfg(all(feature = "batch", feature = "batch-pk", not(feature = "elgamal3")))]
#[test]
fn n_pep_batch_distributed_verifiable() {
    use libpep::client::{Client, Distributed};
    use libpep::data::batch::EncryptedBatch;
    use libpep::transcryptor::DistributedTranscryptor;

    let n = 3;
    let rng = &mut rand::rng();

    let (_global_public_keys, blinded_global_keys, blinding_factors) =
        libpep::keys::distribution::make_distributed_global_keys(n, rng);

    let systems = (0..n)
        .map(|i| {
            DistributedTranscryptor::new(
                PseudonymizationSecret::from(format!("ps-{i}").as_bytes().into()),
                EncryptionSecret::from(format!("es-{i}").as_bytes().into()),
                blinding_factors[i],
            )
        })
        .collect::<Vec<_>>();

    let domain_a = PseudonymizationDomain::from("a");
    let domain_b = PseudonymizationDomain::from("b");
    let session_a = EncryptionContext::from("sa");
    let session_b = EncryptionContext::from("sb");

    let sks_a = systems
        .iter()
        .map(|s| s.session_key_shares(&session_a))
        .collect::<Vec<_>>();
    let sks_b = systems
        .iter()
        .map(|s| s.session_key_shares(&session_b))
        .collect::<Vec<_>>();

    let client_a = Client::from_shares(blinded_global_keys, &sks_a);
    let client_b = Client::from_shares(blinded_global_keys, &sks_b);

    // Client A encrypts a batch of pseudonyms.
    let pseudonyms: Vec<Pseudonym> = (0..5).map(|_| Pseudonym::random(rng)).collect();
    let initial_batch: EncryptedBatch<EncryptedPseudonym> = client_a
        .encrypt_batch(&pseudonyms, rng)
        .expect("encrypt batch");

    // The chain: each step records (proof, post-batch, transcryptor info) so the
    // *next* step can verify it before doing its own transcryption.
    let mut current = initial_batch;
    let mut prev: Option<(
        EncryptedBatch<EncryptedPseudonym>,
        libpep::keys::PseudonymSessionPublicKey,
        libpep::data::verifiable::simple::PseudonymPseudonymizationBatchProof,
        libpep::factors::VerifiablePseudonymizationCommitment,
    )> = None;

    for system in &systems {
        // Step 1: verify the previous step (if any) using the saved pre-batch,
        // proof, and commitments. The verification reconstructs the post-batch
        // from the previous step's pre-batch and proof.
        if let Some((pre, pre_pk, proof, commitments)) = prev.as_ref() {
            #[cfg(not(feature = "elgamal3"))]
            let reconstructed = proof
                .verified_reconstruct_batch(pre, pre_pk, &current.public_key, commitments)
                .expect("verification of previous step should succeed");
            #[cfg(feature = "elgamal3")]
            let reconstructed = proof
                .verified_reconstruct_batch(pre, commitments)
                .expect("verification of previous step should succeed");

            // The reconstructed items must match the actually-received items.
            assert_eq!(reconstructed.as_items(), current.as_items());
        }

        // Step 2: this transcryptor builds and applies its own verifiable batch
        // transcryption. We save a *clone* of the pre-batch (originals) and its
        // pk so the next iteration can verify against them.
        let pre_batch = current.clone();
        let pre_pk = current.public_key;
        let info = system.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
        let commitments = Transcryptor::pseudonymization_commitment(&info.pseudonym);
        let proof = current.verifiable_pseudonymize(&info.pseudonym, rng);

        prev = Some((pre_batch, pre_pk, proof, commitments));
    }

    // Final step: client B verifies the last transcryptor's proof, then decrypts.
    let (pre, pre_pk, proof, commitments) = prev.expect("at least one transcryption step");
    #[cfg(not(feature = "elgamal3"))]
    let verified_batch = proof
        .verified_reconstruct_batch(&pre, &pre_pk, &current.public_key, &commitments)
        .expect("final verification should succeed");
    #[cfg(feature = "elgamal3")]
    let verified_batch = proof
        .verified_reconstruct_batch(&pre, &commitments)
        .expect("final verification should succeed");
    assert_eq!(verified_batch.as_items(), current.as_items());

    let decrypted = client_b
        .decrypt_batch(verified_batch.as_items())
        .expect("decrypt batch");
    assert_eq!(decrypted.len(), pseudonyms.len());
    // In this scenario the domains differ, so pseudonyms are remapped and
    // should NOT equal the originals.
    assert_ne!(decrypted, pseudonyms);
}

/// End-to-end: prove + verify a transcryption on a composite (record) value.
/// Exercises `Transcryptor::verifiable_transcrypt` (prover) and
/// `Verifier::verify_transcryption` (verifier).
#[test]
fn test_verifiable_record_transcryption() {
    use libpep::data::records::{EncryptedRecord, Record};

    let rng = &mut rand::rng();
    let (_global_pseudonym_pk, global_pseudonym_sk) = make_pseudonym_global_keys(rng);
    let (_global_attribute_pk, global_attribute_sk) = make_attribute_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain_a = PseudonymizationDomain::from("a");
    let domain_b = PseudonymizationDomain::from("b");
    let session_a = EncryptionContext::from("sa");
    let session_b = EncryptionContext::from("sb");

    let (pseudonym_session_a_pk, pseudonym_session_a_sk) =
        make_pseudonym_session_keys(&global_pseudonym_sk, &session_a, &enc_secret);
    let (attribute_session_a_pk, attribute_session_a_sk) =
        make_attribute_session_keys(&global_attribute_sk, &session_a, &enc_secret);
    let session_a_keys = SessionKeys {
        pseudonym: PseudonymSessionKeys {
            public: pseudonym_session_a_pk,
            secret: pseudonym_session_a_sk,
        },
        attribute: AttributeSessionKeys {
            public: attribute_session_a_pk,
            secret: attribute_session_a_sk,
        },
    };

    // Build a record and encrypt it.
    let record = Record::new(
        vec![Pseudonym::random(rng), Pseudonym::random(rng)],
        vec![
            Attribute::random(rng),
            Attribute::random(rng),
            Attribute::random(rng),
        ],
    );
    let enc_record = EncryptedRecord::new(
        record
            .pseudonyms
            .iter()
            .map(|p| encrypt(p, &session_a_keys.pseudonym.public, rng))
            .collect(),
        record
            .attributes
            .iter()
            .map(|a| encrypt(a, &session_a_keys.attribute.public, rng))
            .collect(),
    );

    let transcryptor = Transcryptor::new(pseudo_secret, enc_secret);
    let info = transcryptor.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
    let commitments = Transcryptor::transcryption_commitment(&info);

    #[cfg(feature = "elgamal3")]
    let proof = transcryptor.verifiable_transcrypt(&enc_record, &info, rng);
    #[cfg(not(feature = "elgamal3"))]
    let proof = transcryptor.verifiable_transcrypt(&enc_record, &info, &session_a_keys, rng);

    let verifier = Verifier::new();
    #[cfg(feature = "elgamal3")]
    let reconstructed: EncryptedRecord = verifier
        .verified_reconstruct_transcryption(&enc_record, &proof, &commitments)
        .expect("verify");
    #[cfg(not(feature = "elgamal3"))]
    let reconstructed: EncryptedRecord = verifier
        .verified_reconstruct_transcryption(&enc_record, &proof, &session_a_keys, &commitments)
        .expect("verify");

    assert_eq!(reconstructed.pseudonyms.len(), record.pseudonyms.len());
    assert_eq!(reconstructed.attributes.len(), record.attributes.len());
}
