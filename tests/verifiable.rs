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

/// Serde-roundtrip a verifiable proof, flipping a single character inside the
/// JSON encoding to produce a syntactically valid but semantically different
/// proof. Used by tampered-proof tests below.
///
/// The mutation targets hex/base64 string literals in the JSON: it walks the
/// JSON character by character, finds the first character inside a string
/// literal that is a hex/base64 digit, and replaces it with a different valid
/// digit. This keeps deserialization happy (the string still decodes) while
/// changing the underlying group element / scalar.
/// Swap the proof's first base64 / hex-encoded string value with the
/// corresponding value from a *different but valid* proof, producing a
/// well-formed but semantically wrong proof for verification testing.
///
/// Strategy: re-serialize the donor proof into the recipient proof's JSON
/// shape, copy the first leaf string value across, and deserialize back.
/// This guarantees the result is a fully-valid serialization (group elements
/// still decode, scalars still canonical) but the proof no longer matches the
/// statement it claims to prove.
#[cfg(feature = "serde")]
fn swap_first_string<T>(proof: &T, donor: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let mut target: serde_json::Value =
        serde_json::to_value(proof).expect("serialize target to JSON");
    let donor_value: serde_json::Value =
        serde_json::to_value(donor).expect("serialize donor to JSON");
    let swapped = swap_first_string_value(&mut target, &donor_value);
    assert!(swapped, "swap_first_string: no string value found to swap");
    serde_json::from_value(target).expect("swapped proof should still deserialize")
}

/// Walk `target` and `donor` in parallel, replacing the first string value in
/// `target` with the corresponding string in `donor`. Returns true on success.
#[cfg(feature = "serde")]
fn swap_first_string_value(target: &mut serde_json::Value, donor: &serde_json::Value) -> bool {
    match (target, donor) {
        (serde_json::Value::String(t), serde_json::Value::String(d)) if t != d => {
            *t = d.clone();
            true
        }
        (serde_json::Value::Array(ts), serde_json::Value::Array(ds)) => {
            for (t, d) in ts.iter_mut().zip(ds.iter()) {
                if swap_first_string_value(t, d) {
                    return true;
                }
            }
            false
        }
        (serde_json::Value::Object(tm), serde_json::Value::Object(dm)) => {
            for (k, t) in tm.iter_mut() {
                if let Some(d) = dm.get(k) {
                    if swap_first_string_value(t, d) {
                        return true;
                    }
                }
            }
            false
        }
        _ => false,
    }
}

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
    let commitments =
        transcryptor.pseudonymization_commitment(&domain1, &domain2, &session1, &session2);

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
    let commitments = transcryptor.pseudonym_rekey_commitment(&session1, &session2);

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
    let commitments = transcryptor.attribute_rekey_commitment(&session1, &session2);

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
    let commitments =
        transcryptor.pseudonymization_commitment(&domain1, &domain2, &session1, &session2);

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

    use libpep::verifier::VerifyError;
    #[cfg(feature = "elgamal3")]
    let result: Result<EncryptedPseudonym, _> = verifier
        .verified_reconstruct_pseudonymization_cached(
            &transcryptor_id,
            &enc_pseudo,
            &operation_proof,
            &domain1,
            &domain2,
            &session1,
            &session2,
        );
    #[cfg(not(feature = "elgamal3"))]
    let result: Result<EncryptedPseudonym, _> = verifier
        .verified_reconstruct_pseudonymization_cached(
            &transcryptor_id,
            &enc_pseudo,
            &operation_proof,
            &pseudonym_session1_public,
            &domain1,
            &domain2,
            &session1,
            &session2,
        );
    assert!(result.is_ok());

    // Wrong transition (different target domain) should not be in the cache.
    #[cfg(feature = "elgamal3")]
    let bad: Result<EncryptedPseudonym, _> = verifier.verified_reconstruct_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &operation_proof,
        &domain1,
        &domain3,
        &session1,
        &session2,
    );
    #[cfg(not(feature = "elgamal3"))]
    let bad: Result<EncryptedPseudonym, _> = verifier.verified_reconstruct_pseudonymization_cached(
        &transcryptor_id,
        &enc_pseudo,
        &operation_proof,
        &pseudonym_session1_public,
        &domain1,
        &domain3,
        &session1,
        &session2,
    );
    assert!(matches!(bad, Err(VerifyError::UnknownCommitment)));

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
        let commitments =
            system.pseudonymization_commitment(&domain_a, &domain_b, &session_a, &session_b);
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
    let commitments =
        transcryptor.transcryption_commitment(&domain_a, &domain_b, &session_a, &session_b);

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

// ============================================================================
// Negative tests: tampered proofs, wrong originals, and wrong commitments must
// all cause verification to fail with a structured error.
// ============================================================================

#[cfg(feature = "serde")]
#[test]
fn tampered_proof_rejected_pseudonymization() {
    use libpep::verifier::VerifyError;

    let rng = &mut rand::rng();
    let (_, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("d1");
    let domain2 = PseudonymizationDomain::from("d2");
    let session1 = EncryptionContext::from("s1");
    let session2 = EncryptionContext::from("s2");

    let (pseudonym_session1_public, _) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);

    let transcryptor = Transcryptor::new(pseudo_secret, enc_secret);
    let info = transcryptor.pseudonymization_info(&domain1, &domain2, &session1, &session2);
    let commitments =
        transcryptor.pseudonymization_commitment(&domain1, &domain2, &session1, &session2);

    let enc_pseudo = encrypt(&Pseudonym::random(rng), &pseudonym_session1_public, rng);
    #[cfg(feature = "elgamal3")]
    let proof = enc_pseudo.verifiable_pseudonymize(&info, rng);
    #[cfg(not(feature = "elgamal3"))]
    let proof = enc_pseudo.verifiable_pseudonymize(&info, &pseudonym_session1_public, rng);

    // Build a second valid proof to donate one of its components.
    let donor_enc = encrypt(&Pseudonym::random(rng), &pseudonym_session1_public, rng);
    #[cfg(feature = "elgamal3")]
    let donor_proof = donor_enc.verifiable_pseudonymize(&info, rng);
    #[cfg(not(feature = "elgamal3"))]
    let donor_proof = donor_enc.verifiable_pseudonymize(&info, &pseudonym_session1_public, rng);

    let tampered = swap_first_string(&proof, &donor_proof);

    let verifier = Verifier::new();
    #[cfg(feature = "elgamal3")]
    let result = verifier.verify_pseudonymization::<_>(&enc_pseudo, &tampered, &commitments);
    #[cfg(not(feature = "elgamal3"))]
    let result = verifier.verify_pseudonymization::<_>(
        &enc_pseudo,
        &tampered,
        &pseudonym_session1_public,
        &commitments,
    );
    assert!(matches!(result, Err(VerifyError::ProofRejected)));
}

#[test]
fn wrong_original_rejected_pseudonymization() {
    use libpep::verifier::VerifyError;

    let rng = &mut rand::rng();
    let (_, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("d1");
    let domain2 = PseudonymizationDomain::from("d2");
    let session1 = EncryptionContext::from("s1");
    let session2 = EncryptionContext::from("s2");

    let (pseudonym_session1_public, _) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);

    let transcryptor = Transcryptor::new(pseudo_secret, enc_secret);
    let info = transcryptor.pseudonymization_info(&domain1, &domain2, &session1, &session2);
    let commitments =
        transcryptor.pseudonymization_commitment(&domain1, &domain2, &session1, &session2);

    let enc_pseudo = encrypt(&Pseudonym::random(rng), &pseudonym_session1_public, rng);
    #[cfg(feature = "elgamal3")]
    let proof = enc_pseudo.verifiable_pseudonymize(&info, rng);
    #[cfg(not(feature = "elgamal3"))]
    let proof = enc_pseudo.verifiable_pseudonymize(&info, &pseudonym_session1_public, rng);

    // Verify the proof against a *different* ciphertext.
    let other_enc = encrypt(&Pseudonym::random(rng), &pseudonym_session1_public, rng);

    let verifier = Verifier::new();
    #[cfg(feature = "elgamal3")]
    let result = verifier.verify_pseudonymization::<_>(&other_enc, &proof, &commitments);
    #[cfg(not(feature = "elgamal3"))]
    let result = verifier.verify_pseudonymization::<_>(
        &other_enc,
        &proof,
        &pseudonym_session1_public,
        &commitments,
    );
    assert!(matches!(result, Err(VerifyError::ProofRejected)));
}

#[test]
fn wrong_commitments_rejected_pseudonymization() {
    use libpep::verifier::VerifyError;

    let rng = &mut rand::rng();
    let (_, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("d1");
    let domain2 = PseudonymizationDomain::from("d2");
    let domain3 = PseudonymizationDomain::from("d3");
    let session1 = EncryptionContext::from("s1");
    let session2 = EncryptionContext::from("s2");

    let (pseudonym_session1_public, _) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);

    let transcryptor = Transcryptor::new(pseudo_secret, enc_secret);
    let info = transcryptor.pseudonymization_info(&domain1, &domain2, &session1, &session2);
    // Commitments for a *different* target domain than the proof.
    let wrong_commitments =
        transcryptor.pseudonymization_commitment(&domain1, &domain3, &session1, &session2);

    let enc_pseudo = encrypt(&Pseudonym::random(rng), &pseudonym_session1_public, rng);
    #[cfg(feature = "elgamal3")]
    let proof = enc_pseudo.verifiable_pseudonymize(&info, rng);
    #[cfg(not(feature = "elgamal3"))]
    let proof = enc_pseudo.verifiable_pseudonymize(&info, &pseudonym_session1_public, rng);

    let verifier = Verifier::new();
    #[cfg(feature = "elgamal3")]
    let result = verifier.verify_pseudonymization::<_>(&enc_pseudo, &proof, &wrong_commitments);
    #[cfg(not(feature = "elgamal3"))]
    let result = verifier.verify_pseudonymization::<_>(
        &enc_pseudo,
        &proof,
        &pseudonym_session1_public,
        &wrong_commitments,
    );
    assert!(matches!(result, Err(VerifyError::ProofRejected)));
}

#[cfg(feature = "serde")]
#[test]
fn tampered_proof_rejected_pseudonym_rekey() {
    use libpep::verifier::VerifyError;

    let rng = &mut rand::rng();
    let (_, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let session1 = EncryptionContext::from("s1");
    let session2 = EncryptionContext::from("s2");

    let (pseudonym_session1_public, _) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);

    let transcryptor = Transcryptor::new(pseudo_secret, enc_secret);
    let info = transcryptor.pseudonym_rekey_info(&session1, &session2);
    let commitments = transcryptor.pseudonym_rekey_commitment(&session1, &session2);

    let enc_pseudo = encrypt(&Pseudonym::random(rng), &pseudonym_session1_public, rng);
    let proof = enc_pseudo.verifiable_rekey(&info, rng);

    let donor_enc = encrypt(&Pseudonym::random(rng), &pseudonym_session1_public, rng);
    let donor_proof = donor_enc.verifiable_rekey(&info, rng);

    let tampered = swap_first_string(&proof, &donor_proof);

    let verifier = Verifier::new();
    let result: Result<(), _> = verifier.verify_rekey(&enc_pseudo, &tampered, &commitments);
    assert!(matches!(result, Err(VerifyError::ProofRejected)));
}

#[test]
fn wrong_original_rejected_pseudonym_rekey() {
    use libpep::verifier::VerifyError;

    let rng = &mut rand::rng();
    let (_, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let session1 = EncryptionContext::from("s1");
    let session2 = EncryptionContext::from("s2");

    let (pseudonym_session1_public, _) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);

    let transcryptor = Transcryptor::new(pseudo_secret, enc_secret);
    let info = transcryptor.pseudonym_rekey_info(&session1, &session2);
    let commitments = transcryptor.pseudonym_rekey_commitment(&session1, &session2);

    let enc_pseudo = encrypt(&Pseudonym::random(rng), &pseudonym_session1_public, rng);
    let proof = enc_pseudo.verifiable_rekey(&info, rng);

    let other_enc = encrypt(&Pseudonym::random(rng), &pseudonym_session1_public, rng);

    let verifier = Verifier::new();
    let result: Result<(), _> = verifier.verify_rekey(&other_enc, &proof, &commitments);
    assert!(matches!(result, Err(VerifyError::ProofRejected)));
}

#[cfg(feature = "serde")]
#[test]
fn tampered_proof_rejected_attribute_rekey() {
    use libpep::verifier::VerifyError;

    let rng = &mut rand::rng();
    let (_, attribute_global_secret) = make_attribute_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let session1 = EncryptionContext::from("s1");
    let session2 = EncryptionContext::from("s2");

    let (attribute_session1_public, _) =
        make_attribute_session_keys(&attribute_global_secret, &session1, &enc_secret);

    let transcryptor = Transcryptor::new(pseudo_secret, enc_secret);
    let info = transcryptor.attribute_rekey_info(&session1, &session2);
    let commitments = transcryptor.attribute_rekey_commitment(&session1, &session2);

    let enc_attr = encrypt(&Attribute::random(rng), &attribute_session1_public, rng);
    let proof = enc_attr.verifiable_rekey(&info, rng);

    let donor_enc = encrypt(&Attribute::random(rng), &attribute_session1_public, rng);
    let donor_proof = donor_enc.verifiable_rekey(&info, rng);

    let tampered = swap_first_string(&proof, &donor_proof);

    let verifier = Verifier::new();
    let result: Result<(), _> = verifier.verify_rekey(&enc_attr, &tampered, &commitments);
    assert!(matches!(result, Err(VerifyError::ProofRejected)));
}

#[test]
fn wrong_original_rejected_attribute_rekey() {
    use libpep::verifier::VerifyError;

    let rng = &mut rand::rng();
    let (_, attribute_global_secret) = make_attribute_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let session1 = EncryptionContext::from("s1");
    let session2 = EncryptionContext::from("s2");

    let (attribute_session1_public, _) =
        make_attribute_session_keys(&attribute_global_secret, &session1, &enc_secret);

    let transcryptor = Transcryptor::new(pseudo_secret, enc_secret);
    let info = transcryptor.attribute_rekey_info(&session1, &session2);
    let commitments = transcryptor.attribute_rekey_commitment(&session1, &session2);

    let enc_attr = encrypt(&Attribute::random(rng), &attribute_session1_public, rng);
    let proof = enc_attr.verifiable_rekey(&info, rng);

    let other_enc = encrypt(&Attribute::random(rng), &attribute_session1_public, rng);

    let verifier = Verifier::new();
    let result: Result<(), _> = verifier.verify_rekey(&other_enc, &proof, &commitments);
    assert!(matches!(result, Err(VerifyError::ProofRejected)));
}

#[cfg(feature = "serde")]
#[test]
fn tampered_proof_rejected_record_transcryption() {
    use libpep::data::records::{EncryptedRecord, Record};
    use libpep::verifier::VerifyError;

    let rng = &mut rand::rng();
    let (_, global_pseudonym_sk) = make_pseudonym_global_keys(rng);
    let (_, global_attribute_sk) = make_attribute_global_keys(rng);
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

    let record = Record::new(
        vec![Pseudonym::random(rng)],
        vec![Attribute::random(rng), Attribute::random(rng)],
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
    let commitments =
        transcryptor.transcryption_commitment(&domain_a, &domain_b, &session_a, &session_b);

    #[cfg(feature = "elgamal3")]
    let proof = transcryptor.verifiable_transcrypt(&enc_record, &info, rng);
    #[cfg(not(feature = "elgamal3"))]
    let proof = transcryptor.verifiable_transcrypt(&enc_record, &info, &session_a_keys, rng);

    // Donor: independently re-encrypt the same record and prove again.
    let donor_enc = EncryptedRecord::new(
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
    #[cfg(feature = "elgamal3")]
    let donor_proof = transcryptor.verifiable_transcrypt(&donor_enc, &info, rng);
    #[cfg(not(feature = "elgamal3"))]
    let donor_proof = transcryptor.verifiable_transcrypt(&donor_enc, &info, &session_a_keys, rng);

    let tampered = swap_first_string(&proof, &donor_proof);

    let verifier = Verifier::new();
    #[cfg(feature = "elgamal3")]
    let result = verifier.verify_transcryption::<_>(&enc_record, &tampered, &commitments);
    #[cfg(not(feature = "elgamal3"))]
    let result =
        verifier.verify_transcryption::<_>(&enc_record, &tampered, &session_a_keys, &commitments);
    assert!(matches!(result, Err(VerifyError::ProofRejected)));
}

// ---------------------------------------------------------------------------
// Batch negative tests: tampered proof, wrong original, element reorder,
// wrong recipient PK, single-element batch, empty batch.
// ---------------------------------------------------------------------------

/// Set up a single-transcryptor batch verifiable-pseudonymize scenario and
/// return everything the negative tests below need: the pre-batch (originals),
/// the produced proof, the post-batch (mutated by the proving step), the
/// transcryptor commitments, and the session-A public key.
#[cfg(all(feature = "batch", feature = "serde"))]
#[allow(clippy::type_complexity)]
fn batch_pseudonymize_fixture<R: rand_core::Rng + rand_core::CryptoRng>(
    rng: &mut R,
) -> (
    libpep::data::batch::EncryptedBatch<EncryptedPseudonym>,
    libpep::data::batch::EncryptedBatch<EncryptedPseudonym>,
    libpep::data::verifiable::simple::PseudonymPseudonymizationBatchProof,
    libpep::factors::VerifiablePseudonymizationCommitment,
    PseudonymSessionPublicKey,
) {
    let (_, gsk) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let d1 = PseudonymizationDomain::from("d1");
    let d2 = PseudonymizationDomain::from("d2");
    let s1 = EncryptionContext::from("s1");
    let s2 = EncryptionContext::from("s2");

    let (pk1, _) = make_pseudonym_session_keys(&gsk, &s1, &enc_secret);
    let transcryptor = Transcryptor::new(pseudo_secret, enc_secret);
    let info = transcryptor.pseudonymization_info(&d1, &d2, &s1, &s2);
    let commitments = transcryptor.pseudonymization_commitment(&d1, &d2, &s1, &s2);

    let items: Vec<_> = (0..3)
        .map(|_| encrypt(&Pseudonym::random(rng), &pk1, rng))
        .collect();

    #[cfg(not(feature = "elgamal3"))]
    let pre = libpep::data::batch::EncryptedBatch::new(items, pk1).expect("new batch");
    #[cfg(feature = "elgamal3")]
    let pre = libpep::data::batch::EncryptedBatch::new(items).expect("new batch");

    let mut post = pre.clone();
    let proof = post.verifiable_pseudonymize(&info, rng);

    (pre, post, proof, commitments, pk1)
}

/// A batch proof whose serialized form has had a single string component
/// swapped must be rejected.
#[cfg(all(feature = "batch", feature = "serde"))]
#[test]
fn tampered_proof_rejected_pseudonymization_batch() {
    let rng = &mut rand::rng();
    let (pre, _post, proof, commitments, pk1) = batch_pseudonymize_fixture(rng);
    // Build a donor proof from an independent batch over the same statement.
    let (_pre2, _post2, donor_proof, _c2, _pk2) = batch_pseudonymize_fixture(rng);
    let tampered = swap_first_string(&proof, &donor_proof);

    #[cfg(not(feature = "elgamal3"))]
    let result = tampered.verified_reconstruct(&pre, &pk1, &commitments);
    #[cfg(feature = "elgamal3")]
    let result = {
        let _ = &pk1; // unused under elgamal3
        tampered.verified_reconstruct(&pre, &commitments)
    };
    assert!(result.is_none(), "tampered batch proof must not verify");
}

/// Verifying a batch proof against a different (but well-formed) pre-batch
/// must be rejected: each per-item inner proof binds to its original
/// ciphertext.
#[cfg(all(feature = "batch", feature = "serde"))]
#[test]
fn wrong_original_rejected_pseudonymization_batch() {
    let rng = &mut rand::rng();
    let (_pre, _post, proof, commitments, pk1) = batch_pseudonymize_fixture(rng);
    // Fresh, independent batch: same shape and key, different ciphertexts.
    let (other_pre, _, _, _, _) = batch_pseudonymize_fixture(rng);

    #[cfg(not(feature = "elgamal3"))]
    let result = proof.verified_reconstruct(&other_pre, &pk1, &commitments);
    #[cfg(feature = "elgamal3")]
    let result = {
        let _ = &pk1;
        proof.verified_reconstruct(&other_pre, &commitments)
    };
    assert!(
        result.is_none(),
        "batch proof against a wrong original batch must not verify"
    );
}

/// Reordering items within the input batch must be rejected: the per-item
/// inner proofs are positionally bound to their originals.
#[cfg(all(feature = "batch", feature = "serde"))]
#[test]
fn reordered_originals_rejected_pseudonymization_batch() {
    let rng = &mut rand::rng();
    let (pre, _post, proof, commitments, pk1) = batch_pseudonymize_fixture(rng);

    // Build a permuted version of `pre` (swap items 0 and 1).
    let mut items: Vec<_> = pre.as_items().to_vec();
    assert!(items.len() >= 2);
    items.swap(0, 1);
    #[cfg(not(feature = "elgamal3"))]
    let reordered = libpep::data::batch::EncryptedBatch::new(items, pk1).expect("reordered batch");
    #[cfg(feature = "elgamal3")]
    let reordered = libpep::data::batch::EncryptedBatch::new(items).expect("reordered batch");

    #[cfg(not(feature = "elgamal3"))]
    let result = proof.verified_reconstruct(&reordered, &pk1, &commitments);
    #[cfg(feature = "elgamal3")]
    let result = {
        let _ = &pk1;
        proof.verified_reconstruct(&reordered, &commitments)
    };
    assert!(
        result.is_none(),
        "swapping two items in the original batch must invalidate the proof"
    );
}

/// Verifying a batch proof against a different recipient public key must be
/// rejected (non-`elgamal3` only — under `elgamal3` the recipient key is
/// embedded in `gy` and changing it amounts to changing the originals).
#[cfg(all(feature = "batch", feature = "serde", not(feature = "elgamal3")))]
#[test]
fn wrong_recipient_pk_rejected_pseudonymization_batch() {
    let rng = &mut rand::rng();
    let (pre, _post, proof, commitments, _pk1) = batch_pseudonymize_fixture(rng);
    // Fresh, unrelated recipient public key.
    let (other_pk, _) = make_pseudonym_global_keys(rng);
    let other_session_pk = PseudonymSessionPublicKey::from(*other_pk);

    let result = proof.verified_reconstruct(&pre, &other_session_pk, &commitments);
    assert!(
        result.is_none(),
        "batch proof must not verify under a wrong recipient public key"
    );
}

/// Single-element batch happy path: proves the batch machinery handles
/// `n=1` correctly (a common boundary).
#[cfg(feature = "batch")]
#[test]
fn single_element_batch_verified_pseudonymization() {
    let rng = &mut rand::rng();
    let (_, gsk) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let d1 = PseudonymizationDomain::from("d1");
    let d2 = PseudonymizationDomain::from("d2");
    let s1 = EncryptionContext::from("s1");
    let s2 = EncryptionContext::from("s2");

    let (pk1, _) = make_pseudonym_session_keys(&gsk, &s1, &enc_secret);
    let transcryptor = Transcryptor::new(pseudo_secret, enc_secret);
    let info = transcryptor.pseudonymization_info(&d1, &d2, &s1, &s2);
    let commitments = transcryptor.pseudonymization_commitment(&d1, &d2, &s1, &s2);

    let item = encrypt(&Pseudonym::random(rng), &pk1, rng);
    #[cfg(not(feature = "elgamal3"))]
    let pre = libpep::data::batch::EncryptedBatch::new(vec![item], pk1).expect("new batch");
    #[cfg(feature = "elgamal3")]
    let pre = libpep::data::batch::EncryptedBatch::new(vec![item]).expect("new batch");

    let mut post = pre.clone();
    let proof = post.verifiable_pseudonymize(&info, rng);

    #[cfg(not(feature = "elgamal3"))]
    let result = proof.verified_reconstruct(&pre, &pk1, &commitments);
    #[cfg(feature = "elgamal3")]
    let result = proof.verified_reconstruct(&pre, &commitments);
    let news = result.expect("single-element batch must verify");
    assert_eq!(news.len(), 1);
}

/// Empty-batch verification: an honestly-built empty proof verifies, but
/// only against an empty pre-batch. Verifying an empty proof against a
/// non-empty batch must fail (length mismatch).
#[cfg(feature = "batch")]
#[test]
fn empty_batch_proof_only_verifies_against_empty_batch() {
    let rng = &mut rand::rng();
    let (_, gsk) = make_pseudonym_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let d1 = PseudonymizationDomain::from("d1");
    let d2 = PseudonymizationDomain::from("d2");
    let s1 = EncryptionContext::from("s1");
    let s2 = EncryptionContext::from("s2");

    let (pk1, _) = make_pseudonym_session_keys(&gsk, &s1, &enc_secret);
    let transcryptor = Transcryptor::new(pseudo_secret, enc_secret);
    let info = transcryptor.pseudonymization_info(&d1, &d2, &s1, &s2);
    let commitments = transcryptor.pseudonymization_commitment(&d1, &d2, &s1, &s2);

    #[cfg(not(feature = "elgamal3"))]
    let pre_empty: libpep::data::batch::EncryptedBatch<EncryptedPseudonym> =
        libpep::data::batch::EncryptedBatch::new(vec![], pk1).expect("empty batch");
    #[cfg(feature = "elgamal3")]
    let pre_empty: libpep::data::batch::EncryptedBatch<EncryptedPseudonym> =
        libpep::data::batch::EncryptedBatch::new(vec![]).expect("empty batch");

    let mut post = pre_empty.clone();
    let empty_proof = post.verifiable_pseudonymize(&info, rng);

    // Verifying the empty proof against the empty batch reconstructs to an
    // empty Vec — and under elgamal3 we additionally enforce that the
    // batch's `gy` is consistent (which an empty batch has no `gy` to share),
    // so verification fails rather than vacuously succeeding.
    #[cfg(not(feature = "elgamal3"))]
    {
        let result = empty_proof.verified_reconstruct(&pre_empty, &pk1, &commitments);
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }
    #[cfg(feature = "elgamal3")]
    {
        let result = empty_proof.verified_reconstruct(&pre_empty, &commitments);
        assert!(
            result.is_none(),
            "elgamal3 empty-batch verify must fail — no gy to bind"
        );
    }

    // Verifying the empty proof against a non-empty batch must fail
    // regardless of feature configuration.
    let item = encrypt(&Pseudonym::random(rng), &pk1, rng);
    #[cfg(not(feature = "elgamal3"))]
    let pre_nonempty =
        libpep::data::batch::EncryptedBatch::new(vec![item], pk1).expect("non-empty batch");
    #[cfg(feature = "elgamal3")]
    let pre_nonempty =
        libpep::data::batch::EncryptedBatch::new(vec![item]).expect("non-empty batch");

    #[cfg(not(feature = "elgamal3"))]
    let bad = empty_proof.verified_reconstruct(&pre_nonempty, &pk1, &commitments);
    #[cfg(feature = "elgamal3")]
    let bad = empty_proof.verified_reconstruct(&pre_nonempty, &commitments);
    assert!(bad.is_none(), "length mismatch must reject verification");
}

/// Under elgamal3, a batch mixing items encrypted under different recipient
/// public keys (i.e. items with different `gy`) must be rejected even if
/// every per-item proof is otherwise valid for *one* of the keys.
#[cfg(all(feature = "batch", feature = "elgamal3"))]
#[test]
fn mixed_gy_rejected_pseudonymization_batch() {
    let rng = &mut rand::rng();
    let (pre, _post, proof, commitments, _pk1) = batch_pseudonymize_fixture(rng);
    // Build a foreign item under a *different* recipient session key so the
    // `gy` differs from the rest of the batch.
    let (_, gsk2) = make_pseudonym_global_keys(rng);
    let enc_secret2 = EncryptionSecret::from("other-secret".into());
    let (other_session_pk, _) = make_pseudonym_session_keys(
        &gsk2,
        &EncryptionContext::from("other-session"),
        &enc_secret2,
    );
    let foreign_item = encrypt(&Pseudonym::random(rng), &other_session_pk, rng);

    // Splice the foreign item into the pre-batch.
    let mut items: Vec<_> = pre.as_items().to_vec();
    items[0] = foreign_item;
    let mixed = libpep::data::batch::EncryptedBatch::new(items).expect("mixed batch");

    let result = proof.verified_reconstruct(&mixed, &commitments);
    assert!(
        result.is_none(),
        "mixed-gy batch must be rejected by the shared_gy guard"
    );
}
