#![cfg(feature = "json")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::core::json::builder::PEPJSONBuilder;
use libpep::core::keys::{make_global_keys, make_session_keys};
use libpep::core::transcryption::contexts::{
    EncryptionContext, PseudonymizationDomain, TranscryptionInfo,
};
use libpep::core::transcryption::secrets::{EncryptionSecret, PseudonymizationSecret};
use libpep::pep_json;

#[test]
fn test_json_transcryption_with_macro() {
    let mut rng = rand::rng();

    // Setup keys and secrets
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());
    let enc_secret = EncryptionSecret::from("encryption-secret".as_bytes().to_vec());

    let domain_a = PseudonymizationDomain::from("hospital-a");
    let domain_b = PseudonymizationDomain::from("hospital-b");
    let session = EncryptionContext::from("session-1");

    let session_keys = make_session_keys(&global_secret, &session, &enc_secret);

    // Create patient record with pseudonym using macro
    let patient_record = pep_json!({
        "patient_id": pseudonym("patient-12345"),
        "diagnosis": "Flu",
        "temperature": 38.5
    });

    // Encrypt
    let encrypted = patient_record.encrypt(&session_keys, &mut rng);

    // Decrypt to verify original
    let decrypted_original = encrypted
        .decrypt(&session_keys)
        .expect("Decryption should succeed");
    assert_eq!(decrypted_original["patient_id"], "patient-12345");
    assert_eq!(decrypted_original["diagnosis"], "Flu");

    // Transcrypt from hospital A to hospital B
    let transcryption_info = TranscryptionInfo::new(
        &domain_a,
        &domain_b,
        Some(&session),
        Some(&session),
        &pseudo_secret,
        &enc_secret,
    );

    let transcrypted = encrypted.transcrypt(&transcryption_info);

    // Verify that the encrypted structures are different after transcryption
    // (The pseudonym has been transformed)
    assert_ne!(
        format!("{:?}", encrypted),
        format!("{:?}", transcrypted),
        "Encrypted values should be different after transcryption"
    );
}

#[test]
fn test_json_transcryption_with_builder() {
    let mut rng = rand::rng();

    // Setup keys and secrets
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());
    let enc_secret = EncryptionSecret::from("encryption-secret".as_bytes().to_vec());

    let domain_a = PseudonymizationDomain::from("clinic-a");
    let domain_b = PseudonymizationDomain::from("clinic-b");
    let session = EncryptionContext::from("session-1");

    let session_keys = make_session_keys(&global_secret, &session, &enc_secret);

    // Build patient record with pseudonym using builder
    use serde_json::json;
    let patient_record = PEPJSONBuilder::new()
        .pseudonym("user_id", "user-67890")
        .attribute("name", json!("Alice"))
        .attribute("age", json!(30))
        .attribute("active", json!(true))
        .build();

    // Encrypt
    let encrypted = patient_record.encrypt(&session_keys, &mut rng);

    // Decrypt to verify original
    let decrypted_original = encrypted
        .decrypt(&session_keys)
        .expect("Decryption should succeed");
    assert_eq!(decrypted_original["user_id"], "user-67890");
    assert_eq!(decrypted_original["name"], "Alice");

    // Transcrypt from clinic A to clinic B
    let transcryption_info = TranscryptionInfo::new(
        &domain_a,
        &domain_b,
        Some(&session),
        Some(&session),
        &pseudo_secret,
        &enc_secret,
    );

    let transcrypted = encrypted.transcrypt(&transcryption_info);

    // Verify that the encrypted structures are different after transcryption
    // (The pseudonym has been transformed)
    assert_ne!(
        format!("{:?}", encrypted),
        format!("{:?}", transcrypted),
        "Encrypted values should be different after transcryption"
    );
}

#[cfg(feature = "batch")]
#[test]
fn test_json_batch_transcryption_same_structure() {
    use libpep::core::json::transcryption::transcrypt_json_batch;

    let mut rng = rand::rng();

    // Setup keys and secrets
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());
    let enc_secret = EncryptionSecret::from("encryption-secret".as_bytes().to_vec());

    let domain_a = PseudonymizationDomain::from("domain-a");
    let domain_b = PseudonymizationDomain::from("domain-b");
    let session = EncryptionContext::from("session-1");

    let session_keys = make_session_keys(&global_secret, &session, &enc_secret);

    // Create two JSON values with the SAME structure
    let record1 = pep_json!({
        "patient_id": pseudonym("patient-001"),
        "diagnosis": "Flu",
        "temperature": 38.5
    });

    let record2 = pep_json!({
        "patient_id": pseudonym("patient-002"),
        "diagnosis": "Cold",
        "temperature": 37.2
    });

    // Encrypt both records
    let encrypted1 = record1.encrypt(&session_keys, &mut rng);
    let encrypted2 = record2.encrypt(&session_keys, &mut rng);

    // Verify they have the same structure
    let structure1 = encrypted1.structure();
    let structure2 = encrypted2.structure();
    assert_eq!(structure1, structure2, "Records should have same structure");

    // Batch transcrypt (this should succeed because structures match)
    let transcryption_info = TranscryptionInfo::new(
        &domain_a,
        &domain_b,
        Some(&session),
        Some(&session),
        &pseudo_secret,
        &enc_secret,
    );

    let transcrypted_batch = transcrypt_json_batch(
        vec![encrypted1.clone(), encrypted2.clone()],
        &transcryption_info,
        &mut rng,
    )
    .expect("Batch transcryption should succeed for same structure");

    // Verify we got 2 records back
    assert_eq!(transcrypted_batch.len(), 2);

    // Verify that batch transcryption succeeded and values changed
    assert_ne!(
        format!("{:?}", vec![encrypted1, encrypted2]),
        format!("{:?}", transcrypted_batch),
        "Batch transcryption should transform the values"
    );

    // Decrypt all transcrypted values
    let mut decrypted_batch: Vec<serde_json::Value> = transcrypted_batch
        .iter()
        .map(|v| v.decrypt(&session_keys).expect("Decryption should succeed"))
        .collect();

    // Sort by temperature to have a consistent order (Flu=38.5, Cold=37.2)
    decrypted_batch.sort_by(|a, b| {
        let temp_a = a["temperature"].as_f64().unwrap();
        let temp_b = b["temperature"].as_f64().unwrap();
        temp_a.partial_cmp(&temp_b).unwrap()
    });

    // Verify the Cold patient data (lower temperature)
    assert_eq!(decrypted_batch[0]["diagnosis"], "Cold");
    assert_eq!(decrypted_batch[0]["temperature"].as_f64().unwrap(), 37.2);
    assert_ne!(
        decrypted_batch[0]["patient_id"], "patient-002",
        "Patient ID should be different after cross-domain transcryption"
    );

    // Verify the Flu patient data (higher temperature)
    assert_eq!(decrypted_batch[1]["diagnosis"], "Flu");
    assert_eq!(decrypted_batch[1]["temperature"].as_f64().unwrap(), 38.5);
    assert_ne!(
        decrypted_batch[1]["patient_id"], "patient-001",
        "Patient ID should be different after cross-domain transcryption"
    );
}

#[cfg(feature = "batch")]
#[test]
fn test_json_batch_transcryption_different_structures() {
    use libpep::core::json::transcryption::transcrypt_json_batch;

    let mut rng = rand::rng();

    // Setup keys and secrets
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());
    let enc_secret = EncryptionSecret::from("encryption-secret".as_bytes().to_vec());

    let domain_a = PseudonymizationDomain::from("domain-a");
    let domain_b = PseudonymizationDomain::from("domain-b");
    let session = EncryptionContext::from("session-1");

    let session_keys = make_session_keys(&global_secret, &session, &enc_secret);

    // Create two JSON values with DIFFERENT structures
    let record1 = pep_json!({
        "patient_id": pseudonym("patient-001"),
        "diagnosis": "Flu",
        "temperature": 38.5
    });

    let record2 = pep_json!({
        "user_id": pseudonym("user-002"),
        "name": "Bob",
        "age": 25,
        "active": true
    });

    // Encrypt both records
    let encrypted1 = record1.encrypt(&session_keys, &mut rng);
    let encrypted2 = record2.encrypt(&session_keys, &mut rng);

    // Verify they have different structures
    let structure1 = encrypted1.structure();
    let structure2 = encrypted2.structure();
    assert_ne!(
        structure1, structure2,
        "Records should have different structures"
    );

    // Attempt batch transcryption (this should return an error because structures don't match)
    let transcryption_info = TranscryptionInfo::new(
        &domain_a,
        &domain_b,
        Some(&session),
        Some(&session),
        &pseudo_secret,
        &enc_secret,
    );

    let result = transcrypt_json_batch(vec![encrypted1, encrypted2], &transcryption_info, &mut rng);

    // Verify we got an error about structure mismatch
    assert!(
        result.is_err(),
        "Should return error for different structures"
    );
    assert!(
        result
            .unwrap_err()
            .contains("All values must have the same structure"),
        "Error should mention structure mismatch"
    );
}
