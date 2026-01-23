#![cfg(feature = "json")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(feature = "batch")]
use libpep::core::batch::transcrypt_batch;
use libpep::core::data::json::builder::PEPJSONBuilder;
use libpep::core::data::traits::{Encryptable, Encrypted, Transcryptable};
use libpep::core::factors::contexts::{
    EncryptionContext, PseudonymizationDomain, TranscryptionInfo,
};
use libpep::core::factors::secrets::{EncryptionSecret, PseudonymizationSecret};
use libpep::core::keys::{make_global_keys, make_session_keys};
use libpep::pep_json;
use serde_json::json;

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
    #[cfg(feature = "elgamal3")]
    let decrypted_original = encrypted.decrypt(&session_keys).unwrap();
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_original = encrypted.decrypt(&session_keys);

    let json_original = decrypted_original
        .to_value()
        .expect("Should convert to JSON");
    assert_eq!(json_original["patient_id"], "patient-12345");
    assert_eq!(json_original["diagnosis"], "Flu");

    // Transcrypt from hospital A to hospital B
    let transcryption_info = TranscryptionInfo::new(
        &domain_a,
        &domain_b,
        &session,
        &session,
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

    // Create JSON with existing data, marking "user_id" as a pseudonym field
    let patient_data = json!({
        "user_id": "user-67890",
        "name": "Alice",
        "age": 30,
        "active": true
    });

    // Convert to PEP JSON, specifying which fields are pseudonyms
    let patient_record = PEPJSONBuilder::from_json(&patient_data, &["user_id"])
        .expect("Should create PEP JSON from existing JSON")
        .build();

    // Encrypt
    let encrypted = patient_record.encrypt(&session_keys, &mut rng);

    // Decrypt to verify original
    #[cfg(feature = "elgamal3")]
    let decrypted_original = encrypted.decrypt(&session_keys).unwrap();
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_original = encrypted.decrypt(&session_keys);

    let json_original = decrypted_original
        .to_value()
        .expect("Should convert to JSON");
    assert_eq!(json_original["user_id"], "user-67890");
    assert_eq!(json_original["name"], "Alice");
    assert_eq!(json_original["age"], 30);
    assert_eq!(json_original["active"], true);

    // Transcrypt from clinic A to clinic B
    let transcryption_info = TranscryptionInfo::new(
        &domain_a,
        &domain_b,
        &session,
        &session,
        &pseudo_secret,
        &enc_secret,
    );

    let transcrypted = encrypted.transcrypt(&transcryption_info);

    // Decrypt transcrypted data
    #[cfg(feature = "elgamal3")]
    let decrypted_transcrypted = transcrypted.decrypt(&session_keys).unwrap();
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_transcrypted = transcrypted.decrypt(&session_keys);
    let json_transcrypted = decrypted_transcrypted
        .to_value()
        .expect("Should convert to JSON");

    // Attributes should remain the same, but pseudonym should be different
    assert_eq!(json_transcrypted["name"], "Alice");
    assert_eq!(json_transcrypted["age"], 30);
    assert_eq!(json_transcrypted["active"], true);
    assert_ne!(
        json_transcrypted["user_id"], "user-67890",
        "Pseudonym should be different after cross-domain transcryption"
    );
}

#[cfg(feature = "batch")]
#[test]
fn test_json_batch_transcryption_same_structure() {
    let mut rng = rand::rng();

    // Setup keys and secrets
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());
    let enc_secret = EncryptionSecret::from("encryption-secret".as_bytes().to_vec());

    let domain_a = PseudonymizationDomain::from("domain-a");
    let domain_b = PseudonymizationDomain::from("domain-b");
    let session = EncryptionContext::from("session-1");

    let session_keys = make_session_keys(&global_secret, &session, &enc_secret);

    // Create two JSON values with the SAME structure using standard JSON

    let data1 = json!({
        "patient_id": "patient-001",
        "diagnosis": "Flu",
        "temperature": 38.5
    });

    let data2 = json!({
        "patient_id": "patient-002",
        "diagnosis": "Cold",
        "temperature": 37.2
    });

    // Convert to PEP JSON, specifying "patient_id" as pseudonym field
    let record1 = PEPJSONBuilder::from_json(&data1, &["patient_id"])
        .expect("Should create PEP JSON from existing JSON")
        .build();
    let record2 = PEPJSONBuilder::from_json(&data2, &["patient_id"])
        .expect("Should create PEP JSON from existing JSON")
        .build();

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
        &session,
        &session,
        &pseudo_secret,
        &enc_secret,
    );

    let mut batch = vec![encrypted1.clone(), encrypted2.clone()];
    let transcrypted_batch = transcrypt_batch(&mut batch, &transcryption_info, &mut rng)
        .unwrap()
        .into_vec();

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
        .map(|v| {
            #[cfg(feature = "elgamal3")]
            let decrypted = v.decrypt(&session_keys).unwrap();
            #[cfg(not(feature = "elgamal3"))]
            let decrypted = v.decrypt(&session_keys);

            decrypted.to_value().expect("Should convert to JSON")
        })
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
    let mut rng = rand::rng();

    // Setup keys and secrets
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());
    let enc_secret = EncryptionSecret::from("encryption-secret".as_bytes().to_vec());

    let domain_a = PseudonymizationDomain::from("domain-a");
    let domain_b = PseudonymizationDomain::from("domain-b");
    let session = EncryptionContext::from("session-1");

    let session_keys = make_session_keys(&global_secret, &session, &enc_secret);

    // Create two JSON values with DIFFERENT structures using standard JSON

    let data1 = json!({
        "patient_id": "patient-001",
        "diagnosis": "Flu",
        "temperature": 38.5
    });

    let data2 = json!({
        "user_id": "user-002",
        "name": "Bob",
        "age": 25,
        "active": true
    });

    // Convert to PEP JSON with different pseudonym fields
    let record1 = PEPJSONBuilder::from_json(&data1, &["patient_id"])
        .expect("Should create PEP JSON from existing JSON")
        .build();
    let record2 = PEPJSONBuilder::from_json(&data2, &["user_id"])
        .expect("Should create PEP JSON from existing JSON")
        .build();

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
        &session,
        &session,
        &pseudo_secret,
        &enc_secret,
    );

    // Attempt batch transcryption (this should fail because structures don't match)
    let mut batch = vec![encrypted1, encrypted2];
    let result = transcrypt_batch(&mut batch, &transcryption_info, &mut rng);

    // Verify that it returns an error due to inconsistent structure
    assert!(result.is_err(), "Should fail with inconsistent structures");
    match result {
        Err(libpep::core::batch::BatchError::InconsistentStructure { .. }) => {
            // Expected error
        }
        _ => panic!("Expected InconsistentStructure error"),
    }
}
