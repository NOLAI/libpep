#![cfg(feature = "json")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::data::json::builder::PEPJSONBuilder;
use libpep::data::traits::{Encryptable, Encrypted, Transcryptable};
use libpep::factors::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::factors::secrets::{EncryptionSecret, PseudonymizationSecret};
use libpep::factors::TranscryptionInfo;
use libpep::keys::{make_global_keys, make_session_keys};
use libpep::pep_json;
#[cfg(feature = "batch")]
use libpep::transcryptor::transcrypt_batch;
use serde_json::json;

#[test]
fn test_json_transcryption_with_macro() {
    let mut rng = rand::rng();

    // Setup keys and secrets
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());
    let enc_secret = EncryptionSecret::from("encryption-secret".as_bytes().to_vec());

    let domain_a = PseudonymizationDomain::from("domain-a");
    let domain_b = PseudonymizationDomain::from("domain-b");
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

    // Transcrypt from domain A to domain B
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
        Err(libpep::transcryptor::BatchError::InconsistentStructure { .. }) => {
            // Expected error
        }
        _ => panic!("Expected InconsistentStructure error"),
    }
}

#[test]
fn test_json_transcryption_with_client_and_transcryptor() {
    let mut rng = rand::rng();

    // Setup keys and secrets
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());
    let enc_secret = EncryptionSecret::from("encryption-secret".as_bytes().to_vec());

    let domain_a = PseudonymizationDomain::from("domain-a");
    let domain_b = PseudonymizationDomain::from("domain-b");
    let session = EncryptionContext::from("session-1");

    let session_keys = make_session_keys(&global_secret, &session, &enc_secret);

    // Create client and transcryptor
    let client = libpep::client::Client::new(session_keys);
    let transcryptor =
        libpep::transcryptor::Transcryptor::new(pseudo_secret.clone(), enc_secret.clone());

    // Create patient record JSON data
    let patient_data = json!({
        "patient_id": "patient-54321",
        "name": "John Doe",
        "diagnosis": "Healthy",
        "temperature": 36.6
    });

    // Convert to PEP JSON, marking "patient_id" as a pseudonym field
    let patient_record = PEPJSONBuilder::from_json(&patient_data, &["patient_id"])
        .expect("Should create PEP JSON from existing JSON")
        .build();

    // Encrypt using the client
    let encrypted = client.encrypt(&patient_record, &mut rng);

    // Decrypt to verify original
    #[cfg(feature = "elgamal3")]
    let decrypted_original = client.decrypt(&encrypted).unwrap();
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_original = client.decrypt(&encrypted);

    let json_original = decrypted_original
        .to_value()
        .expect("Should convert to JSON");
    assert_eq!(json_original["patient_id"], "patient-54321");
    assert_eq!(json_original["name"], "John Doe");
    assert_eq!(json_original["diagnosis"], "Healthy");
    assert_eq!(json_original["temperature"].as_f64().unwrap(), 36.6);

    // Transcrypt from domain A to domain B using the transcryptor
    let transcryption_info =
        transcryptor.transcryption_info(&domain_a, &domain_b, &session, &session);

    let transcrypted = transcryptor.transcrypt(&encrypted, &transcryption_info);

    // Verify that the encrypted structures are different after transcryption
    assert_ne!(
        format!("{:?}", encrypted),
        format!("{:?}", transcrypted),
        "Encrypted values should be different after transcryption"
    );

    // Decrypt transcrypted data
    #[cfg(feature = "elgamal3")]
    let decrypted_transcrypted = client.decrypt(&transcrypted).unwrap();
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_transcrypted = client.decrypt(&transcrypted);

    let json_transcrypted = decrypted_transcrypted
        .to_value()
        .expect("Should convert to JSON");

    // Attributes should remain the same, but pseudonym should be different
    assert_eq!(json_transcrypted["name"], "John Doe");
    assert_eq!(json_transcrypted["diagnosis"], "Healthy");
    assert_eq!(json_transcrypted["temperature"].as_f64().unwrap(), 36.6);
    assert_ne!(
        json_transcrypted["patient_id"], "patient-54321",
        "Pseudonym should be different after cross-domain transcryption"
    );
}

/// Test full round-trip: PEPJSON → Encrypt → Transcrypt → Decrypt → JSON → PEPJSON → Repeat
///
/// This test demonstrates that pseudonyms maintain their correct type (short vs long)
/// after transcryption and JSON serialization round-trips.
#[test]
fn test_pseudonym_roundtrip_with_json_serialization() {
    let mut rng = rand::rng();

    // Setup keys and secrets
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudonymization_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());
    let encryption_secret = EncryptionSecret::from("encryption-secret".as_bytes().to_vec());

    let session = EncryptionContext::from("session-1");
    let session_keys = make_session_keys(&global_secret, &session, &encryption_secret);

    // Create client and transcryptor
    let client = libpep::client::Client::new(session_keys);
    let transcryptor = libpep::transcryptor::Transcryptor::new(
        pseudonymization_secret.clone(),
        encryption_secret.clone(),
    );

    // Create PEPJSON with both short and long pseudonyms using pep_json! macro
    let original_pep = pep_json!({
        "short_id": pseudonym("john"),  // 4 bytes → single Pseudonym
        "long_id": pseudonym("user@example.com"),  // 17 bytes → LongPseudonym (2 blocks)
        "name": "Alice",
        "age": 30
    });

    // 1. Encrypt the PEPJSON using the client
    let encrypted = client.encrypt(&original_pep, &mut rng);

    // 2. Transcrypt (pseudonymize + rekey) the pseudonyms
    let domain_from = PseudonymizationDomain::from("domain-a");
    let domain_to = PseudonymizationDomain::from("domain-b");

    let transcryption_info =
        transcryptor.transcryption_info(&domain_from, &domain_to, &session, &session);

    let transcrypted = transcryptor.transcrypt(&encrypted, &transcryption_info);

    // 3. Decrypt back to PEPJSONValue using the client
    #[cfg(feature = "elgamal3")]
    let decrypted = client.decrypt(&transcrypted).unwrap();
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = client.decrypt(&transcrypted);

    // Verify structure is preserved (name and age should still be there)
    let json_value = decrypted.to_value().unwrap();
    assert_eq!(json_value["name"], "Alice");
    assert_eq!(json_value["age"], 30);

    // Pseudonyms should be hex-encoded (64 chars for short, 128 for long)
    let short_id_hex = json_value["short_id"].as_str().unwrap();
    let long_id_hex = json_value["long_id"].as_str().unwrap();
    assert_eq!(
        short_id_hex.len(),
        64,
        "Short pseudonym should be 64 hex chars"
    );
    assert_eq!(
        long_id_hex.len(),
        128,
        "Long pseudonym should be 128 hex chars"
    );

    // 4. Create PEPJSON from the hex values using pep_json! macro
    let transcrypted_pep = pep_json!({
        "short_id": pseudonym(short_id_hex),  // Reconstructs as Pseudonym (1 block)
        "long_id": pseudonym(long_id_hex),    // Reconstructs as LongPseudonym (2 blocks)
        "name": "Alice",
        "age": 30
    });

    // 5. Encrypt the transcrypted PEPJSON
    let encrypted_b = client.encrypt(&transcrypted_pep, &mut rng);

    // 6. Transcrypt back (domain-b → domain-a)
    let transcryption_info_back =
        transcryptor.transcryption_info(&domain_to, &domain_from, &session, &session);

    let transcrypted_back = transcryptor.transcrypt(&encrypted_b, &transcryption_info_back);

    // 7. Decrypt and verify we get back the original values
    #[cfg(feature = "elgamal3")]
    let decrypted_back = client.decrypt(&transcrypted_back).unwrap();
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_back = client.decrypt(&transcrypted_back);

    let json_back = decrypted_back.to_value().unwrap();

    // Should have the original pseudonym values
    assert_eq!(json_back["short_id"], "john");
    assert_eq!(json_back["long_id"], "user@example.com");
    assert_eq!(json_back["name"], "Alice");
    assert_eq!(json_back["age"], 30);
}

/// Test full round-trip using PEPJSONBuilder: Build → Encrypt → Transcrypt → Decrypt → Build → Repeat
///
/// This test demonstrates the same flow as test_pseudonym_roundtrip_with_json_serialization
/// but uses the builder API instead of the pep_json! macro.
#[test]
fn test_pseudonym_roundtrip_with_builder() {
    use libpep::data::json::data::PEPJSONValue;

    let mut rng = rand::rng();

    // Setup keys and secrets
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudonymization_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());
    let encryption_secret = EncryptionSecret::from("encryption-secret".as_bytes().to_vec());

    let session = EncryptionContext::from("session-1");
    let session_keys = make_session_keys(&global_secret, &session, &encryption_secret);

    // Create client and transcryptor
    let client = libpep::client::Client::new(session_keys);
    let transcryptor = libpep::transcryptor::Transcryptor::new(
        pseudonymization_secret.clone(),
        encryption_secret.clone(),
    );

    // 1. Create PEPJSON with both short and long pseudonyms using the builder
    let original_pep = PEPJSONBuilder::new()
        .pseudonym("short_id", "john") // 4 bytes → Pseudonym (1 block)
        .pseudonym("long_id", "user@example.com") // 17 bytes → LongPseudonym (2 blocks)
        .attribute("name", json!("Alice"))
        .attribute("age", json!(30))
        .build();

    // Verify the types are correct after initial construction
    if let PEPJSONValue::Object(fields) = &original_pep {
        assert!(matches!(
            fields.get("short_id"),
            Some(PEPJSONValue::Pseudonym(_))
        ));
        assert!(
            matches!(fields.get("long_id"), Some(PEPJSONValue::LongPseudonym(lp)) if lp.len() == 2)
        );
    }

    // 2. Encrypt the PEPJSON using the client
    let encrypted = client.encrypt(&original_pep, &mut rng);

    // 3. Transcrypt (pseudonymize + rekey) the pseudonyms
    let domain_from = PseudonymizationDomain::from("domain-a");
    let domain_to = PseudonymizationDomain::from("domain-b");

    let transcryption_info =
        transcryptor.transcryption_info(&domain_from, &domain_to, &session, &session);

    let transcrypted = transcryptor.transcrypt(&encrypted, &transcryption_info);

    // 4. Decrypt back to PEPJSONValue using the client
    #[cfg(feature = "elgamal3")]
    let decrypted = client.decrypt(&transcrypted).unwrap();
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = client.decrypt(&transcrypted);

    // Verify structure is preserved (name and age should still be there)
    let json_value = decrypted.to_value().unwrap();
    assert_eq!(json_value["name"], "Alice");
    assert_eq!(json_value["age"], 30);

    // Pseudonyms should be hex-encoded (64 chars for short, 128 for long)
    let short_id_hex = json_value["short_id"].as_str().unwrap();
    let long_id_hex = json_value["long_id"].as_str().unwrap();
    assert_eq!(
        short_id_hex.len(),
        64,
        "Short pseudonym should be 64 hex chars"
    );
    assert_eq!(
        long_id_hex.len(),
        128,
        "Long pseudonym should be 128 hex chars"
    );

    // 5. Rebuild PEPJSON from the hex values using the builder
    let transcrypted_pep = PEPJSONBuilder::new()
        .pseudonym("short_id", short_id_hex) // Reconstructs as Pseudonym (1 block)
        .pseudonym("long_id", long_id_hex) // Reconstructs as LongPseudonym (2 blocks)
        .attribute("name", json!("Alice"))
        .attribute("age", json!(30))
        .build();

    // Verify the types are correct after reconstruction
    if let PEPJSONValue::Object(fields) = &transcrypted_pep {
        assert!(matches!(
            fields.get("short_id"),
            Some(PEPJSONValue::Pseudonym(_))
        ));
        assert!(matches!(
            fields.get("long_id"),
            Some(PEPJSONValue::LongPseudonym(lp)) if lp.len() == 2
        ));
    }

    // 6. Encrypt the transcrypted PEPJSON
    let encrypted_b = client.encrypt(&transcrypted_pep, &mut rng);

    // 7. Transcrypt back (domain-b → domain-a)
    let transcryption_info_back =
        transcryptor.transcryption_info(&domain_to, &domain_from, &session, &session);

    let transcrypted_back = transcryptor.transcrypt(&encrypted_b, &transcryption_info_back);

    // 8. Decrypt and verify we get back the original values
    #[cfg(feature = "elgamal3")]
    let decrypted_back = client.decrypt(&transcrypted_back).unwrap();
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_back = client.decrypt(&transcrypted_back);

    let json_back = decrypted_back.to_value().unwrap();

    // Should have the original pseudonym values
    assert_eq!(json_back["short_id"], "john");
    assert_eq!(json_back["long_id"], "user@example.com");
    assert_eq!(json_back["name"], "Alice");
    assert_eq!(json_back["age"], 30);
}

/// Test that unicode characters work correctly in pseudonyms and attributes
#[test]
fn test_unicode_pseudonyms_and_attributes() {
    let mut rng = rand::rng();

    // Setup keys and secrets
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudonymization_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());
    let encryption_secret = EncryptionSecret::from("encryption-secret".as_bytes().to_vec());

    let session = EncryptionContext::from("session-1");
    let session_keys = make_session_keys(&global_secret, &session, &encryption_secret);

    // Create client and transcryptor
    let client = libpep::client::Client::new(session_keys);
    let transcryptor = libpep::transcryptor::Transcryptor::new(
        pseudonymization_secret.clone(),
        encryption_secret.clone(),
    );

    // Create PEPJSON with unicode characters
    let original_pep = pep_json!({
        "emoji_id": pseudonym("🔒👤"),  // Emoji (short, 8 bytes UTF-8)
        "chinese_id": pseudonym("用户@例子.中国"),  // Chinese email (long, ~21 bytes)
        "arabic_name": "مرحبا بك",  // Arabic attribute
        "cyrillic_name": "Здравствуй",  // Cyrillic attribute
        "mixed": "Café™ ñoño 你好 🏥",  // Mixed unicode attribute
        "age": 25
    });

    // 1. Encrypt
    let encrypted = client.encrypt(&original_pep, &mut rng);

    // 2. Transcrypt to another domain
    let domain_from = PseudonymizationDomain::from("domain-a");
    let domain_to = PseudonymizationDomain::from("domain-b");

    let transcryption_info =
        transcryptor.transcryption_info(&domain_from, &domain_to, &session, &session);

    let transcrypted = transcryptor.transcrypt(&encrypted, &transcryption_info);

    // 3. Decrypt
    #[cfg(feature = "elgamal3")]
    let decrypted = client.decrypt(&transcrypted).unwrap();
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = client.decrypt(&transcrypted);

    let json_value = decrypted.to_value().unwrap();

    // Verify attributes with unicode preserved
    assert_eq!(json_value["arabic_name"], "مرحبا بك");
    assert_eq!(json_value["cyrillic_name"], "Здравствуй");
    assert_eq!(json_value["mixed"], "Café™ ñoño 你好 🏥");
    assert_eq!(json_value["age"], 25);

    // Pseudonyms should be hex-encoded
    let emoji_id_hex = json_value["emoji_id"].as_str().unwrap();
    let chinese_id_hex = json_value["chinese_id"].as_str().unwrap();

    // Emoji fits in 1 block (8 bytes UTF-8)
    assert_eq!(
        emoji_id_hex.len(),
        64,
        "Emoji pseudonym should be 64 hex chars"
    );

    // Chinese email is longer and needs multiple blocks
    assert!(
        chinese_id_hex.len() >= 64,
        "Chinese email should need at least 1 block"
    );
    assert_eq!(
        chinese_id_hex.len() % 64,
        0,
        "Should be multiple of 64 chars"
    );

    // 4. Reconstruct PEPJSON from hex values
    let transcrypted_pep = pep_json!({
        "emoji_id": pseudonym(emoji_id_hex),
        "chinese_id": pseudonym(chinese_id_hex),
        "arabic_name": "مرحبا بك",
        "cyrillic_name": "Здравствуй",
        "mixed": "Café™ ñoño 你好 🏥",
        "age": 25
    });

    // 5. Encrypt again
    let encrypted_b = client.encrypt(&transcrypted_pep, &mut rng);

    // 6. Transcrypt back
    let transcryption_info_back =
        transcryptor.transcryption_info(&domain_to, &domain_from, &session, &session);

    let transcrypted_back = transcryptor.transcrypt(&encrypted_b, &transcryption_info_back);

    // 7. Decrypt and verify original unicode values restored
    #[cfg(feature = "elgamal3")]
    let decrypted_back = client.decrypt(&transcrypted_back).unwrap();
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_back = client.decrypt(&transcrypted_back);

    let json_back = decrypted_back.to_value().unwrap();

    // Verify all unicode preserved through full round-trip
    assert_eq!(json_back["emoji_id"], "🔒👤");
    assert_eq!(json_back["chinese_id"], "用户@例子.中国");
    assert_eq!(json_back["arabic_name"], "مرحبا بك");
    assert_eq!(json_back["cyrillic_name"], "Здравствуй");
    assert_eq!(json_back["mixed"], "Café™ ñoño 你好 🏥");
    assert_eq!(json_back["age"], 25);
}
