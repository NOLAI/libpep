#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::client::{decrypt, encrypt};
#[cfg(feature = "batch")]
use libpep::data::batch::EncryptedBatch;
#[cfg(all(feature = "batch", feature = "long"))]
use libpep::data::long::{LongAttribute, LongPseudonym};
#[cfg(all(feature = "batch", feature = "long"))]
use libpep::data::records::LongEncryptedRecord;
use libpep::data::simple::*;
use libpep::factors::contexts::*;
use libpep::factors::{
    AttributeRekeyInfo, EncryptionSecret, PseudonymRekeyInfo, PseudonymizationInfo,
    PseudonymizationSecret, TranscryptionInfo,
};
use libpep::keys::*;
#[cfg(feature = "elgamal3")]
use libpep::transcryptor::rerandomize;
use libpep::transcryptor::{pseudonymize, rekey, transcrypt};

#[test]
fn test_core_flow() {
    let rng = &mut rand::rng();
    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let (_attribute_global_public, attribute_global_secret) = make_attribute_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("domain1");
    let session1 = EncryptionContext::from("session1");
    let domain2 = PseudonymizationDomain::from("context2");
    let session2 = EncryptionContext::from("session2");

    let (pseudonym_session1_public, pseudonym_session1_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);
    let (_pseudonym_session2_public, pseudonym_session2_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session2, &enc_secret);
    let (attribute_session1_public, attribute_session1_secret) =
        make_attribute_session_keys(&attribute_global_secret, &session1, &enc_secret);
    let (_attribute_session2_public, attribute_session2_secret) =
        make_attribute_session_keys(&attribute_global_secret, &session2, &enc_secret);

    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &pseudonym_session1_public, rng);

    let data = Attribute::random(rng);
    let enc_data = encrypt(&data, &attribute_session1_public, rng);

    #[cfg(feature = "elgamal3")]
    let dec_pseudo =
        decrypt(&enc_pseudo, &pseudonym_session1_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let dec_pseudo = decrypt(&enc_pseudo, &pseudonym_session1_secret);
    #[cfg(feature = "elgamal3")]
    let dec_data =
        decrypt(&enc_data, &attribute_session1_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let dec_data = decrypt(&enc_data, &attribute_session1_secret);

    assert_eq!(pseudo, dec_pseudo);
    assert_eq!(data, dec_data);

    #[cfg(feature = "elgamal3")]
    {
        let rr_pseudo = rerandomize(&enc_pseudo, rng);
        let rr_data = rerandomize(&enc_data, rng);

        assert_ne!(enc_pseudo, rr_pseudo);
        assert_ne!(enc_data, rr_data);

        let rr_dec_pseudo =
            decrypt(&rr_pseudo, &pseudonym_session1_secret).expect("decryption should succeed");
        let rr_dec_data =
            decrypt(&rr_data, &attribute_session1_secret).expect("decryption should succeed");

        assert_eq!(pseudo, rr_dec_pseudo);
        assert_eq!(data, rr_dec_data);
    }

    let transcryption_info = TranscryptionInfo::new(
        &domain1,
        &domain2,
        &session1,
        &session2,
        &pseudo_secret,
        &enc_secret,
    );
    let attribute_rekey_info = transcryption_info.attribute;

    let rekeyed = rekey(&enc_data, &attribute_rekey_info);
    #[cfg(feature = "elgamal3")]
    let rekeyed_dec =
        decrypt(&rekeyed, &attribute_session2_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let rekeyed_dec = decrypt(&rekeyed, &attribute_session2_secret);

    assert_eq!(data, rekeyed_dec);

    #[cfg(feature = "elgamal3")]
    let pseudonymized = transcrypt(&enc_pseudo, &transcryption_info, rng);
    #[cfg(not(feature = "elgamal3"))]
    let pseudonymized = transcrypt(
        &enc_pseudo,
        &transcryption_info,
        &pseudonym_session1_public,
        rng,
    );
    #[cfg(feature = "elgamal3")]
    let pseudonymized_dec =
        decrypt(&pseudonymized, &pseudonym_session2_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let pseudonymized_dec = decrypt(&pseudonymized, &pseudonym_session2_secret);

    assert_ne!(pseudo, pseudonymized_dec);

    #[cfg(feature = "elgamal3")]
    let rev_pseudonymized = transcrypt(&pseudonymized, &transcryption_info.reverse(), rng);
    #[cfg(not(feature = "elgamal3"))]
    let rev_pseudonymized = {
        // After forward transcryption the pseudonym is now encrypted under session2's public key.
        let (pseudonym_session2_public, _) =
            make_pseudonym_session_keys(&pseudonym_global_secret, &session2, &enc_secret);
        transcrypt(
            &pseudonymized,
            &transcryption_info.reverse(),
            &pseudonym_session2_public,
            rng,
        )
    };
    #[cfg(feature = "elgamal3")]
    let rev_pseudonymized_dec =
        decrypt(&rev_pseudonymized, &pseudonym_session1_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let rev_pseudonymized_dec = decrypt(&rev_pseudonymized, &pseudonym_session1_secret);

    assert_eq!(pseudo, rev_pseudonymized_dec);
}
#[test]
#[cfg(all(feature = "batch", feature = "batch-pk"))]
fn test_batch() {
    let rng = &mut rand::rng();
    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let (_attribute_global_public, attribute_global_secret) = make_attribute_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("domain1");
    let session1 = EncryptionContext::from("session1");
    let domain2 = PseudonymizationDomain::from("domain2");
    let session2 = EncryptionContext::from("session2");

    let (pseudonym_session1_public, _pseudonym_session1_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);
    let (_pseudonym_session2_public, _pseudonym_session2_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session2, &enc_secret);
    let (attribute_session1_public, _attribute_session1_secret) =
        make_attribute_session_keys(&attribute_global_secret, &session1, &enc_secret);
    let (_attribute_session2_public, _attribute_session2_secret) =
        make_attribute_session_keys(&attribute_global_secret, &session2, &enc_secret);

    let mut attributes = vec![];
    let mut pseudonyms = vec![];
    for _ in 0..10 {
        attributes.push(encrypt(
            &Attribute::random(rng),
            &attribute_session1_public,
            rng,
        ));
        pseudonyms.push(encrypt(
            &Pseudonym::random(rng),
            &pseudonym_session1_public,
            rng,
        ));
    }

    let transcryption_info = TranscryptionInfo::new(
        &domain1,
        &domain2,
        &session1,
        &session2,
        &pseudo_secret,
        &enc_secret,
    );

    let attribute_rekey_info = transcryption_info.attribute;

    #[cfg(feature = "elgamal3")]
    let mut attribute_batch = EncryptedBatch::new(attributes).expect("structure check should pass");
    #[cfg(not(feature = "elgamal3"))]
    let mut attribute_batch = EncryptedBatch::new(attributes, attribute_session1_public)
        .expect("structure check should pass");
    attribute_batch
        .rekey(&attribute_rekey_info, rng)
        .expect("rekey batch");

    #[cfg(feature = "elgamal3")]
    let mut pseudonym_batch = EncryptedBatch::new(pseudonyms).expect("structure check should pass");
    #[cfg(not(feature = "elgamal3"))]
    let mut pseudonym_batch = EncryptedBatch::new(pseudonyms, pseudonym_session1_public)
        .expect("structure check should pass");
    pseudonym_batch
        .pseudonymize(&transcryption_info.pseudonym, rng)
        .expect("pseudonymize batch");
}

#[test]
#[cfg(all(feature = "batch", feature = "batch-pk", feature = "long"))]
fn test_batch_long() {
    let rng = &mut rand::rng();
    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let (_attribute_global_public, attribute_global_secret) = make_attribute_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("domain1");
    let session1 = EncryptionContext::from("session1");
    let domain2 = PseudonymizationDomain::from("domain2");
    let session2 = EncryptionContext::from("session2");

    #[cfg_attr(feature = "elgamal3", allow(unused_variables))]
    let (pseudonym_session1_public, pseudonym_session1_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session1, &enc_secret);
    let (_pseudonym_session2_public, pseudonym_session2_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session2, &enc_secret);
    #[cfg_attr(feature = "elgamal3", allow(unused_variables))]
    let (attribute_session1_public, attribute_session1_secret) =
        make_attribute_session_keys(&attribute_global_secret, &session1, &enc_secret);
    let (_attribute_session2_public, attribute_session2_secret) =
        make_attribute_session_keys(&attribute_global_secret, &session2, &enc_secret);

    // Create long pseudonyms and attributes with padding
    let test_strings = [
        "User 1 identifier string that spans multiple blocks",
        "User 2 identifier string that spans multiple blocks",
        "User 3 identifier string that spans multiple blocks",
    ];

    let long_pseudonyms: Vec<_> = test_strings
        .iter()
        .map(|s| {
            let long_pseudo = LongPseudonym::from_string_padded(s);
            encrypt(&long_pseudo, &pseudonym_session1_public, rng)
        })
        .collect();

    let long_attributes: Vec<_> = test_strings
        .iter()
        .map(|s| {
            let long_attr = LongAttribute::from_string_padded(s);
            encrypt(&long_attr, &attribute_session1_public, rng)
        })
        .collect();

    let transcryption_info = TranscryptionInfo::new(
        &domain1,
        &domain2,
        &session1,
        &session2,
        &pseudo_secret,
        &enc_secret,
    );

    // Test batch rekeying of long pseudonyms
    #[cfg(feature = "elgamal3")]
    let mut long_pseudonym_batch = EncryptedBatch::new(long_pseudonyms.clone()).expect("structure");
    #[cfg(not(feature = "elgamal3"))]
    let mut long_pseudonym_batch =
        EncryptedBatch::new(long_pseudonyms.clone(), pseudonym_session1_public).expect("structure");
    long_pseudonym_batch
        .rekey(&transcryption_info.pseudonym.k, rng)
        .expect("rekey");
    assert_eq!(long_pseudonym_batch.len(), 3);

    // Test batch rekeying of long attributes
    #[cfg(feature = "elgamal3")]
    let mut long_attribute_batch = EncryptedBatch::new(long_attributes.clone()).expect("structure");
    #[cfg(not(feature = "elgamal3"))]
    let mut long_attribute_batch =
        EncryptedBatch::new(long_attributes.clone(), attribute_session1_public).expect("structure");
    long_attribute_batch
        .rekey(&transcryption_info.attribute, rng)
        .expect("rekey");
    assert_eq!(long_attribute_batch.len(), 3);

    // Verify decryption works after rekeying
    for rekeyed_attr in long_attribute_batch.as_items().iter() {
        #[cfg(feature = "elgamal3")]
        let decrypted =
            decrypt(rekeyed_attr, &attribute_session2_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(rekeyed_attr, &attribute_session2_secret);
        let decrypted_string = decrypted.to_string_padded().unwrap();
        assert!(test_strings.contains(&decrypted_string.as_str()));
    }

    // Test batch pseudonymization of long pseudonyms
    #[cfg(feature = "elgamal3")]
    let mut long_pseudo_pseudonymize_batch =
        EncryptedBatch::new(long_pseudonyms.clone()).expect("structure");
    #[cfg(not(feature = "elgamal3"))]
    let mut long_pseudo_pseudonymize_batch =
        EncryptedBatch::new(long_pseudonyms.clone(), pseudonym_session1_public).expect("structure");
    long_pseudo_pseudonymize_batch
        .pseudonymize(&transcryption_info.pseudonym, rng)
        .expect("pseudonymize");
    assert_eq!(long_pseudo_pseudonymize_batch.len(), 3);

    // Verify decryption works after pseudonymization (values will be different due to domain change)
    for pseudonymized_pseudo in long_pseudo_pseudonymize_batch.as_items().iter() {
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(pseudonymized_pseudo, &pseudonym_session2_secret)
            .expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(pseudonymized_pseudo, &pseudonym_session2_secret);
        // After pseudonymization, the value changes but we can verify it decrypts
        assert_eq!(decrypted.0.len(), 4); // String padded to 4 blocks
    }

    // Test batch transcryption of long data
    let data: Vec<_> = (0..3)
        .map(|i| {
            let pseudo_str = format!("Entity {} pseudonym data", i);
            let attr_str = format!("Entity {} attribute data", i);

            let long_pseudonyms = vec![{
                let long_pseudo = LongPseudonym::from_string_padded(&pseudo_str);
                encrypt(&long_pseudo, &pseudonym_session1_public, rng)
            }];

            let long_attributes = vec![{
                let long_attr = LongAttribute::from_string_padded(&attr_str);
                encrypt(&long_attr, &attribute_session1_public, rng)
            }];

            LongEncryptedRecord::new(long_pseudonyms, long_attributes)
        })
        .collect();

    #[cfg(feature = "elgamal3")]
    let mut record_batch = EncryptedBatch::new(data).expect("structure");
    #[cfg(not(feature = "elgamal3"))]
    let session_keys_1 = SessionKeys {
        pseudonym: PseudonymSessionKeys {
            public: pseudonym_session1_public,
            secret: pseudonym_session1_secret,
        },
        attribute: AttributeSessionKeys {
            public: attribute_session1_public,
            secret: attribute_session1_secret,
        },
    };
    #[cfg(not(feature = "elgamal3"))]
    let mut record_batch = EncryptedBatch::new(data, session_keys_1).expect("structure");
    record_batch
        .transcrypt(&transcryption_info, rng)
        .expect("transcrypt");
    assert_eq!(record_batch.len(), 3);

    // Verify each entity has one pseudonym and one attribute
    for record in record_batch.as_items().iter() {
        assert_eq!(record.pseudonyms.len(), 1);
        assert_eq!(record.attributes.len(), 1);

        // Verify attributes decrypt correctly (they're rekeyed, not pseudonymized)
        #[cfg(feature = "elgamal3")]
        let decrypted_attr = decrypt(&record.attributes[0], &attribute_session2_secret)
            .expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted_attr = decrypt(&record.attributes[0], &attribute_session2_secret);
        let attr_str = decrypted_attr.to_string_padded().unwrap();
        assert!(attr_str.starts_with("Entity ") && attr_str.ends_with(" attribute data"));
    }
}

// Tests for polymorphic transcryption operations
// Moved from src/lib/core/transcryption.rs

#[test]
fn test_pseudonymize_changes_encryption_context() {
    let mut rng = rand::rng();
    let (_, global_sk) = make_global_keys(&mut rng);
    let from_ctx = EncryptionContext::from("from");
    let to_ctx = EncryptionContext::from("to");
    let enc_secret = EncryptionSecret::from(b"enc".to_vec());
    let pseudo_secret = PseudonymizationSecret::from(b"pseudo".to_vec());
    let from_domain = PseudonymizationDomain::from("domain-from");
    let to_domain = PseudonymizationDomain::from("domain-to");

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

    let pseudonym = Pseudonym::random(&mut rng);
    let encrypted = encrypt(&pseudonym, &from_session.pseudonym.public, &mut rng);

    let info = PseudonymizationInfo::new(
        &from_domain,
        &to_domain,
        &from_ctx,
        &to_ctx,
        &pseudo_secret,
        &enc_secret,
    );
    #[cfg(feature = "elgamal3")]
    let pseudonymized = pseudonymize(&encrypted, &info, &mut rng);
    #[cfg(not(feature = "elgamal3"))]
    let pseudonymized = pseudonymize(&encrypted, &info, &from_session.pseudonym.public, &mut rng);

    #[cfg(feature = "elgamal3")]
    let decrypted = decrypt(&pseudonymized, &to_session.pseudonym.secret).expect("decrypt failed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = decrypt(&pseudonymized, &to_session.pseudonym.secret);
    assert_ne!(pseudonym, decrypted);
}

#[test]
fn test_rekey_pseudonym_preserves_plaintext() {
    let mut rng = rand::rng();
    let (_, global_sk) = make_global_keys(&mut rng);
    let from_ctx = EncryptionContext::from("from");
    let to_ctx = EncryptionContext::from("to");
    let enc_secret = EncryptionSecret::from(b"enc".to_vec());

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

    let pseudonym = Pseudonym::random(&mut rng);
    let encrypted = encrypt(&pseudonym, &from_session.pseudonym.public, &mut rng);

    let rekey_info = PseudonymRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret);
    let rekeyed = rekey(&encrypted, &rekey_info);

    #[cfg(feature = "elgamal3")]
    let decrypted = decrypt(&rekeyed, &to_session.pseudonym.secret).expect("decrypt failed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = decrypt(&rekeyed, &to_session.pseudonym.secret);
    assert_eq!(pseudonym, decrypted);
}

#[test]
fn test_rekey_attribute_preserves_plaintext() {
    let mut rng = rand::rng();
    let (_, global_sk) = make_global_keys(&mut rng);
    let from_ctx = EncryptionContext::from("from");
    let to_ctx = EncryptionContext::from("to");
    let enc_secret = EncryptionSecret::from(b"enc".to_vec());

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

    let attribute = Attribute::random(&mut rng);
    let encrypted = encrypt(&attribute, &from_session.attribute.public, &mut rng);

    let rekey_info = AttributeRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret);
    let rekeyed = rekey(&encrypted, &rekey_info);

    #[cfg(feature = "elgamal3")]
    let decrypted = decrypt(&rekeyed, &to_session.attribute.secret).expect("decrypt failed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = decrypt(&rekeyed, &to_session.attribute.secret);
    assert_eq!(attribute, decrypted);
}

#[test]
fn test_transcrypt_pseudonym_applies_pseudonymization() {
    let mut rng = rand::rng();
    let (_, global_sk) = make_global_keys(&mut rng);
    let from_ctx = EncryptionContext::from("from");
    let to_ctx = EncryptionContext::from("to");
    let enc_secret = EncryptionSecret::from(b"enc".to_vec());
    let pseudo_secret = PseudonymizationSecret::from(b"pseudo".to_vec());
    let from_domain = PseudonymizationDomain::from("domain-from");
    let to_domain = PseudonymizationDomain::from("domain-to");

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

    let pseudonym = Pseudonym::random(&mut rng);
    let encrypted = encrypt(&pseudonym, &from_session.pseudonym.public, &mut rng);

    let info = TranscryptionInfo::new(
        &from_domain,
        &to_domain,
        &from_ctx,
        &to_ctx,
        &pseudo_secret,
        &enc_secret,
    );
    #[cfg(feature = "elgamal3")]
    let transcrypted = transcrypt(&encrypted, &info, &mut rng);
    #[cfg(not(feature = "elgamal3"))]
    let transcrypted = transcrypt(&encrypted, &info, &from_session.pseudonym.public, &mut rng);

    #[cfg(feature = "elgamal3")]
    let decrypted = decrypt(&transcrypted, &to_session.pseudonym.secret).expect("decrypt failed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = decrypt(&transcrypted, &to_session.pseudonym.secret);
    assert_ne!(pseudonym, decrypted);
}

#[test]
fn test_transcrypt_attribute_rekeys_only() {
    let mut rng = rand::rng();
    let (_, global_sk) = make_global_keys(&mut rng);
    let from_ctx = EncryptionContext::from("from");
    let to_ctx = EncryptionContext::from("to");
    let enc_secret = EncryptionSecret::from(b"enc".to_vec());
    let pseudo_secret = PseudonymizationSecret::from(b"pseudo".to_vec());
    let from_domain = PseudonymizationDomain::from("domain-from");
    let to_domain = PseudonymizationDomain::from("domain-to");

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

    let attribute = Attribute::random(&mut rng);
    let encrypted = encrypt(&attribute, &from_session.attribute.public, &mut rng);

    let info = TranscryptionInfo::new(
        &from_domain,
        &to_domain,
        &from_ctx,
        &to_ctx,
        &pseudo_secret,
        &enc_secret,
    );
    #[cfg(feature = "elgamal3")]
    let transcrypted = transcrypt(&encrypted, &info, &mut rng);
    #[cfg(not(feature = "elgamal3"))]
    let transcrypted = transcrypt(&encrypted, &info, &from_session.attribute.public, &mut rng);

    #[cfg(feature = "elgamal3")]
    let decrypted = decrypt(&transcrypted, &to_session.attribute.secret).expect("decrypt failed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = decrypt(&transcrypted, &to_session.attribute.secret);
    assert_eq!(attribute, decrypted);
}

#[test]
fn test_polymorphic_rekey_works_for_both_types() {
    let mut rng = rand::rng();
    let (_, global_sk) = make_global_keys(&mut rng);
    let from_ctx = EncryptionContext::from("from");
    let to_ctx = EncryptionContext::from("to");
    let enc_secret = EncryptionSecret::from(b"enc".to_vec());

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

    // Test with pseudonym
    let pseudonym = Pseudonym::random(&mut rng);
    let enc_p = encrypt(&pseudonym, &from_session.pseudonym.public, &mut rng);
    let rekey_p = PseudonymRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret);
    let rekeyed_p = rekey(&enc_p, &rekey_p);
    #[cfg(feature = "elgamal3")]
    let decrypted_p = decrypt(&rekeyed_p, &to_session.pseudonym.secret).expect("decrypt failed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_p = decrypt(&rekeyed_p, &to_session.pseudonym.secret);
    assert_eq!(pseudonym, decrypted_p);

    // Test with attribute
    let attribute = Attribute::random(&mut rng);
    let enc_a = encrypt(&attribute, &from_session.attribute.public, &mut rng);
    let rekey_a = AttributeRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret);
    let rekeyed_a = rekey(&enc_a, &rekey_a);
    #[cfg(feature = "elgamal3")]
    let decrypted_a = decrypt(&rekeyed_a, &to_session.attribute.secret).expect("decrypt failed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_a = decrypt(&rekeyed_a, &to_session.attribute.secret);
    assert_eq!(attribute, decrypted_a);
}
