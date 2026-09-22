#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::client::{decrypt, encrypt};
use libpep::contexts::*;
#[cfg(all(feature = "batch", feature = "long"))]
use libpep::data::long::{LongAttribute, LongPseudonym};
#[cfg(all(feature = "batch", feature = "long"))]
use libpep::data::records::LongEncryptedRecord;
use libpep::data::simple::*;
use libpep::factors::{
    AttributeRekeyInfo, EncryptionSecret, PseudonymRekeyInfo, PseudonymizationInfo,
    PseudonymizationSecret, TranscryptionInfo,
};
use libpep::keys::*;
use libpep::protocol::Context;
#[cfg(feature = "elgamal3")]
use libpep::transcryptor::rerandomize;
#[cfg(all(feature = "batch", feature = "long"))]
use libpep::transcryptor::transcrypt_batch;
use libpep::transcryptor::{pseudonymize, rekey, transcrypt};
#[cfg(feature = "batch")]
use libpep::transcryptor::{pseudonymize_batch, rekey_batch};
#[cfg(feature = "batch")]
use std::collections::HashSet;

/// Call a transcryption function with the argument list of the active ciphertext encoding: with
/// `elgamal3` the ciphertext carries its public key, otherwise it is passed explicitly.
macro_rules! tx {
    ($f:path, $enc:expr, $info:expr, $pk:expr, $rng:expr) => {{
        #[cfg(feature = "elgamal3")]
        let result = {
            let _ = &$pk;
            $f($enc, $info, $rng)
        };
        #[cfg(not(feature = "elgamal3"))]
        let result = $f($enc, $info, $pk, $rng);
        result
    }};
}

/// Decrypt with the active ciphertext encoding (with `elgamal3`, decryption can fail).
#[cfg(feature = "batch")]
macro_rules! dec {
    ($enc:expr, $sk:expr) => {{
        #[cfg(feature = "elgamal3")]
        let result = decrypt($enc, $sk).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let result = decrypt($enc, $sk);
        result
    }};
}

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

    let (pseudonym_session1_public, pseudonym_session1_secret) = make_pseudonym_session_keys(
        &pseudonym_global_secret,
        &session1,
        &enc_secret,
        &Context::default(),
    );
    let (pseudonym_session2_public, pseudonym_session2_secret) = make_pseudonym_session_keys(
        &pseudonym_global_secret,
        &session2,
        &enc_secret,
        &Context::default(),
    );
    let (attribute_session1_public, attribute_session1_secret) = make_attribute_session_keys(
        &attribute_global_secret,
        &session1,
        &enc_secret,
        &Context::default(),
    );
    let (_attribute_session2_public, attribute_session2_secret) = make_attribute_session_keys(
        &attribute_global_secret,
        &session2,
        &enc_secret,
        &Context::default(),
    );

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
        &Context::default(),
    );
    let attribute_rekey_info = transcryption_info.attribute;

    let rekeyed = tx!(
        rekey,
        &enc_data,
        &attribute_rekey_info,
        &attribute_session1_public,
        rng
    );
    #[cfg(feature = "elgamal3")]
    let rekeyed_dec =
        decrypt(&rekeyed, &attribute_session2_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let rekeyed_dec = decrypt(&rekeyed, &attribute_session2_secret);

    assert_eq!(data, rekeyed_dec);

    let pseudonymized = tx!(
        transcrypt,
        &enc_pseudo,
        &transcryption_info,
        &pseudonym_session1_public,
        rng
    );
    #[cfg(feature = "elgamal3")]
    let pseudonymized_dec =
        decrypt(&pseudonymized, &pseudonym_session2_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let pseudonymized_dec = decrypt(&pseudonymized, &pseudonym_session2_secret);

    assert_ne!(pseudo, pseudonymized_dec);

    let rev_pseudonymized = tx!(
        transcrypt,
        &pseudonymized,
        &transcryption_info.reverse(),
        &pseudonym_session2_public,
        rng
    );
    #[cfg(feature = "elgamal3")]
    let rev_pseudonymized_dec =
        decrypt(&rev_pseudonymized, &pseudonym_session1_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let rev_pseudonymized_dec = decrypt(&rev_pseudonymized, &pseudonym_session1_secret);

    assert_eq!(pseudo, rev_pseudonymized_dec);
}
#[test]
#[cfg(feature = "batch")]
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

    let (pseudonym_session1_public, _pseudonym_session1_secret) = make_pseudonym_session_keys(
        &pseudonym_global_secret,
        &session1,
        &enc_secret,
        &Context::default(),
    );
    let (_pseudonym_session2_public, pseudonym_session2_secret) = make_pseudonym_session_keys(
        &pseudonym_global_secret,
        &session2,
        &enc_secret,
        &Context::default(),
    );
    let (attribute_session1_public, _attribute_session1_secret) = make_attribute_session_keys(
        &attribute_global_secret,
        &session1,
        &enc_secret,
        &Context::default(),
    );
    let (_attribute_session2_public, attribute_session2_secret) = make_attribute_session_keys(
        &attribute_global_secret,
        &session2,
        &enc_secret,
        &Context::default(),
    );

    let mut attributes = vec![];
    let mut attribute_values = vec![];
    let mut pseudonyms = vec![];
    let mut pseudonym_values = vec![];
    for _ in 0..10 {
        let attribute = Attribute::random(rng);
        attributes.push(encrypt(&attribute, &attribute_session1_public, rng));
        attribute_values.push(attribute);
        let pseudonym = Pseudonym::random(rng);
        pseudonyms.push(encrypt(&pseudonym, &pseudonym_session1_public, rng));
        pseudonym_values.push(pseudonym);
    }

    let transcryption_info = TranscryptionInfo::new(
        &domain1,
        &domain2,
        &session1,
        &session2,
        &pseudo_secret,
        &enc_secret,
        &Context::default(),
    );

    let attribute_rekey_info = transcryption_info.attribute;

    // Batch operations apply the same transformation as the single-item functions (compared after
    // decryption, since every transcryption rerandomizes), but shuffle the order so that outputs
    // cannot be linked to inputs by position.
    let rekeyed = tx!(
        rekey_batch,
        &mut attributes.clone(),
        &attribute_rekey_info,
        &attribute_session1_public,
        rng
    )
    .unwrap();
    let decrypted: Vec<_> = rekeyed
        .iter()
        .map(|a| dec!(a, &attribute_session2_secret))
        .collect();
    assert_eq!(
        decrypted.iter().collect::<HashSet<_>>(),
        attribute_values.iter().collect::<HashSet<_>>()
    );
    assert_ne!(decrypted, attribute_values, "batch should be shuffled");

    let pseudonymized = tx!(
        pseudonymize_batch,
        &mut pseudonyms.clone(),
        &transcryption_info.pseudonym,
        &pseudonym_session1_public,
        rng
    )
    .unwrap();
    let expected: Vec<_> = pseudonyms
        .iter()
        .map(|p| {
            dec!(
                &tx!(
                    pseudonymize,
                    p,
                    &transcryption_info.pseudonym,
                    &pseudonym_session1_public,
                    rng
                ),
                &pseudonym_session2_secret
            )
        })
        .collect();
    let decrypted: Vec<_> = pseudonymized
        .iter()
        .map(|p| dec!(p, &pseudonym_session2_secret))
        .collect();
    assert_eq!(
        decrypted.iter().collect::<HashSet<_>>(),
        expected.iter().collect::<HashSet<_>>()
    );
    assert_ne!(decrypted, expected, "batch should be shuffled");
}

#[test]
#[cfg(all(feature = "batch", feature = "long"))]
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

    let (pseudonym_session1_public, _pseudonym_session1_secret) = make_pseudonym_session_keys(
        &pseudonym_global_secret,
        &session1,
        &enc_secret,
        &Context::default(),
    );
    let (_pseudonym_session2_public, pseudonym_session2_secret) = make_pseudonym_session_keys(
        &pseudonym_global_secret,
        &session2,
        &enc_secret,
        &Context::default(),
    );
    let (attribute_session1_public, _attribute_session1_secret) = make_attribute_session_keys(
        &attribute_global_secret,
        &session1,
        &enc_secret,
        &Context::default(),
    );
    let (_attribute_session2_public, attribute_session2_secret) = make_attribute_session_keys(
        &attribute_global_secret,
        &session2,
        &enc_secret,
        &Context::default(),
    );

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
        &Context::default(),
    );

    // Test batch rekeying of long pseudonyms
    let rekeyed_pseudonyms = tx!(
        rekey_batch,
        &mut long_pseudonyms.clone(),
        &transcryption_info.pseudonym.into(),
        &pseudonym_session1_public,
        rng
    )
    .unwrap();
    assert_eq!(rekeyed_pseudonyms.len(), 3);

    // Test batch rekeying of long attributes
    let rekeyed_attributes = tx!(
        rekey_batch,
        &mut long_attributes.clone(),
        &transcryption_info.attribute,
        &attribute_session1_public,
        rng
    )
    .unwrap();
    assert_eq!(rekeyed_attributes.len(), 3);

    // Verify decryption works after rekeying
    for rekeyed_attr in rekeyed_attributes.iter() {
        #[cfg(feature = "elgamal3")]
        let decrypted =
            decrypt(rekeyed_attr, &attribute_session2_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(rekeyed_attr, &attribute_session2_secret);
        let decrypted_string = decrypted.to_string_padded().unwrap();
        assert!(test_strings.contains(&decrypted_string.as_str()));
    }

    // Test batch pseudonymization of long pseudonyms
    let pseudonymized = tx!(
        pseudonymize_batch,
        &mut long_pseudonyms.clone(),
        &transcryption_info.pseudonym,
        &pseudonym_session1_public,
        rng
    )
    .unwrap();
    assert_eq!(pseudonymized.len(), 3);

    // Verify decryption works after pseudonymization (values will be different due to domain change)
    for pseudonymized_pseudo in pseudonymized.iter() {
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

    let mut data_slice: Vec<_> = data.into_iter().collect();
    let session1_public = SessionPublicKeys {
        pseudonym: pseudonym_session1_public,
        attribute: attribute_session1_public,
    };
    let transcrypted = tx!(
        transcrypt_batch,
        &mut data_slice,
        &transcryption_info,
        &session1_public,
        rng
    )
    .expect("Batch transcryption should succeed");
    assert_eq!(transcrypted.len(), 3);

    // Verify each entity has one pseudonym and one attribute
    for record in transcrypted.iter() {
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

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret, &Context::default());
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret, &Context::default());

    let pseudonym = Pseudonym::random(&mut rng);
    let encrypted = encrypt(&pseudonym, &from_session.pseudonym.public, &mut rng);

    let info = PseudonymizationInfo::new(
        &from_domain,
        &to_domain,
        &from_ctx,
        &to_ctx,
        &pseudo_secret,
        &enc_secret,
        &Context::default(),
    );
    let pseudonymized = tx!(
        pseudonymize,
        &encrypted,
        &info,
        &from_session.pseudonym.public,
        &mut rng
    );

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

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret, &Context::default());
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret, &Context::default());

    let pseudonym = Pseudonym::random(&mut rng);
    let encrypted = encrypt(&pseudonym, &from_session.pseudonym.public, &mut rng);

    let rekey_info = PseudonymRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret, &Context::default());
    let rekeyed = tx!(
        rekey,
        &encrypted,
        &rekey_info,
        &from_session.pseudonym.public,
        &mut rng
    );

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

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret, &Context::default());
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret, &Context::default());

    let attribute = Attribute::random(&mut rng);
    let encrypted = encrypt(&attribute, &from_session.attribute.public, &mut rng);

    let rekey_info = AttributeRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret, &Context::default());
    let rekeyed = tx!(
        rekey,
        &encrypted,
        &rekey_info,
        &from_session.attribute.public,
        &mut rng
    );

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

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret, &Context::default());
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret, &Context::default());

    let pseudonym = Pseudonym::random(&mut rng);
    let encrypted = encrypt(&pseudonym, &from_session.pseudonym.public, &mut rng);

    let info = TranscryptionInfo::new(
        &from_domain,
        &to_domain,
        &from_ctx,
        &to_ctx,
        &pseudo_secret,
        &enc_secret,
        &Context::default(),
    );
    let transcrypted = tx!(
        transcrypt,
        &encrypted,
        &info,
        &from_session.pseudonym.public,
        &mut rng
    );

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

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret, &Context::default());
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret, &Context::default());

    let attribute = Attribute::random(&mut rng);
    let encrypted = encrypt(&attribute, &from_session.attribute.public, &mut rng);

    let info = TranscryptionInfo::new(
        &from_domain,
        &to_domain,
        &from_ctx,
        &to_ctx,
        &pseudo_secret,
        &enc_secret,
        &Context::default(),
    );
    let transcrypted = tx!(
        transcrypt,
        &encrypted,
        &info,
        &from_session.attribute.public,
        &mut rng
    );

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

    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret, &Context::default());
    let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret, &Context::default());

    // Test with pseudonym
    let pseudonym = Pseudonym::random(&mut rng);
    let enc_p = encrypt(&pseudonym, &from_session.pseudonym.public, &mut rng);
    let rekey_p = PseudonymRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret, &Context::default());
    let rekeyed_p = tx!(
        rekey,
        &enc_p,
        &rekey_p,
        &from_session.pseudonym.public,
        &mut rng
    );
    #[cfg(feature = "elgamal3")]
    let decrypted_p = decrypt(&rekeyed_p, &to_session.pseudonym.secret).expect("decrypt failed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_p = decrypt(&rekeyed_p, &to_session.pseudonym.secret);
    assert_eq!(pseudonym, decrypted_p);

    // Test with attribute
    let attribute = Attribute::random(&mut rng);
    let enc_a = encrypt(&attribute, &from_session.attribute.public, &mut rng);
    let rekey_a = AttributeRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret, &Context::default());
    let rekeyed_a = tx!(
        rekey,
        &enc_a,
        &rekey_a,
        &from_session.attribute.public,
        &mut rng
    );
    #[cfg(feature = "elgamal3")]
    let decrypted_a = decrypt(&rekeyed_a, &to_session.attribute.secret).expect("decrypt failed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted_a = decrypt(&rekeyed_a, &to_session.attribute.secret);
    assert_eq!(attribute, decrypted_a);
}

/// A malicious sender places a pseudonym directly in the ciphertext (`(B, M)` with an arbitrary
/// `B`). A plain reshuffle would return `s * M` in the clear; the rerandomizing operation hides the
/// result under the receiver's key regardless of the input.
#[test]
fn plaintext_injection_is_blocked_by_rerandomization() {
    use libpep::data::traits::Pseudonymizable;
    #[cfg(feature = "elgamal3")]
    use libpep::keys::PublicKey;
    let mut rng = rand::rng();
    let (_, global_sk) = make_global_keys(&mut rng);
    let enc_secret = EncryptionSecret::from(b"enc".to_vec());
    let pseudo_secret = PseudonymizationSecret::from(b"pseudo".to_vec());
    let from_ctx = EncryptionContext::from("from");
    let to_ctx = EncryptionContext::from("to");
    let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret, &Context::default());
    let info = PseudonymizationInfo::new(
        &PseudonymizationDomain::from("domain-from"),
        &PseudonymizationDomain::from("domain-to"),
        &from_ctx,
        &to_ctx,
        &pseudo_secret,
        &enc_secret,
        &Context::default(),
    );

    let pseudonym = Pseudonym::random(&mut rng);
    let malformed = EncryptedPseudonym::from_value(libpep::elgamal::ElGamal {
        gb: libpep::elgamal::arithmetic::group_elements::GroupElement::random(&mut rng),
        gc: *pseudonym.value(),
        #[cfg(feature = "elgamal3")]
        gy: *from_session.pseudonym.public.value(),
    });
    let leaked = info.s.scalar() * pseudonym.value();

    // Without rerandomization the reshuffled pseudonym is exposed in the C component.
    assert_eq!(malformed.pseudonymize_raw(&info).value().gc, leaked);

    // With rerandomization it is not.
    #[cfg(feature = "elgamal3")]
    let protected = malformed.pseudonymize(&info, &mut rng);
    #[cfg(not(feature = "elgamal3"))]
    let protected = malformed.pseudonymize(&info, &from_session.pseudonym.public, &mut rng);
    assert_ne!(protected.value().gc, leaked);
}

/// The protocol context separates deployments: the same secrets and identifiers give unrelated
/// session keys, transcryption factors and hashed origin pseudonyms under a different context.
/// Under `hmac-derivation` the factors ignore the context by design; only hashing separates.
#[test]
fn protocol_context_separates_deployments() {
    use libpep::encodings::hash_to_group;
    use libpep::protocol::Mode;

    let rng = &mut rand::rng();
    let (_global_public, global_secret) = make_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from(b"pseudonymization secret".to_vec());
    let enc_secret = EncryptionSecret::from(b"encryption secret".to_vec());
    let (domain_a, domain_b) = (
        PseudonymizationDomain::from("hospital"),
        PseudonymizationDomain::from("research"),
    );
    let (session_a, session_b) = (
        EncryptionContext::from("session-a"),
        EncryptionContext::from("session-b"),
    );

    let contexts = [
        Context::default(),
        Context::from_identifier("another-deployment"),
        Context::new(Mode::VcoPRF, "ristretto255-SHA512"),
    ];
    let infos: Vec<_> = contexts
        .iter()
        .map(|ctx| {
            TranscryptionInfo::new(
                &domain_a,
                &domain_b,
                &session_a,
                &session_b,
                &pseudo_secret,
                &enc_secret,
                ctx,
            )
        })
        .collect();
    let keys: Vec<_> = contexts
        .iter()
        .map(|ctx| make_session_keys(&global_secret, &session_a, &enc_secret, ctx))
        .collect();
    let origins: Vec<_> = contexts
        .iter()
        .map(|ctx| Pseudonym::from_point(hash_to_group(b"patient-1", ctx)))
        .collect();

    // Determinism within one context.
    assert_eq!(
        infos[0],
        TranscryptionInfo::new(
            &domain_a,
            &domain_b,
            &session_a,
            &session_b,
            &pseudo_secret,
            &enc_secret,
            &contexts[0],
        )
    );
    assert_eq!(
        keys[0],
        make_session_keys(&global_secret, &session_a, &enc_secret, &contexts[0])
    );
    assert_eq!(
        origins[0],
        Pseudonym::from_point(hash_to_group(b"patient-1", &contexts[0]))
    );

    // Separation between contexts.
    for i in 0..contexts.len() {
        for j in 0..i {
            assert_ne!(origins[i], origins[j]);
            #[cfg(not(feature = "hmac-derivation"))]
            {
                assert_ne!(infos[i], infos[j]);
                assert_ne!(keys[i], keys[j]);
            }
            #[cfg(feature = "hmac-derivation")]
            {
                assert_eq!(infos[i], infos[j]);
                assert_eq!(keys[i], keys[j]);
            }
        }
    }
}
