#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::core::data::*;
use libpep::core::keys::*;
#[cfg(feature = "elgamal3")]
use libpep::core::rerandomize::rerandomize;
use libpep::core::transcryption::batch::{pseudonymize_batch, rekey_batch, transcrypt_batch};
use libpep::core::transcryption::contexts::*;
use libpep::core::transcryption::ops::{rekey, transcrypt};
use libpep::core::transcryption::secrets::{EncryptionSecret, PseudonymizationSecret};

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

    let pseudonymized = transcrypt(&enc_pseudo, &transcryption_info);
    #[cfg(feature = "elgamal3")]
    let pseudonymized_dec =
        decrypt(&pseudonymized, &pseudonym_session2_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let pseudonymized_dec = decrypt(&pseudonymized, &pseudonym_session2_secret);

    assert_ne!(pseudo, pseudonymized_dec);

    let rev_pseudonymized = transcrypt(&pseudonymized, &transcryption_info.reverse());
    #[cfg(feature = "elgamal3")]
    let rev_pseudonymized_dec =
        decrypt(&rev_pseudonymized, &pseudonym_session1_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let rev_pseudonymized_dec = decrypt(&rev_pseudonymized, &pseudonym_session1_secret);

    assert_eq!(pseudo, rev_pseudonymized_dec);
}
#[test]
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

    let _rekeyed = rekey_batch(&mut attributes, &attribute_rekey_info, rng);
    let _pseudonymized = pseudonymize_batch(&mut pseudonyms, &transcryption_info.pseudonym, rng);

    let mut data = vec![];
    for _ in 0..10 {
        let pseudonyms = (0..10)
            .map(|_| encrypt(&Pseudonym::random(rng), &pseudonym_session1_public, rng))
            .collect();
        let attributes = (0..10)
            .map(|_| encrypt(&Attribute::random(rng), &attribute_session1_public, rng))
            .collect();
        data.push((pseudonyms, attributes));
    }

    let _transcrypted = transcrypt_batch(data, &transcryption_info, rng)
        .expect("Batch transcryption should succeed");

    // TODO check that the batch is indeed shuffled
}

#[test]
fn test_batch_long() {
    use libpep::core::long::batch::{
        pseudonymize_long_batch, rekey_long_attribute_batch, rekey_long_pseudonym_batch,
        transcrypt_long_batch,
    };
    use libpep::core::long::data::{
        decrypt_long_attribute, decrypt_long_pseudonym, encrypt_long_attribute,
        encrypt_long_pseudonym, LongAttribute, LongPseudonym,
    };

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
    let (_pseudonym_session2_public, pseudonym_session2_secret) =
        make_pseudonym_session_keys(&pseudonym_global_secret, &session2, &enc_secret);
    let (attribute_session1_public, _attribute_session1_secret) =
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
            encrypt_long_pseudonym(&long_pseudo, &pseudonym_session1_public, rng)
        })
        .collect();

    let long_attributes: Vec<_> = test_strings
        .iter()
        .map(|s| {
            let long_attr = LongAttribute::from_string_padded(s);
            encrypt_long_attribute(&long_attr, &attribute_session1_public, rng)
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
    let rekeyed_pseudonyms = rekey_long_pseudonym_batch(
        &mut long_pseudonyms.clone(),
        &transcryption_info.pseudonym.k,
        rng,
    );
    assert_eq!(rekeyed_pseudonyms.len(), 3);

    // Test batch rekeying of long attributes
    let rekeyed_attributes = rekey_long_attribute_batch(
        &mut long_attributes.clone(),
        &transcryption_info.attribute,
        rng,
    );
    assert_eq!(rekeyed_attributes.len(), 3);

    // Verify decryption works after rekeying
    for rekeyed_attr in rekeyed_attributes.iter() {
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt_long_attribute(rekeyed_attr, &attribute_session2_secret)
            .expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt_long_attribute(rekeyed_attr, &attribute_session2_secret);
        let decrypted_string = decrypted.to_string_padded().unwrap();
        assert!(test_strings.contains(&decrypted_string.as_str()));
    }

    // Test batch pseudonymization of long pseudonyms
    let pseudonymized = pseudonymize_long_batch(
        &mut long_pseudonyms.clone(),
        &transcryption_info.pseudonym,
        rng,
    );
    assert_eq!(pseudonymized.len(), 3);

    // Verify decryption works after pseudonymization (values will be different due to domain change)
    for pseudonymized_pseudo in pseudonymized.iter() {
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt_long_pseudonym(pseudonymized_pseudo, &pseudonym_session2_secret)
            .expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt_long_pseudonym(pseudonymized_pseudo, &pseudonym_session2_secret);
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
                encrypt_long_pseudonym(&long_pseudo, &pseudonym_session1_public, rng)
            }];

            let long_attributes = vec![{
                let long_attr = LongAttribute::from_string_padded(&attr_str);
                encrypt_long_attribute(&long_attr, &attribute_session1_public, rng)
            }];

            (long_pseudonyms, long_attributes)
        })
        .collect();

    let transcrypted = transcrypt_long_batch(data, &transcryption_info, rng)
        .expect("Batch transcryption should succeed");
    assert_eq!(transcrypted.len(), 3);

    // Verify each entity has one pseudonym and one attribute
    for (pseudonyms, attributes) in transcrypted.iter() {
        assert_eq!(pseudonyms.len(), 1);
        assert_eq!(attributes.len(), 1);

        // Verify attributes decrypt correctly (they're rekeyed, not pseudonymized)
        #[cfg(feature = "elgamal3")]
        let decrypted_attr = decrypt_long_attribute(&attributes[0], &attribute_session2_secret)
            .expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted_attr = decrypt_long_attribute(&attributes[0], &attribute_session2_secret);
        let attr_str = decrypted_attr.to_string_padded().unwrap();
        assert!(attr_str.starts_with("Entity ") && attr_str.ends_with(" attribute data"));
    }
}
