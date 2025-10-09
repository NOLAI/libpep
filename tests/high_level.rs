use libpep::high_level::contexts::*;
use libpep::high_level::data_types::*;
use libpep::high_level::keys::*;
use libpep::high_level::ops::*;
use libpep::high_level::secrets::{EncryptionSecret, PseudonymizationSecret};
use rand_core::OsRng;

#[test]
fn test_high_level_flow() {
    let rng = &mut OsRng;
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

    let dec_pseudo = decrypt(&enc_pseudo, &pseudonym_session1_secret);
    let dec_data = decrypt(&enc_data, &attribute_session1_secret);

    assert_eq!(pseudo, dec_pseudo);
    assert_eq!(data, dec_data);

    #[cfg(feature = "elgamal3")]
    {
        let rr_pseudo = rerandomize(&enc_pseudo, rng);
        let rr_data = rerandomize(&enc_data, rng);

        assert_ne!(enc_pseudo, rr_pseudo);
        assert_ne!(enc_data, rr_data);

        let rr_dec_pseudo = decrypt(&rr_pseudo, &pseudonym_session1_secret);
        let rr_dec_data = decrypt(&rr_data, &attribute_session1_secret);

        assert_eq!(pseudo, rr_dec_pseudo);
        assert_eq!(data, rr_dec_data);
    }

    let transcryption_info = TranscryptionInfo::new(
        &domain1,
        &domain2,
        Some(&session1),
        Some(&session2),
        &pseudo_secret,
        &enc_secret,
    );
    let attribute_rekey_info = transcryption_info.attribute;

    let rekeyed = rekey(&enc_data, &attribute_rekey_info);
    let rekeyed_dec = decrypt(&rekeyed, &attribute_session2_secret);

    assert_eq!(data, rekeyed_dec);

    let pseudonymized = transcrypt(&enc_pseudo, &transcryption_info);
    let pseudonymized_dec = decrypt(&pseudonymized, &pseudonym_session2_secret);

    assert_ne!(pseudo, pseudonymized_dec);

    let rev_pseudonymized = transcrypt(&pseudonymized, &transcryption_info.reverse());
    let rev_pseudonymized_dec = decrypt(&rev_pseudonymized, &pseudonym_session1_secret);

    assert_eq!(pseudo, rev_pseudonymized_dec);
}
#[test]
fn test_batch() {
    let rng = &mut OsRng;
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
        Some(&session1),
        Some(&session2),
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

    let _transcrypted = transcrypt_batch(&mut data.into_boxed_slice(), &transcryption_info, rng);

    // TODO check that the batch is indeed shuffled
}
