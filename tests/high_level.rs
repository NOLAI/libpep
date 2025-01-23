use libpep::high_level::contexts::*;
use libpep::high_level::data_types::*;
use libpep::high_level::keys::*;
use libpep::high_level::ops::*;
use rand_core::OsRng;

#[test]
fn test_high_level_flow() {
    let rng = &mut OsRng;
    let (_global_public, global_secret) = make_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("domain1");
    let session1 = EncryptionContext::from("session1");
    let domain2 = PseudonymizationDomain::from("context2");
    let session2 = EncryptionContext::from("session2");

    let (session1_public, session1_secret) =
        make_session_keys(&global_secret, &session1, &enc_secret);
    let (_session2_public, session2_secret) =
        make_session_keys(&global_secret, &session2, &enc_secret);

    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &session1_public, rng);

    let data = DataPoint::random(rng);
    let enc_data = encrypt(&data, &session1_public, rng);

    let dec_pseudo = decrypt(&enc_pseudo, &session1_secret);
    let dec_data = decrypt(&enc_data, &session1_secret);

    assert_eq!(pseudo, dec_pseudo);
    assert_eq!(data, dec_data);

    #[cfg(feature = "elgamal3")]
    {
        let rr_pseudo = rerandomize(&enc_pseudo, rng);
        let rr_data = rerandomize(&enc_data, rng);

        assert_ne!(enc_pseudo, rr_pseudo);
        assert_ne!(enc_data, rr_data);

        let rr_dec_pseudo = decrypt(&rr_pseudo, &session1_secret);
        let rr_dec_data = decrypt(&rr_data, &session1_secret);

        assert_eq!(pseudo, rr_dec_pseudo);
        assert_eq!(data, rr_dec_data);
    }

    let pseudo_info = PseudonymizationInfo::new(
        &domain1,
        &domain2,
        Some(&session1),
        Some(&session2),
        &pseudo_secret,
        &enc_secret,
    );
    let rekey_info = RekeyInfo::from(pseudo_info);

    let rekeyed = rekey(&enc_data, &rekey_info);
    let rekeyed_dec = decrypt(&rekeyed, &session2_secret);

    assert_eq!(data, rekeyed_dec);

    let pseudonymized = transcrypt(&enc_pseudo, &pseudo_info);
    let pseudonymized_dec = decrypt(&pseudonymized, &session2_secret);

    assert_ne!(pseudo, pseudonymized_dec);

    let rev_pseudonymized = transcrypt(&pseudonymized, &pseudo_info.reverse());
    let rev_pseudonymized_dec = decrypt(&rev_pseudonymized, &session1_secret);

    assert_eq!(pseudo, rev_pseudonymized_dec);
}
#[test]
fn test_batch() {
    let rng = &mut OsRng;
    let (_global_public, global_secret) = make_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let domain1 = PseudonymizationDomain::from("domain1");
    let session1 = EncryptionContext::from("session1");
    let domain2 = PseudonymizationDomain::from("domain2");
    let session2 = EncryptionContext::from("session2");

    let (session1_public, _session1_secret) =
        make_session_keys(&global_secret, &session1, &enc_secret);
    let (_session2_public, _session2_secret) =
        make_session_keys(&global_secret, &session2, &enc_secret);

    let mut data_points = vec![];
    let mut pseudonyms = vec![];
    for _ in 0..10 {
        data_points.push(encrypt(&DataPoint::random(rng), &session1_public, rng));
        pseudonyms.push(encrypt(&Pseudonym::random(rng), &session1_public, rng));
    }

    let transcryption_info = TranscryptionInfo::new(
        &domain1,
        &domain2,
        Some(&session1),
        Some(&session2),
        &pseudo_secret,
        &enc_secret,
    );

    let rekey_info = RekeyInfo::from(transcryption_info);

    let _rekeyed = rekey_batch(&mut data_points, &rekey_info, rng);
    let _pseudonymized = pseudonymize_batch(&mut pseudonyms, &transcryption_info, rng);

    let mut data = vec![];
    for _ in 0..10 {
        let pseudonyms = (0..10)
            .map(|_| encrypt(&Pseudonym::random(rng), &session1_public, rng))
            .collect();
        let data_points = (0..10)
            .map(|_| encrypt(&DataPoint::random(rng), &session1_public, rng))
            .collect();
        data.push((pseudonyms, data_points));
    }

    let _transcrypted = transcrypt_batch(&mut data.into_boxed_slice(), &transcryption_info, rng);

    // TODO check that the batch is indeed shuffled
}
