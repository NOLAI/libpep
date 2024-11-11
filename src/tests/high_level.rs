use crate::arithmetic::GroupElement;
use crate::high_level::contexts::*;
use crate::high_level::keys::*;
use crate::high_level::ops::*;
use crate::high_level::data_types::*;
use rand_core::OsRng;

#[test]
fn test_high_level_flow() {
    let rng = &mut OsRng;
    let (_global_public, global_secret) = make_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let pseudo_context1 = PseudonymizationContext::from("context1");
    let enc_context1 = EncryptionContext::from("session1");
    let pseudo_context2 = PseudonymizationContext::from("context2");
    let enc_context2 = EncryptionContext::from("session2");


    let (session1_public, session1_secret) =
        make_session_keys(&global_secret, &enc_context1, &enc_secret);
    let (_session2_public, session2_secret) =
        make_session_keys(&global_secret, &enc_context2, &enc_secret);

    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt(&pseudo, &session1_public, rng);

    let data = DataPoint::from_point(GroupElement::random(rng));
    let enc_data = encrypt(&data, &session1_public, rng);

    let dec_pseudo = decrypt(&enc_pseudo, &session1_secret);
    let dec_data = decrypt(&enc_data, &session1_secret);

    assert_eq!(pseudo, dec_pseudo);
    assert_eq!(data, dec_data);

    #[cfg(not(feature = "elgamal2"))]
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
        &pseudo_context1,
        &pseudo_context2,
        &enc_context1,
        &enc_context2,
        &pseudo_secret,
        &enc_secret,
    );
    let rekey_info = RekeyInfo::from(pseudo_info);

    let rekeyed = rekey(&enc_data, &rekey_info);
    let rekeyed_dec = decrypt(&rekeyed, &session2_secret);

    assert_eq!(data, rekeyed_dec);

    let pseudonymized = pseudonymize(&enc_pseudo, &pseudo_info);
    let pseudonymized_dec = decrypt(&pseudonymized, &session2_secret);

    assert_ne!(pseudo, pseudonymized_dec);

    let rev_pseudonymized = pseudonymize(&pseudonymized, &pseudo_info.reverse());
    let rev_pseudonymized_dec = decrypt(&rev_pseudonymized, &session1_secret);

    assert_eq!(pseudo, rev_pseudonymized_dec);

    let rekeyed_transcrypt = transcrypt(&enc_data.into(), &pseudo_info);
    let rekeyed_dec_transcrypt = decrypt(&EncryptedDataPoint::try_from(rekeyed_transcrypt).unwrap(), &session2_secret);

    assert_eq!(data, rekeyed_dec_transcrypt);

    let pseudonymized_transcrypt = transcrypt(&enc_pseudo.into(), &pseudo_info);
    let pseudonymized_dec_transcrypt = decrypt(&EncryptedPseudonym::try_from(pseudonymized_transcrypt).unwrap(), &session2_secret);

    assert_ne!(pseudo, pseudonymized_dec_transcrypt);
    assert_eq!(pseudonymized_dec, pseudonymized_dec_transcrypt);

    let rev_pseudonymized_transcrypt = transcrypt(&pseudonymized_transcrypt, &pseudo_info.reverse());
    let rev_pseudonymized_dec_transcrypt = decrypt(&EncryptedPseudonym::try_from(rev_pseudonymized_transcrypt).unwrap(), &session1_secret);

    assert_eq!(pseudo, rev_pseudonymized_dec_transcrypt);
}
#[test]
fn test_batch() {
    let rng = &mut OsRng;
    let (_global_public, global_secret) = make_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let pseudo_context1 = PseudonymizationContext::from("context1");
    let enc_context1 = EncryptionContext::from("session1");
    let pseudo_context2 = PseudonymizationContext::from("context2");
    let enc_context2 = EncryptionContext::from("session2");


    let (session1_public, _session1_secret) =
        make_session_keys(&global_secret, &enc_context1, &enc_secret);
    let (_session2_public, _session2_secret) =
        make_session_keys(&global_secret, &enc_context2, &enc_secret);

    let mut data = vec![];
    let mut pseudonyms = vec![];
    for _ in 0..10 {
        data.push(encrypt(&DataPoint::random(rng), &session1_public, rng));
        pseudonyms.push(encrypt(&Pseudonym::random(rng), &session1_public, rng));
    }

    let transcryption_info = TranscryptionInfo::new(
        &pseudo_context1,
        &pseudo_context2,
        &enc_context1,
        &enc_context2,
        &pseudo_secret,
        &enc_secret,
    );

    let rekey_info = RekeyInfo::from(transcryption_info);

    let _rekeyed = rekey_batch(&data, &rekey_info, rng);
    let _pseudonymized = pseudonymize_batch(&pseudonyms, &transcryption_info, rng);

    // TODO check that the batch is indeed shuffled
}