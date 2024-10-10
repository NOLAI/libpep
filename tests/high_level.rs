use libpep::arithmetic::GroupElement;
use libpep::high_level::*;
use libpep::high_level_proved::*;
use rand_core::OsRng;

#[test]
fn test_high_level_flow() {
    let rng = &mut OsRng;
    let (_global_public, global_secret) = make_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret("secret".to_string());
    let enc_secret = EncryptionSecret("secret".to_string());

    let pseudo_context1 = PseudonymizationContext("context1".to_string());
    let enc_context1 = EncryptionContext("session1".to_string());
    let pseudo_context2 = PseudonymizationContext("context2".to_string());
    let enc_context2 = EncryptionContext("session2".to_string());

    let (session1_public, session1_secret) =
        make_session_keys(&global_secret, &enc_context1, &enc_secret);
    let (_session2_public, session2_secret) =
        make_session_keys(&global_secret, &enc_context2, &enc_secret);

    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt_pseudonym(&pseudo, &session1_public, rng);

    let data = DataPoint::new(GroupElement::random(rng));
    let enc_data = encrypt_data(&data, &session1_public, rng);

    let dec_pseudo = decrypt_pseudonym(&enc_pseudo, &session1_secret);
    let dec_data = decrypt_data(&enc_data, &session1_secret);

    assert_eq!(pseudo, dec_pseudo);
    assert_eq!(data, dec_data);

    #[cfg(not(feature = "elgamal2"))]
    {
        let rr_pseudo = rerandomize_encrypted_pseudonym(&enc_pseudo, rng);
        let rr_data = rerandomize_encrypted(&enc_data, rng);

        assert_ne!(enc_pseudo, rr_pseudo);
        assert_ne!(enc_data, rr_data);

        let rr_dec_pseudo = decrypt_pseudonym(&rr_pseudo, &session1_secret);
        let rr_dec_data = decrypt_data(&rr_data, &session1_secret);

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
    let rekeyed_dec = decrypt_data(&rekeyed, &session2_secret);

    assert_eq!(data, rekeyed_dec);

    let pseudonymized = pseudonymize(&enc_pseudo, &pseudo_info);
    let pseudonymized_dec = decrypt_pseudonym(&pseudonymized, &session2_secret);

    assert_ne!(pseudo, pseudonymized_dec);

    let rev_pseudonymized = pseudonymize(&pseudonymized, &pseudo_info.reverse());
    let rev_pseudonymized_dec = decrypt_pseudonym(&rev_pseudonymized, &session1_secret);

    assert_eq!(pseudo, rev_pseudonymized_dec);
}

#[test]
fn test_proved() {
    let rng = &mut OsRng;
    let (_global_public, global_secret) = make_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret("secret".to_string());
    let enc_secret = EncryptionSecret("secret".to_string());

    let pseudo_context1 = PseudonymizationContext("context1".to_string());
    let enc_context1 = EncryptionContext("session1".to_string());
    let pseudo_context2 = PseudonymizationContext("context2".to_string());
    let enc_context2 = EncryptionContext("session2".to_string());

    let (rekey_verifiers1, pr1) = EncryptionContextVerifiers::new(&enc_context1, &enc_secret, rng);
    let (pseudo_verifiers1, pp1) =
        PseudonymizationContextVerifiers::new(&pseudo_context1, &pseudo_secret, rng);
    let (rekey_verifiers2, pr2) = EncryptionContextVerifiers::new(&enc_context2, &enc_secret, rng);
    let (pseudo_verifiers2, pp2) =
        PseudonymizationContextVerifiers::new(&pseudo_context2, &pseudo_secret, rng);

    assert!(pr1.verify(&rekey_verifiers1));
    assert!(pp1.verify(&pseudo_verifiers1));
    assert!(pr2.verify(&rekey_verifiers2));
    assert!(pp2.verify(&pseudo_verifiers2));

    let (session1_public, session1_secret) =
        make_session_keys(&global_secret, &enc_context1, &enc_secret);
    let (_session2_public, session2_secret) =
        make_session_keys(&global_secret, &enc_context2, &enc_secret);

    let pseudo_1 = Pseudonym::random(rng);
    let enc_pseudo_1 = encrypt_pseudonym(&pseudo_1, &session1_public, rng);

    let data = DataPoint::new(GroupElement::random(rng));
    let enc_data = encrypt_data(&data, &session1_public, rng);

    let pseudo_info = PseudonymizationInfo::new(
        &pseudo_context1,
        &pseudo_context2,
        &enc_context1,
        &enc_context2,
        &pseudo_secret,
        &enc_secret,
    );
    let rekey_info = RekeyInfo::from(pseudo_info);

    let pseudo_info_proof = PseudonymizationInfoProof::new(&pseudo_info, rng);
    let rekey_info_proof = RekeyInfoProof::from(&pseudo_info_proof);

    let rekeyed = proved_rekey(&enc_data, &rekey_info, rng);
    let rekeyed_dec =
        verified_decrypt_data(&rekeyed, &enc_data, &session2_secret, &rekey_info_proof);

    assert!(rekeyed_dec.is_some());
    assert_eq!(data, rekeyed_dec.unwrap());

    let pseudonymized = proved_pseudonymize(&enc_pseudo_1, &pseudo_info, rng);

    let pseudonymized_dec = verified_decrypt_pseudonym(
        &pseudonymized,
        &enc_pseudo_1,
        &session2_secret,
        &pseudo_info_proof,
    );

    assert!(pseudonymized_dec.is_some());
    assert_ne!(pseudo_1, pseudonymized_dec.unwrap());

    let enc_pseudo_2 = pseudonymized.reconstruct(&enc_pseudo_1, &pseudo_info_proof);
    let dec_pseudo_2 = decrypt_pseudonym(&enc_pseudo_2.unwrap(), &session2_secret);
    assert_eq!(pseudonymized_dec.unwrap(), dec_pseudo_2);

    let non_proved = pseudonymize(&enc_pseudo_1, &pseudo_info);
    let non_proved_dec = decrypt_pseudonym(&non_proved, &session2_secret);
    assert_eq!(pseudonymized_dec.unwrap(), non_proved_dec);

    let pseudo_info_proof_rev = PseudonymizationInfoProof::new(&pseudo_info.reverse(), rng);

    let rev_pseudonymized =
        proved_pseudonymize(&enc_pseudo_2.unwrap(), &pseudo_info.reverse(), rng);
    let rev_pseudonymized_dec = verified_decrypt_pseudonym(
        &rev_pseudonymized,
        &enc_pseudo_2.unwrap(),
        &session1_secret,
        &pseudo_info_proof_rev,
    );

    assert_eq!(pseudo_1, rev_pseudonymized_dec.unwrap());
}
