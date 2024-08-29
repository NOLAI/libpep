use rand_core::OsRng;
use libpep::arithmetic::GroupElement;
use libpep::high_level::*;

#[test]
fn test() {
    let (_global_public, global_secret) = make_global_keys();
    let pseudo_secret = PseudonymizationSecret("secret".to_string());
    let enc_secret = EncryptionSecret("secret".to_string());

    let pseudo_context1 = PseudonymizationContext("context1".to_string());
    let enc_context1 = EncryptionContext("session1".to_string());
    let pseudo_context2 = PseudonymizationContext("context2".to_string());
    let enc_context2 = EncryptionContext("session2".to_string());

    let (session1_public, session1_secret) = make_session_keys(&global_secret, &enc_context1, &enc_secret);
    let (_session2_public, session2_secret) = make_session_keys(&global_secret, &enc_context2, &enc_secret);

    let pseudo = Pseudonym::random();
    let enc_pseudo = encrypt_pseudonym(&pseudo, &session1_public);

    let data = DataPoint::new(GroupElement::random(&mut OsRng));
    let enc_data = encrypt_data(&data, &session1_public);

    let dec_pseudo = decrypt_pseudonym(&enc_pseudo, &session1_secret);
    let dec_data = decrypt_data(&enc_data, &session1_secret);

    assert_eq!(pseudo, dec_pseudo);
    assert_eq!(data, dec_data);

    #[cfg(not(feature = "elgamal2"))]
    {
        let rr_pseudo = rerandomize_encrypted_pseudonym(&enc_pseudo);
        let rr_data = rerandomize_encrypted(&enc_data);

        assert_ne!(enc_pseudo, rr_pseudo);
        assert_ne!(enc_data, rr_data);

        let rr_dec_pseudo = decrypt_pseudonym(&rr_pseudo, &session1_secret);
        let rr_dec_data = decrypt_data(&rr_data, &session1_secret);

        assert_eq!(pseudo, rr_dec_pseudo);
        assert_eq!(data, rr_dec_data);
    }

    let rekeyed = rekey(&enc_data, &enc_context1, &enc_context2, &enc_secret);
    let rekeyed_dec = decrypt_data(&rekeyed, &session2_secret);

    assert_eq!(data, rekeyed_dec);

    let pseudonymized = pseudonymize(&enc_pseudo, &pseudo_context1, &pseudo_context2, &enc_context1, &enc_context2, &pseudo_secret, &enc_secret);
    let pseudonymized_dec = decrypt_pseudonym(&pseudonymized, &session2_secret);

    assert_ne!(pseudo, pseudonymized_dec);

    let rev_pseudonymized = pseudonymize(&pseudonymized, &pseudo_context2, &pseudo_context1, &enc_context2, &enc_context1, &pseudo_secret, &enc_secret);
    let rev_pseudonymized_dec = decrypt_pseudonym(&rev_pseudonymized, &session1_secret);

    assert_eq!(pseudo, rev_pseudonymized_dec);
}
