use rand_core::OsRng;
use crate::arithmetic::GroupElement;
use crate::high_level::contexts::{EncryptionContext, PseudonymizationContext, PseudonymizationInfo, RekeyInfo};
use crate::high_level::data_types::{DataPoint, Pseudonym};
use crate::high_level::keys::{make_global_keys, make_session_keys, EncryptionSecret, PseudonymizationSecret};
use crate::high_level::ops::{decrypt, encrypt, pseudonymize};
use crate::proved::high_level::*;

#[test]
fn test_proved() {
    let rng = &mut OsRng;
    let (_global_public, global_secret) = make_global_keys(rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let pseudo_context1 = PseudonymizationContext::from("context1");
    let enc_context1 = EncryptionContext::from("session1");
    let pseudo_context2 = PseudonymizationContext::from("context2");
    let enc_context2 = EncryptionContext::from("session2");

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
    let enc_pseudo_1 = encrypt(&pseudo_1, &session1_public, rng);

    let data = DataPoint::from_point(GroupElement::random(rng));
    let enc_data = encrypt(&data, &session1_public, rng);

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
    let dec_pseudo_2 = decrypt(&enc_pseudo_2.unwrap(), &session2_secret);
    assert_eq!(pseudonymized_dec.unwrap(), dec_pseudo_2);

    let non_proved = pseudonymize(&enc_pseudo_1, &pseudo_info);
    let non_proved_dec = decrypt(&non_proved, &session2_secret);
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
