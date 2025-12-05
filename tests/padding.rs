#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::core::data::{decrypt, encrypt, EncryptedPseudonym, Pseudonym};
use libpep::core::keys::{make_pseudonym_global_keys, make_pseudonym_session_keys};
use libpep::core::long::data::LongPseudonym;
use libpep::core::transcryption::contexts::{
    EncryptionContext, PseudonymizationDomain, PseudonymizationInfo,
};
use libpep::core::transcryption::ops::pseudonymize;
use libpep::core::transcryption::secrets::{EncryptionSecret, PseudonymizationSecret};
use std::io::Error;

#[test]
fn test_pseudonymize_string_roundtrip() -> Result<(), Error> {
    // Initialize test environment
    let mut rng = rand::rng();
    let (_global_public, global_secret) = make_pseudonym_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("test-secret".as_bytes().to_vec());
    let enc_secret = EncryptionSecret::from("enc-secret".as_bytes().to_vec());

    // Setup domains and contexts
    let domain_a = PseudonymizationDomain::from("domain-a");
    let domain_b = PseudonymizationDomain::from("domain-b");
    let session = EncryptionContext::from("session-1");

    // Create session keys
    let (session_public, session_secret) =
        make_pseudonym_session_keys(&global_secret, &session, &enc_secret);

    // Original string to encrypt and pseudonymize
    let original_string = "This is a very long id that will be pseudonymized";

    // Step 1: Convert string to padded pseudonyms
    let pseudonym = LongPseudonym::from_string_padded(original_string);

    // Step 2: Encrypt the pseudonyms
    let encrypted_pseudonyms: Vec<EncryptedPseudonym> = pseudonym
        .iter()
        .map(|p| encrypt(p, &session_public, &mut rng))
        .collect();

    // Step 3: Create pseudonymization info for transform
    let pseudo_info = PseudonymizationInfo::new(
        &domain_a,
        &domain_b,
        &session,
        &session,
        &pseudo_secret,
        &enc_secret,
    );

    // Step 4: Pseudonymize (transform) the encrypted pseudonyms
    let transformed_pseudonyms: Vec<EncryptedPseudonym> = encrypted_pseudonyms
        .iter()
        .map(|ep| pseudonymize(ep, &pseudo_info))
        .collect();

    // Step 5: Decrypt the transformed pseudonyms
    let decrypted_pseudonyms: Vec<Pseudonym> = transformed_pseudonyms
        .iter()
        .map(|ep| {
            #[cfg(feature = "elgamal3")]
            {
                decrypt(ep, &session_secret).expect("decrypt failed")
            }
            #[cfg(not(feature = "elgamal3"))]
            {
                decrypt(ep, &session_secret)
            }
        })
        .collect();

    // Step 6: Encrypt the decrypted pseudonyms
    let re_encrypted_pseudonyms: Vec<EncryptedPseudonym> = decrypted_pseudonyms
        .iter()
        .map(|p| encrypt(p, &session_public, &mut rng))
        .collect();

    // Step 7: Reverse the pseudonymization
    let reverse_pseudo_info = PseudonymizationInfo::new(
        &domain_b,
        &domain_a,
        &session,
        &session,
        &pseudo_secret,
        &enc_secret,
    );

    let reverse_transformed: Vec<EncryptedPseudonym> = re_encrypted_pseudonyms
        .iter()
        .map(|ep| pseudonymize(ep, &reverse_pseudo_info))
        .collect();

    let reverse_decrypted: Vec<Pseudonym> = reverse_transformed
        .iter()
        .map(|ep| {
            #[cfg(feature = "elgamal3")]
            {
                decrypt(ep, &session_secret).expect("decrypt failed")
            }
            #[cfg(not(feature = "elgamal3"))]
            {
                decrypt(ep, &session_secret)
            }
        })
        .collect();

    let reverse_long = LongPseudonym(reverse_decrypted);
    let reverse_string = reverse_long.to_string_padded()?;

    // After reversing the pseudonymization, we should get back the original string
    assert_eq!(original_string, reverse_string);

    Ok(())
}
