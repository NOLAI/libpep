#![cfg(all(feature = "offline", feature = "insecure"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::client::{decrypt_global, encrypt_global};
#[cfg(feature = "batch")]
use libpep::client::{decrypt_global_batch, encrypt_global_batch};
#[cfg(feature = "long")]
use libpep::data::long::{LongAttribute, LongPseudonym};
use libpep::data::simple::{Attribute, ElGamalEncryptable, Pseudonym};
#[cfg(feature = "json")]
use libpep::keys::make_global_keys;
use libpep::keys::{make_attribute_global_keys, make_pseudonym_global_keys};
#[cfg(feature = "json")]
use libpep::pep_json;

#[test]
fn test_encrypt_decrypt_global() {
    let rng = &mut rand::rng();
    let (pseudonym_public, pseudonym_secret) = make_pseudonym_global_keys(rng);
    let (attribute_public, attribute_secret) = make_attribute_global_keys(rng);

    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt_global(&pseudo, &pseudonym_public, rng);
    #[cfg(feature = "elgamal3")]
    let dec_pseudo =
        decrypt_global(&enc_pseudo, &pseudonym_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let dec_pseudo = decrypt_global(&enc_pseudo, &pseudonym_secret);
    assert_eq!(pseudo, dec_pseudo);

    let attribute = Attribute::random(rng);
    let enc_attribute = encrypt_global(&attribute, &attribute_public, rng);
    #[cfg(feature = "elgamal3")]
    let dec_attribute =
        decrypt_global(&enc_attribute, &attribute_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let dec_attribute = decrypt_global(&enc_attribute, &attribute_secret);
    assert_eq!(attribute, dec_attribute);
}

#[test]
#[cfg(feature = "elgamal3")]
fn test_decrypt_global_wrong_key_fails() {
    let rng = &mut rand::rng();
    let (pseudonym_public, _pseudonym_secret) = make_pseudonym_global_keys(rng);
    let (_other_public, other_secret) = make_pseudonym_global_keys(rng);

    let pseudo = Pseudonym::random(rng);
    let enc_pseudo = encrypt_global(&pseudo, &pseudonym_public, rng);
    assert!(decrypt_global(&enc_pseudo, &other_secret).is_none());
}

#[test]
#[cfg(feature = "long")]
fn test_encrypt_decrypt_global_long() {
    let rng = &mut rand::rng();
    let (pseudonym_public, pseudonym_secret) = make_pseudonym_global_keys(rng);
    let (attribute_public, attribute_secret) = make_attribute_global_keys(rng);

    let pseudo = LongPseudonym::from_bytes_padded("a-pseudonym-longer-than-15-bytes".as_bytes());
    let enc_pseudo = encrypt_global(&pseudo, &pseudonym_public, rng);
    #[cfg(feature = "elgamal3")]
    let dec_pseudo =
        decrypt_global(&enc_pseudo, &pseudonym_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let dec_pseudo = decrypt_global(&enc_pseudo, &pseudonym_secret);
    assert_eq!(pseudo, dec_pseudo);

    let attribute =
        LongAttribute::from_bytes_padded("an-attribute-longer-than-15-bytes".as_bytes());
    let enc_attribute = encrypt_global(&attribute, &attribute_public, rng);
    #[cfg(feature = "elgamal3")]
    let dec_attribute =
        decrypt_global(&enc_attribute, &attribute_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let dec_attribute = decrypt_global(&enc_attribute, &attribute_secret);
    assert_eq!(attribute, dec_attribute);
}

#[test]
#[cfg(feature = "json")]
fn test_encrypt_decrypt_global_json() {
    let rng = &mut rand::rng();
    let (global_public, global_secret) = make_global_keys(rng);

    let record = pep_json!({
        "patient_id": pseudonym("patient-12345"),
        "diagnosis": "Flu",
        "temperature": 38.5
    });

    let encrypted = encrypt_global(&record, &global_public, rng);
    #[cfg(feature = "elgamal3")]
    let decrypted = decrypt_global(&encrypted, &global_secret).expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = decrypt_global(&encrypted, &global_secret);

    let json = decrypted.to_value().expect("should convert to JSON");
    assert_eq!(json["patient_id"], "patient-12345");
    assert_eq!(json["diagnosis"], "Flu");
}

#[test]
#[cfg(feature = "batch")]
fn test_encrypt_decrypt_global_batch() {
    let rng = &mut rand::rng();
    let (pseudonym_public, pseudonym_secret) = make_pseudonym_global_keys(rng);

    let pseudonyms: Vec<Pseudonym> = (0..5).map(|_| Pseudonym::random(rng)).collect();
    let encrypted = encrypt_global_batch(&pseudonyms, &pseudonym_public, rng)
        .expect("batch encryption should succeed");
    let decrypted = decrypt_global_batch(&encrypted, &pseudonym_secret)
        .expect("batch decryption should succeed");
    assert_eq!(pseudonyms, decrypted);
}

#[test]
#[cfg(all(feature = "batch", feature = "json"))]
fn test_encrypt_decrypt_global_batch_json() {
    let rng = &mut rand::rng();
    let (global_public, global_secret) = make_global_keys(rng);

    let records: Vec<_> = (0..3)
        .map(|i| {
            pep_json!({
                "patient_id": pseudonym(format!("patient-{}", i)),
                "diagnosis": "Flu"
            })
        })
        .collect();

    let encrypted = encrypt_global_batch(&records, &global_public, rng)
        .expect("batch encryption should succeed");
    let decrypted =
        decrypt_global_batch(&encrypted, &global_secret).expect("batch decryption should succeed");

    assert_eq!(records.len(), decrypted.len());
    for (original, roundtripped) in records.iter().zip(decrypted.iter()) {
        assert_eq!(
            original.to_value().expect("should convert to JSON"),
            roundtripped.to_value().expect("should convert to JSON")
        );
    }
}
