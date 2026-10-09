//! A key operation accepts either the one key it needs or a bundle to take it from, and the
//! *data's* type decides which half of the bundle is used.
//!
//! These tests pin that selection. Each one performs the same operation twice under an identically
//! seeded rng, once with the specific key and once with the bundle, and asserts the results are
//! byte-identical. Because the two halves of a bundle are different keys (asserted below), a
//! projection that picked the wrong half could not produce an identical result.

use libpep::client::{decrypt, encrypt};
use libpep::contexts::*;
use libpep::data::simple::{Attribute, ElGamalEncryptable, Pseudonym};
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use libpep::keys::*;
use libpep::transcryptor::Transcryptor;
use rand::rngs::ChaCha20Rng;
use rand::SeedableRng;

const SEED: [u8; 32] = [7u8; 32];

fn setup() -> (Transcryptor, SessionKeys, EncryptionContext) {
    let rng = &mut ChaCha20Rng::from_seed(SEED);
    let (_global_public, global_secret) = make_global_keys(rng);
    let transcryptor = Transcryptor::new(
        PseudonymizationSecret::from(b"pseudonymization secret".to_vec()),
        EncryptionSecret::from(b"encryption secret".to_vec()),
    );
    let session = EncryptionContext::from("session-a");
    let keys = make_session_keys(&global_secret, &session, transcryptor.rekeying_secret());
    (transcryptor, keys, session)
}

/// The premise of every test below: the two halves of a session are distinct keys, so selecting
/// the wrong one is observable.
#[test]
fn the_two_halves_of_a_session_are_different_keys() {
    let (_, keys, _) = setup();
    assert_ne!(
        keys.pseudonym.public.to_bytes(),
        keys.attribute.public.to_bytes(),
        "pseudonym and attribute session public keys must differ"
    );
    assert_ne!(
        keys.public().pseudonym.to_bytes(),
        keys.public().attribute.to_bytes(),
    );
}

#[test]
fn encrypting_a_pseudonym_from_the_bundle_selects_the_pseudonym_key() {
    let (_, keys, _) = setup();
    let pseudonym = Pseudonym::random(&mut ChaCha20Rng::from_seed(SEED));

    let specific = encrypt(
        &pseudonym,
        &keys.pseudonym.public,
        &mut ChaCha20Rng::from_seed(SEED),
    );
    let bundled = encrypt(
        &pseudonym,
        &keys.public(),
        &mut ChaCha20Rng::from_seed(SEED),
    );
    assert_eq!(specific.to_bytes(), bundled.to_bytes());
}

#[test]
fn encrypting_an_attribute_from_the_bundle_selects_the_attribute_key() {
    let (_, keys, _) = setup();
    let attribute = Attribute::random(&mut ChaCha20Rng::from_seed(SEED));

    let specific = encrypt(
        &attribute,
        &keys.attribute.public,
        &mut ChaCha20Rng::from_seed(SEED),
    );
    let bundled = encrypt(
        &attribute,
        &keys.public(),
        &mut ChaCha20Rng::from_seed(SEED),
    );
    assert_eq!(specific.to_bytes(), bundled.to_bytes());
}

/// `decrypt` returns an `Option` with the `elgamal3` feature and the value itself without it.
#[cfg(feature = "elgamal3")]
fn unwrap_decrypted<T>(value: Option<T>) -> T {
    match value {
        Some(value) => value,
        None => panic!("decryption must succeed"),
    }
}

#[cfg(not(feature = "elgamal3"))]
fn unwrap_decrypted<T>(value: T) -> T {
    value
}

#[test]
fn decrypting_from_the_bundle_selects_the_matching_secret_key() {
    let (_, keys, _) = setup();
    let rng = &mut ChaCha20Rng::from_seed(SEED);

    let pseudonym = Pseudonym::random(rng);
    let encrypted = encrypt(&pseudonym, &keys.public(), rng);
    // Both forms decrypt, and to the original value.
    assert_eq!(
        unwrap_decrypted(decrypt(&encrypted, &keys.pseudonym.secret)),
        pseudonym
    );
    assert_eq!(unwrap_decrypted(decrypt(&encrypted, &keys)), pseudonym);

    let attribute = Attribute::random(rng);
    let encrypted = encrypt(&attribute, &keys.public(), rng);
    assert_eq!(
        unwrap_decrypted(decrypt(&encrypted, &keys.attribute.secret)),
        attribute
    );
    assert_eq!(unwrap_decrypted(decrypt(&encrypted, &keys)), attribute);
}

/// With `elgamal3` the ciphertext carries its own key, so transcryption takes no key argument and
/// there is nothing to project.
#[cfg(not(feature = "elgamal3"))]
#[test]
fn transcrypting_from_the_bundle_selects_the_pseudonym_key() {
    let (transcryptor, keys, session) = setup();
    let rng = &mut ChaCha20Rng::from_seed(SEED);

    let pseudonym = Pseudonym::random(rng);
    let encrypted = encrypt(&pseudonym, &keys.public(), rng);

    let session_b = EncryptionContext::from("session-b");
    let info = transcryptor.transcryption_info(
        &PseudonymizationDomain::from("hospital"),
        &PseudonymizationDomain::from("research"),
        &session,
        &session_b,
    );

    let specific = transcryptor.transcrypt(
        &encrypted,
        &info,
        &keys.pseudonym.public,
        &mut ChaCha20Rng::from_seed(SEED),
    );
    let bundled = transcryptor.transcrypt(
        &encrypted,
        &info,
        &keys.public(),
        &mut ChaCha20Rng::from_seed(SEED),
    );
    assert_eq!(specific.to_bytes(), bundled.to_bytes());
}
