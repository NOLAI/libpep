//! The generic API with a group and ciphersuite that are not ristretto255.
//!
//! The data types default their group to ristretto255 (`Pseudonym` is `Pseudonym<Ristretto255>`),
//! and the roles default their ciphersuite. A generic item that names a defaulted type without
//! its parameter compiles and silently pins to ristretto255. These tests run the flows with
//! `TestGroup` and `TestSuite`, which delegate to ristretto255 but are different types, so such a
//! pin fails to compile or to run here: `Pseudonym<TestGroup>` is not `Pseudonym`.
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[macro_use]
mod common;

use libpep::ciphersuite;
use libpep::ciphersuite::hashing::hash_to_group_generic;
use libpep::ciphersuite::{Ciphersuite, CiphersuiteId, Ristretto255Sha512};
use libpep::client::{encrypt, Client, Distributed};
use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::data::elgamal::ElGamalEncryptable;
use libpep::data::simple::{Attribute, Pseudonym};
use libpep::factors::{
    make_pseudonym_rekey_factor_generic, Factor, PseudonymizationSecret, RekeyingSecret,
    TranscryptionInfo,
};
use libpep::group::group_elements::GroupElement;
use libpep::group::scalars::{ScalarCanBeZero, ScalarNonZero, ScalarTraits};
use libpep::group::{Group, InvertibleEncoding, Ristretto255};
use libpep::keys::distribution::make_distributed_global_keys_generic;
use libpep::keys::{make_global_keys_generic, make_session_keys_generic, SessionKeys};
use libpep::transcryptor::{rekey, transcrypt, DistributedTranscryptor, Transcryptor};
use rand_core::{CryptoRng, Rng};

/// A group that is ristretto255 under another name.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
struct TestGroup;

impl Group for TestGroup {
    type Scalar = ScalarNonZero;
    type ScalarCanBeZero = ScalarCanBeZero;
    type Element = GroupElement;
    type ElementBytes = [u8; 32];
    type ScalarBytes = [u8; 32];

    const NE: usize = Ristretto255::NE;
    const NS: usize = Ristretto255::NS;

    fn order() -> &'static [u8] {
        Ristretto255::order()
    }
    fn identity() -> GroupElement {
        Ristretto255::identity()
    }
    fn generator() -> GroupElement {
        Ristretto255::generator()
    }
    fn element_from_uniform_bytes(bytes: &[u8; 64]) -> GroupElement {
        Ristretto255::element_from_uniform_bytes(bytes)
    }
    fn scalar_from_uniform_bytes(bytes: &[u8; 64]) -> Option<ScalarNonZero> {
        Ristretto255::scalar_from_uniform_bytes(bytes)
    }
    fn random_scalar<R: Rng + CryptoRng>(rng: &mut R) -> ScalarNonZero {
        Ristretto255::random_scalar(rng)
    }
    fn random_element<R: Rng + CryptoRng>(rng: &mut R) -> GroupElement {
        Ristretto255::random_element(rng)
    }
    fn scalar_one() -> ScalarNonZero {
        Ristretto255::scalar_one()
    }
    fn scalar_inverse(scalar: &ScalarNonZero) -> ScalarNonZero {
        Ristretto255::scalar_inverse(scalar)
    }
    fn serialize_element(element: &GroupElement) -> [u8; 32] {
        Ristretto255::serialize_element(element)
    }
    fn deserialize_element(bytes: &[u8]) -> Option<GroupElement> {
        Ristretto255::deserialize_element(bytes)
    }
    fn serialize_scalar(scalar: &ScalarNonZero) -> [u8; 32] {
        Ristretto255::serialize_scalar(scalar)
    }
    fn deserialize_scalar(bytes: &[u8]) -> Option<ScalarNonZero> {
        Ristretto255::deserialize_scalar(bytes)
    }
    fn serialize_scalar_can_be_zero(scalar: &ScalarCanBeZero) -> [u8; 32] {
        Ristretto255::serialize_scalar_can_be_zero(scalar)
    }
    fn deserialize_scalar_can_be_zero(bytes: &[u8]) -> Option<ScalarCanBeZero> {
        Ristretto255::deserialize_scalar_can_be_zero(bytes)
    }
    fn scalar_mult_gen(scalar: &ScalarNonZero) -> GroupElement {
        Ristretto255::scalar_mult_gen(scalar)
    }
}

impl InvertibleEncoding for TestGroup {
    type Block = <Ristretto255 as InvertibleEncoding>::Block;

    const BLOCK_LENGTH: usize = Ristretto255::BLOCK_LENGTH;

    fn encode_lizard(block: &Self::Block) -> GroupElement {
        Ristretto255::encode_lizard(block)
    }
    fn decode_lizard(element: &GroupElement) -> Option<Self::Block> {
        Ristretto255::decode_lizard(element)
    }
}

/// A ciphersuite on [`TestGroup`] with an identifier of its own, so that its factors and hashes
/// differ from those of `ristretto255-SHA512`.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
struct TestSuite;

impl Ciphersuite for TestSuite {
    type Group = TestGroup;
    type Hash = <Ristretto255Sha512 as Ciphersuite>::Hash;

    const ID: CiphersuiteId = ciphersuite!("test-SHA512");

    fn hash_to_group(msg: &[u8], dst: &[u8]) -> GroupElement {
        Ristretto255Sha512::hash_to_group(msg, dst)
    }
    fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Option<ScalarNonZero> {
        Ristretto255Sha512::hash_to_scalar(msg, dst)
    }
}

fn secrets() -> (PseudonymizationSecret, RekeyingSecret) {
    (
        PseudonymizationSecret::from(b"pseudonymization secret".to_vec()),
        RekeyingSecret::from(b"rekeying secret".to_vec()),
    )
}

#[test]
fn the_test_suite_is_a_different_suite() {
    let secret = RekeyingSecret::from(b"rekeying secret".to_vec());
    let session = EncryptionContext::from("session");
    // Hashing to the group takes its tag from the suite identifier.
    assert_ne!(
        hash_to_group_generic::<TestSuite>(b"identifier").to_bytes(),
        hash_to_group_generic::<Ristretto255Sha512>(b"identifier").to_bytes()
    );
    // So does factor derivation, except in the legacy derivation, which has no tag.
    let test = make_pseudonym_rekey_factor_generic::<TestSuite>(&secret, &session);
    let ristretto = make_pseudonym_rekey_factor_generic::<Ristretto255Sha512>(&secret, &session);
    #[cfg(not(feature = "legacy"))]
    assert_ne!(test.scalar().to_bytes(), ristretto.scalar().to_bytes());
    #[cfg(feature = "legacy")]
    assert_eq!(test.scalar().to_bytes(), ristretto.scalar().to_bytes());
}

#[test]
fn round_trip() {
    let rng = &mut rand::rng();
    let (_public, global_secret) = make_global_keys_generic::<TestGroup, _>(rng);
    let (pseudonymization_secret, rekeying_secret) = secrets();
    let transcryptor = Transcryptor::<TestSuite>::new_generic(
        pseudonymization_secret.clone(),
        rekeying_secret.clone(),
    );

    let (domain_a, session_a) = (
        PseudonymizationDomain::from("hospital"),
        EncryptionContext::from("session-a"),
    );
    let (domain_b, session_b) = (
        PseudonymizationDomain::from("research"),
        EncryptionContext::from("session-b"),
    );
    let keys_a: SessionKeys<TestGroup> =
        make_session_keys_generic::<TestSuite>(&global_secret, &session_a, &rekeying_secret);
    let keys_b =
        make_session_keys_generic::<TestSuite>(&global_secret, &session_b, &rekeying_secret);

    let pseudonym = Pseudonym::<TestGroup>::random(rng);
    let attribute = Attribute::<TestGroup>::random(rng);
    let encrypted = encrypt(&pseudonym, &keys_a.public(), rng);
    let encrypted_attribute = encrypt(&attribute, &keys_a.public(), rng);
    assert_eq!(dec!(&encrypted, &keys_a), pseudonym);

    let info = transcryptor.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
    // The info is the one of the suite, not of ristretto255.
    let same_info = TranscryptionInfo::<TestGroup>::new_generic::<TestSuite>(
        &domain_a,
        &domain_b,
        &session_a,
        &session_b,
        &pseudonymization_secret,
        &rekeying_secret,
    );
    assert_eq!(info, same_info);

    let transcrypted = tx!(transcrypt, &encrypted, &info, &keys_a.public(), rng);
    let converted = dec!(&transcrypted, &keys_b);
    assert_ne!(pseudonym, converted);

    // Back to the first domain and session.
    let back = tx!(
        transcrypt,
        &transcrypted,
        &info.reverse(),
        &keys_b.public(),
        rng
    );
    assert_eq!(dec!(&back, &keys_a), pseudonym);

    // Attributes are rekeyed only.
    let rekey_info = transcryptor.attribute_rekey_info(&session_a, &session_b);
    let rekeyed = tx!(
        rekey,
        &encrypted_attribute,
        &rekey_info,
        &keys_a.attribute.public,
        rng
    );
    assert_eq!(dec!(&rekeyed, &keys_b), attribute);

    // The same through the transcryptor and client types.
    let client_b = Client::new(keys_b);
    let again = txm!(
        transcryptor.transcrypt,
        &encrypted,
        &info,
        &keys_a.public(),
        rng
    );
    #[cfg(feature = "elgamal3")]
    assert_ne!(client_b.decrypt(&again).unwrap(), pseudonym);
    #[cfg(not(feature = "elgamal3"))]
    assert_ne!(client_b.decrypt(&again), pseudonym);
}

#[cfg(feature = "long")]
#[test]
fn long_values() {
    use libpep::data::long::LongPseudonym;

    let rng = &mut rand::rng();
    let (_public, global_secret) = make_global_keys_generic::<TestGroup, _>(rng);
    let (pseudonymization_secret, rekeying_secret) = secrets();
    let transcryptor =
        Transcryptor::<TestSuite>::new_generic(pseudonymization_secret, rekeying_secret.clone());
    let (domain, session_a, session_b) = (
        PseudonymizationDomain::from("hospital"),
        EncryptionContext::from("session-a"),
        EncryptionContext::from("session-b"),
    );
    let keys_a =
        make_session_keys_generic::<TestSuite>(&global_secret, &session_a, &rekeying_secret);
    let keys_b =
        make_session_keys_generic::<TestSuite>(&global_secret, &session_b, &rekeying_secret);

    let pseudonym =
        LongPseudonym::<TestGroup>::from_string_padded("a long identifier of a patient");
    let encrypted = encrypt(&pseudonym, &keys_a.public(), rng);
    // The same domain: only the session changes, so the pseudonym is the same.
    let info = transcryptor.pseudonymization_info(&domain, &domain, &session_a, &session_b);
    let converted = tx!(
        transcrypt,
        &encrypted,
        &TranscryptionInfo {
            pseudonym: info,
            attribute: transcryptor.attribute_rekey_info(&session_a, &session_b),
        },
        &keys_a.public(),
        rng
    );
    assert_eq!(dec!(&converted, &keys_b), pseudonym);
}

#[test]
fn distributed() {
    let n = 3;
    let rng = &mut rand::rng();
    let (_public, blinded_global_keys, blinding_factors) =
        make_distributed_global_keys_generic::<TestGroup, _>(n, rng);
    let systems = (0..n)
        .map(|i| {
            DistributedTranscryptor::<TestSuite>::new_generic(
                PseudonymizationSecret::from(format!("ps-secret-{i}").as_bytes()),
                RekeyingSecret::from(format!("es-secret-{i}").as_bytes()),
                blinding_factors[i],
            )
        })
        .collect::<Vec<_>>();

    let (domain_a, domain_b) = (
        PseudonymizationDomain::from("user-a"),
        PseudonymizationDomain::from("user-b"),
    );
    let (session_a, session_b) = (
        EncryptionContext::from("session-a"),
        EncryptionContext::from("session-b"),
    );
    let shares_a = systems
        .iter()
        .map(|s| s.session_key_shares(&session_a))
        .collect::<Vec<_>>();
    let shares_b = systems
        .iter()
        .map(|s| s.session_key_shares(&session_b))
        .collect::<Vec<_>>();
    let client_a = Client::<TestGroup>::from_shares(blinded_global_keys, &shares_a);
    let client_b = Client::<TestGroup>::from_shares(blinded_global_keys, &shares_b);

    let pseudonym = Pseudonym::<TestGroup>::random(rng);
    let encrypted = client_a.encrypt(&pseudonym, rng);

    // Each transcryptor passes on the key the ciphertext is now encrypted under.
    #[cfg(not(feature = "elgamal3"))]
    let mut key = client_a.keys().public().pseudonym;
    let mut current = encrypted;
    for system in &systems {
        let info = system.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
        #[cfg(feature = "elgamal3")]
        {
            current = system.transcrypt(&current, &info, rng);
        }
        #[cfg(not(feature = "elgamal3"))]
        {
            use libpep::keys::RekeyPublicKey;
            current = system.transcrypt(&current, &info, &key, rng);
            key = info.pseudonym.rekey_public_key(&key);
        }
    }
    #[cfg(not(feature = "elgamal3"))]
    assert_eq!(key, client_b.keys().pseudonym.public);
    #[cfg(feature = "elgamal3")]
    assert_ne!(client_b.decrypt(&current).unwrap(), pseudonym);
    #[cfg(not(feature = "elgamal3"))]
    assert_ne!(client_b.decrypt(&current), pseudonym);
}

#[cfg(feature = "verifiable")]
mod verifiable {
    use super::*;
    use libpep::data::records::{EncryptedRecord, Record};
    use libpep::keys::distribution::{
        make_pseudonym_session_key_share_with_proof_generic, BlindingFactor,
    };
    use libpep::verifier::Verifier;

    #[test]
    fn verified_transcryption() {
        let rng = &mut rand::rng();
        let (_public, global_secret) = make_global_keys_generic::<TestGroup, _>(rng);
        let (pseudonymization_secret, rekeying_secret) = secrets();
        let transcryptor = Transcryptor::<TestSuite>::new_generic(
            pseudonymization_secret,
            rekeying_secret.clone(),
        );
        let (domain_a, domain_b) = (
            PseudonymizationDomain::from("hospital"),
            PseudonymizationDomain::from("research"),
        );
        let (session_a, session_b) = (
            EncryptionContext::from("session-a"),
            EncryptionContext::from("session-b"),
        );
        let keys_a =
            make_session_keys_generic::<TestSuite>(&global_secret, &session_a, &rekeying_secret);
        let keys_b =
            make_session_keys_generic::<TestSuite>(&global_secret, &session_b, &rekeying_secret);

        let record = Record::<TestGroup>::new(
            vec![Pseudonym::random(rng), Pseudonym::random(rng)],
            vec![Attribute::random(rng)],
        );
        let encrypted = EncryptedRecord::<TestGroup>::new(
            record
                .pseudonyms
                .iter()
                .map(|p| encrypt(p, &keys_a.pseudonym.public, rng))
                .collect(),
            record
                .attributes
                .iter()
                .map(|a| encrypt(a, &keys_a.attribute.public, rng))
                .collect(),
        );

        let info = transcryptor.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
        let commitments =
            transcryptor.transcryption_commitment(&domain_a, &domain_b, &session_a, &session_b);

        #[cfg(feature = "elgamal3")]
        let proof = transcryptor.verifiable_transcrypt(&encrypted, &info, rng);
        #[cfg(not(feature = "elgamal3"))]
        let proof = transcryptor.verifiable_transcrypt(&encrypted, &info, &keys_a.public(), rng);

        let verifier = Verifier::<TestSuite>::new_generic();
        #[cfg(feature = "elgamal3")]
        let verified: EncryptedRecord<TestGroup> = verifier
            .verified_reconstruct_transcryption(&encrypted, &proof, &commitments)
            .expect("the proof verifies");
        #[cfg(not(feature = "elgamal3"))]
        let verified: EncryptedRecord<TestGroup> = verifier
            .verified_reconstruct_transcryption(&encrypted, &proof, &keys_a.public(), &commitments)
            .expect("the proof verifies");

        // The verified result decrypts, and converts the pseudonyms.
        let decrypted: Record<TestGroup> = dec!(&verified, &keys_b);
        assert_eq!(decrypted.attributes, record.attributes);
        assert_ne!(decrypted.pseudonyms, record.pseudonyms);

        // Commitments of another ciphersuite do not verify the proof. The legacy derivation has
        // no ciphersuite tag, so both suites derive the same factors there.
        #[cfg(not(feature = "legacy"))]
        {
            let other = Transcryptor::<Ristretto255Sha512>::new(
                PseudonymizationSecret::from(b"pseudonymization secret".to_vec()),
                rekeying_secret,
            );
            let other_commitments =
                other.transcryption_commitment(&domain_a, &domain_b, &session_a, &session_b);
            let other_commitments = libpep::factors::VerifiableTranscryptionCommitment::<TestGroup> {
                pseudonym: libpep::factors::VerifiablePseudonymizationCommitment {
                    reshuffle_commitment:
                        libpep::elgamal::verifiable::PseudonymizationFactorCommitment(
                            libpep::elgamal::verifiable::FactorCommitment(
                                other_commitments.pseudonym.reshuffle_commitment.point(),
                            ),
                        ),
                    rekey_commitment: libpep::elgamal::verifiable::RekeyFactorCommitment(
                        libpep::elgamal::verifiable::FactorCommitment(
                            other_commitments.pseudonym.rekey_commitment.point(),
                        ),
                    ),
                },
                attribute: libpep::factors::VerifiableRekeyCommitment {
                    commitment: libpep::elgamal::verifiable::RekeyFactorCommitment(
                        libpep::elgamal::verifiable::FactorCommitment(
                            other_commitments.attribute.commitment.point(),
                        ),
                    ),
                },
            };
            #[cfg(feature = "elgamal3")]
            let rejected =
                verifier.verified_reconstruct_transcryption(&encrypted, &proof, &other_commitments);
            #[cfg(not(feature = "elgamal3"))]
            let rejected = verifier.verified_reconstruct_transcryption(
                &encrypted,
                &proof,
                &keys_a.public(),
                &other_commitments,
            );
            assert!(rejected.is_err());
        }
    }

    #[test]
    fn session_key_share_proof() {
        let rng = &mut rand::rng();
        let (_, _, blinding_factors) = make_distributed_global_keys_generic::<TestGroup, _>(1, rng);
        let blinding_factor: BlindingFactor<TestGroup> = blinding_factors[0];
        let secret = RekeyingSecret::from(b"rekeying secret".to_vec());
        let factor = make_pseudonym_rekey_factor_generic::<TestSuite>(
            &secret,
            &EncryptionContext::from("session"),
        );
        let (share, proof) = make_pseudonym_session_key_share_with_proof_generic::<TestSuite, _>(
            &factor,
            &blinding_factor,
            rng,
        )
        .expect("a random blinding factor is not weak");
        assert!(proof.matches_share(&share));
    }
}
