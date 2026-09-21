//! The batch protocol of draft-doesburg-cfrg-coprf over its wire formats: a sender, three
//! distributed transcryptors and a receiver that exchange nothing but `BatchRequest` and
//! `BatchResponse` bytes and session key share bytes.
#![cfg(all(feature = "batch", feature = "wire"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use libpep::client::{Client, Distributed};
use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::data::simple::{
    Attribute, ElGamalEncryptable, ElGamalEncrypted, EncryptedAttribute, EncryptedPseudonym,
    Pseudonym,
};
use libpep::data::traits::{Encrypted, Pseudonymizable};
use libpep::elgamal::arithmetic::group_elements::G;
use libpep::elgamal::arithmetic::scalars::ScalarNonZero;
use libpep::elgamal::ElGamal;
use libpep::errors::BatchError;
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use libpep::keys::distribution::{make_distributed_global_keys, SessionKeyShares};
use libpep::keys::PublicKey;
use libpep::transcryptor::{DistributedTranscryptor, Transcryptor};
use libpep::wire::{BatchKind, BatchRequest, BatchResponse, WireError};
use std::collections::HashSet;

const DOMAIN_A: &str = "domain-a";
const DOMAIN_B: &str = "domain-b";
const SESSION_A: &str = "session-a";
const SESSION_B: &str = "session-b";

struct Setup {
    systems: Vec<DistributedTranscryptor>,
    sender: Client,
    receiver: Client,
}

fn setup(n: usize) -> Setup {
    let rng = &mut rand::rng();
    let (_, blinded, blinding_factors) = make_distributed_global_keys(n, rng);
    let systems: Vec<_> = (0..n)
        .map(|i| {
            DistributedTranscryptor::new(
                PseudonymizationSecret::from(format!("ps-{i}").into_bytes()),
                EncryptionSecret::from(format!("es-{i}").into_bytes()),
                blinding_factors[i],
            )
        })
        .collect();
    // Session key shares travel to the clients as bytes.
    let shares = |session: &str| {
        systems
            .iter()
            .map(|s| {
                let bytes = s
                    .session_key_shares(&EncryptionContext::from(session))
                    .to_bytes();
                SessionKeyShares::from_bytes(&bytes).unwrap()
            })
            .collect::<Vec<_>>()
    };
    let sender = Client::from_shares(blinded, &shares(SESSION_A));
    let receiver = Client::from_shares(blinded, &shares(SESSION_B));
    Setup {
        systems,
        sender,
        receiver,
    }
}

fn decrypt<E: Encrypted>(client: &Client, e: &E) -> E::UnencryptedType
where
    libpep::keys::SessionKeys: libpep::keys::KeyProvider<E::SecretKeyType>,
{
    #[cfg(feature = "elgamal3")]
    return client.decrypt(e).expect("decryption succeeds");
    #[cfg(not(feature = "elgamal3"))]
    client.decrypt(e)
}

/// Send `request` through every transcryptor in turn, each hop purely as bytes, and return the
/// final decoded response.
fn chain(systems: &[DistributedTranscryptor], request: &BatchRequest) -> BatchResponse {
    let rng = &mut rand::rng();
    let mut bytes = request.to_bytes();
    let mut response = None;
    for system in systems {
        let req = BatchRequest::from_bytes(&bytes).unwrap();
        let resp = system.transcrypt_wire(&req, rng).unwrap();
        let resp_bytes = resp.to_bytes();
        let resp = BatchResponse::from_bytes(&resp_bytes).unwrap();
        bytes = BatchRequest::new(
            req.kind(),
            req.d_from(),
            req.d_to(),
            req.c_from(),
            req.c_to(),
            *resp.y_to(),
            resp.items().to_vec(),
        )
        .unwrap()
        .to_bytes();
        response = Some(resp);
    }
    response.unwrap()
}

#[test]
fn pseudonym_batch_through_three_transcryptors() {
    let rng = &mut rand::rng();
    let Setup {
        systems,
        sender,
        receiver,
    } = setup(3);
    let pseudonyms: Vec<Pseudonym> = (0..5).map(|_| Pseudonym::random(rng)).collect();
    let encrypted: Vec<EncryptedPseudonym> =
        pseudonyms.iter().map(|p| sender.encrypt(p, rng)).collect();

    let request = BatchRequest::new(
        BatchKind::Pseudonym,
        DOMAIN_A,
        DOMAIN_B,
        SESSION_A,
        SESSION_B,
        *sender.dump().pseudonym.public.value(),
        encrypted.iter().map(|e| *e.value()).collect(),
    )
    .unwrap();
    let response = chain(&systems, &request);

    assert_eq!(
        response.y_to(),
        receiver.dump().pseudonym.public.value(),
        "the response key is the receiver's session key"
    );
    assert_eq!(response.items().len(), pseudonyms.len());

    // The receiver decrypts to the pseudonyms it would get from the in-memory API.
    let expected: HashSet<Pseudonym> = encrypted
        .iter()
        .map(|e| {
            let out = systems.iter().fold(
                (*e, sender.dump().pseudonym.public),
                |(acc, key), system| {
                    let info = system.pseudonymization_info(
                        &PseudonymizationDomain::from(DOMAIN_A),
                        &PseudonymizationDomain::from(DOMAIN_B),
                        &EncryptionContext::from(SESSION_A),
                        &EncryptionContext::from(SESSION_B),
                    );
                    #[cfg(feature = "elgamal3")]
                    let next = acc.pseudonymize(&info, rng);
                    #[cfg(not(feature = "elgamal3"))]
                    let next = acc.pseudonymize(&info, &key, rng);
                    (next, info.rekey_public_key(&key))
                },
            );
            decrypt(&receiver, &out.0)
        })
        .collect();
    let got: HashSet<Pseudonym> = response
        .items()
        .iter()
        .map(|c| decrypt(&receiver, &EncryptedPseudonym::from_value(*c)))
        .collect();
    assert_eq!(got, expected);
    assert!(
        got.is_disjoint(&pseudonyms.iter().copied().collect()),
        "pseudonyms are reshuffled into the receiver's domain"
    );
}

#[test]
fn attribute_batch_through_three_transcryptors() {
    let rng = &mut rand::rng();
    let Setup {
        systems,
        sender,
        receiver,
    } = setup(3);
    let attributes: Vec<Attribute> = (0..4).map(|_| Attribute::random(rng)).collect();
    let encrypted: Vec<EncryptedAttribute> =
        attributes.iter().map(|a| sender.encrypt(a, rng)).collect();

    let request = BatchRequest::new(
        BatchKind::Attribute,
        DOMAIN_A,
        DOMAIN_B,
        SESSION_A,
        SESSION_B,
        *sender.dump().attribute.public.value(),
        encrypted.iter().map(|e| *e.value()).collect(),
    )
    .unwrap();
    let response = chain(&systems, &request);

    assert_eq!(
        response.y_to(),
        receiver.dump().attribute.public.value(),
        "the response key is the receiver's session key"
    );
    let got: HashSet<Attribute> = response
        .items()
        .iter()
        .map(|c| decrypt(&receiver, &EncryptedAttribute::from_value(*c)))
        .collect();
    assert_eq!(got, attributes.iter().copied().collect());
    assert_ne!(
        response.items().iter().collect::<Vec<_>>(),
        encrypted.iter().map(|e| e.value()).collect::<Vec<_>>(),
        "every item is rerandomized"
    );
}

#[test]
fn transcryptor_and_distributed_transcryptor_agree() {
    let rng = &mut rand::rng();
    let ps = PseudonymizationSecret::from(b"ps".to_vec());
    let es = EncryptionSecret::from(b"es".to_vec());
    let plain = Transcryptor::new(ps.clone(), es.clone());
    let distributed = DistributedTranscryptor::new(
        ps,
        es,
        libpep::keys::distribution::BlindingFactor::random(rng),
    );
    let key = ScalarNonZero::random(rng) * G;
    let items = vec![libpep::elgamal::encrypt(
        &(ScalarNonZero::random(rng) * G),
        &key,
        rng,
    )];
    let request = BatchRequest::new(
        BatchKind::Attribute,
        "",
        "",
        SESSION_A,
        SESSION_B,
        key,
        items,
    )
    .unwrap();
    let a = plain.transcrypt_wire(&request, rng).unwrap();
    let b = distributed.transcrypt_wire(&request, rng).unwrap();
    assert_eq!(
        a.y_to(),
        b.y_to(),
        "the blinding factor plays no role in transcryption"
    );
}

#[test]
fn identifiers_must_name_contexts() {
    let rng = &mut rand::rng();
    let transcryptor = Transcryptor::new(
        PseudonymizationSecret::from(b"ps".to_vec()),
        EncryptionSecret::from(b"es".to_vec()),
    );
    let key = ScalarNonZero::random(rng) * G;
    let items: Vec<ElGamal> = vec![libpep::elgamal::encrypt(
        &(ScalarNonZero::random(rng) * G),
        &key,
        rng,
    )];
    let request = BatchRequest::new(
        BatchKind::Pseudonym,
        vec![0xff],
        DOMAIN_B,
        SESSION_A,
        SESSION_B,
        key,
        items,
    )
    .unwrap();
    let err = transcryptor.transcrypt_wire(&request, rng).unwrap_err();
    assert!(
        matches!(err, BatchError::Wire(WireError::IdentifierNotUtf8)),
        "{err}"
    );
}

#[test]
fn malformed_bytes_are_rejected_before_transcryption() {
    let rng = &mut rand::rng();
    let key = ScalarNonZero::random(rng) * G;
    let request = BatchRequest::new(
        BatchKind::Pseudonym,
        DOMAIN_A,
        DOMAIN_B,
        SESSION_A,
        SESSION_B,
        key,
        vec![libpep::elgamal::encrypt(
            &(ScalarNonZero::random(rng) * G),
            &key,
            rng,
        )],
    )
    .unwrap();
    let bytes = request.to_bytes();

    let mut unknown_type = bytes.clone();
    unknown_type[0] = 0;
    assert_eq!(
        BatchRequest::from_bytes(&unknown_type),
        Err(WireError::UnknownType(0))
    );
    assert!(matches!(
        BatchRequest::from_bytes(&bytes[..bytes.len() - 1]),
        Err(WireError::Truncated { .. })
    ));
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(&[1, 2]);
    assert_eq!(
        BatchRequest::from_bytes(&trailing),
        Err(WireError::TrailingBytes(2))
    );
    let mut empty = bytes.clone();
    let count_at = bytes.len() - 4 - 64;
    empty.truncate(count_at);
    empty.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(BatchRequest::from_bytes(&empty), Err(WireError::EmptyBatch));
    let mut identity = bytes;
    let c_at = identity.len() - 32;
    identity[c_at..].copy_from_slice(
        &libpep::elgamal::arithmetic::group_elements::GroupElement::identity().to_bytes(),
    );
    assert_eq!(
        BatchRequest::from_bytes(&identity),
        Err(WireError::InvalidElement { offset: c_at })
    );
}
