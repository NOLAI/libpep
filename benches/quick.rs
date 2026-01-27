//! Quick benchmarks for CI - simple roundtrip transcryption tests with 2 transcryptors.

#![allow(clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libpep::client::{Client, Distributed};
use libpep::data::simple::{Attribute, ElGamalEncryptable, Pseudonym};
use libpep::factors::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use libpep::transcryptor::DistributedTranscryptor;
use rand::rng;

#[cfg(feature = "long")]
use libpep::data::long::{LongAttribute, LongPseudonym};

#[cfg(feature = "json")]
use libpep::data::json::PEPJSONValue;

const NUM_ITEMS: usize = 100;
const NUM_TRANSCRYPTORS: usize = 2;

/// Setup a simple distributed system with 2 transcryptors
fn setup_system() -> (
    Vec<DistributedTranscryptor>,
    Client,
    Client,
    EncryptionContext,
    EncryptionContext,
    PseudonymizationDomain,
    PseudonymizationDomain,
) {
    let rng = &mut rng();
    let n = NUM_TRANSCRYPTORS;

    // Create distributed global keys
    let (_global_public_keys, blinded_global_keys, blinding_factors) =
        libpep::keys::distribution::make_distributed_global_keys(n, rng);

    // Create transcryptors
    let systems: Vec<DistributedTranscryptor> = (0..n)
        .map(|i| {
            let pseudonymization_secret =
                PseudonymizationSecret::from(format!("ps-{i}").as_bytes().into());
            let encryption_secret = EncryptionSecret::from(format!("es-{i}").as_bytes().into());
            DistributedTranscryptor::new(
                pseudonymization_secret,
                encryption_secret,
                blinding_factors[i],
            )
        })
        .collect();

    let session_a = EncryptionContext::from("session-a");
    let session_b = EncryptionContext::from("session-b");
    let domain_a = PseudonymizationDomain::from("domain-a");
    let domain_b = PseudonymizationDomain::from("domain-b");

    // Create session key shares
    let sks_a: Vec<_> = systems
        .iter()
        .map(|s| s.session_key_shares(&session_a))
        .collect();
    let sks_b: Vec<_> = systems
        .iter()
        .map(|s| s.session_key_shares(&session_b))
        .collect();

    let client_a = Client::from_shares(blinded_global_keys, &sks_a);
    let client_b = Client::from_shares(blinded_global_keys, &sks_b);

    (
        systems, client_a, client_b, session_a, session_b, domain_a, domain_b,
    )
}

fn bench_pseudonym_roundtrip(c: &mut Criterion) {
    let (systems, client_a, _client_b, session_a, session_b, domain_a, domain_b) = setup_system();
    let rng = &mut rng();

    // Pre-generate pseudonyms
    let pseudonyms: Vec<_> = (0..NUM_ITEMS).map(|_| Pseudonym::random(rng)).collect();
    let encrypted: Vec<_> = pseudonyms
        .iter()
        .map(|p| client_a.encrypt(p, rng))
        .collect();

    c.bench_function("pseudonym_roundtrip_100", |b| {
        b.iter(|| {
            for enc in &encrypted {
                let transcrypted = systems.iter().fold(*enc, |acc, system| {
                    let info =
                        system.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
                    system.transcrypt(&acc, &info)
                });
                black_box(transcrypted);
            }
        })
    });
}

#[cfg(feature = "batch")]
fn bench_pseudonym_roundtrip_batch(c: &mut Criterion) {
    let (systems, client_a, _client_b, session_a, session_b, domain_a, domain_b) = setup_system();
    let rng_setup = &mut rng();

    // Pre-generate pseudonyms
    let pseudonyms: Vec<_> = (0..NUM_ITEMS)
        .map(|_| Pseudonym::random(rng_setup))
        .collect();
    let encrypted_base: Vec<_> = pseudonyms
        .iter()
        .map(|p| client_a.encrypt(p, rng_setup))
        .collect();

    c.bench_function("pseudonym_roundtrip_batch_100", |b| {
        b.iter(|| {
            let rng = &mut rng();
            let mut working = encrypted_base.clone();
            for system in &systems {
                let info = system.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
                working = system
                    .transcrypt_batch(&mut working, &info, rng)
                    .expect("transcrypt batch")
                    .to_vec();
            }
            black_box(working);
        })
    });
}

fn bench_attribute_roundtrip(c: &mut Criterion) {
    let (systems, client_a, _client_b, session_a, session_b, _domain_a, _domain_b) = setup_system();
    let rng = &mut rng();

    // Pre-generate attributes
    let attributes: Vec<_> = (0..NUM_ITEMS).map(|_| Attribute::random(rng)).collect();
    let encrypted: Vec<_> = attributes
        .iter()
        .map(|a| client_a.encrypt(a, rng))
        .collect();

    c.bench_function("attribute_roundtrip_100", |b| {
        b.iter(|| {
            for enc in &encrypted {
                let rekeyed = systems.iter().fold(*enc, |acc, system| {
                    let info = system.attribute_rekey_info(&session_a, &session_b);
                    system.rekey(&acc, &info)
                });
                black_box(rekeyed);
            }
        })
    });
}

#[cfg(feature = "batch")]
fn bench_attribute_roundtrip_batch(c: &mut Criterion) {
    let (systems, client_a, _client_b, session_a, session_b, _domain_a, _domain_b) = setup_system();
    let rng_setup = &mut rng();

    // Pre-generate attributes
    let attributes: Vec<_> = (0..NUM_ITEMS)
        .map(|_| Attribute::random(rng_setup))
        .collect();
    let encrypted_base: Vec<_> = attributes
        .iter()
        .map(|a| client_a.encrypt(a, rng_setup))
        .collect();

    c.bench_function("attribute_roundtrip_batch_100", |b| {
        b.iter(|| {
            let rng = &mut rng();
            let mut working = encrypted_base.clone();
            for system in &systems {
                let info = system.attribute_rekey_info(&session_a, &session_b);
                working = system
                    .rekey_batch(&mut working, &info, rng)
                    .expect("rekey batch")
                    .to_vec();
            }
            black_box(working);
        })
    });
}

#[cfg(feature = "long")]
fn bench_long_pseudonym_roundtrip(c: &mut Criterion) {
    let (systems, client_a, _client_b, session_a, session_b, domain_a, domain_b) = setup_system();
    let rng = &mut rng();

    // Pre-generate long pseudonyms (50 bytes each)
    let long_pseudonyms: Vec<_> = (0..NUM_ITEMS)
        .map(|_| LongPseudonym::from_bytes_padded(&[42u8; 50]))
        .collect();
    let encrypted: Vec<_> = long_pseudonyms
        .iter()
        .map(|p| client_a.encrypt(p, rng))
        .collect();

    c.bench_function("long_pseudonym_roundtrip_100", |b| {
        b.iter(|| {
            for enc in &encrypted {
                let transcrypted = systems.iter().fold(enc.clone(), |acc, system| {
                    let info =
                        system.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
                    system.transcrypt(&acc, &info)
                });
                black_box(transcrypted);
            }
        })
    });
}

#[cfg(all(feature = "long", feature = "batch"))]
fn bench_long_pseudonym_roundtrip_batch(c: &mut Criterion) {
    let (systems, client_a, _client_b, session_a, session_b, domain_a, domain_b) = setup_system();
    let rng_setup = &mut rng();

    // Pre-generate long pseudonyms (50 bytes each)
    let long_pseudonyms: Vec<_> = (0..NUM_ITEMS)
        .map(|_| LongPseudonym::from_bytes_padded(&[42u8; 50]))
        .collect();
    let encrypted_base: Vec<_> = long_pseudonyms
        .iter()
        .map(|p| client_a.encrypt(p, rng_setup))
        .collect();

    c.bench_function("long_pseudonym_roundtrip_batch_100", |b| {
        b.iter(|| {
            let rng = &mut rng();
            let mut working = encrypted_base.clone();
            for system in &systems {
                let info = system.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
                working = system
                    .transcrypt_batch(&mut working, &info, rng)
                    .expect("transcrypt batch")
                    .to_vec();
            }
            black_box(working);
        })
    });
}

#[cfg(feature = "long")]
fn bench_long_attribute_roundtrip(c: &mut Criterion) {
    let (systems, client_a, _client_b, session_a, session_b, _domain_a, _domain_b) = setup_system();
    let rng = &mut rng();

    // Pre-generate long attributes (50 bytes each)
    let long_attributes: Vec<_> = (0..NUM_ITEMS)
        .map(|_| LongAttribute::from_bytes_padded(&[42u8; 50]))
        .collect();
    let encrypted: Vec<_> = long_attributes
        .iter()
        .map(|a| client_a.encrypt(a, rng))
        .collect();

    c.bench_function("long_attribute_roundtrip_100", |b| {
        b.iter(|| {
            for enc in &encrypted {
                let rekeyed = systems.iter().fold(enc.clone(), |acc, system| {
                    let info = system.attribute_rekey_info(&session_a, &session_b);
                    system.rekey(&acc, &info)
                });
                black_box(rekeyed);
            }
        })
    });
}

#[cfg(all(feature = "long", feature = "batch"))]
fn bench_long_attribute_roundtrip_batch(c: &mut Criterion) {
    let (systems, client_a, _client_b, session_a, session_b, _domain_a, _domain_b) = setup_system();
    let rng_setup = &mut rng();

    // Pre-generate long attributes (50 bytes each)
    let long_attributes: Vec<_> = (0..NUM_ITEMS)
        .map(|_| LongAttribute::from_bytes_padded(&[42u8; 50]))
        .collect();
    let encrypted_base: Vec<_> = long_attributes
        .iter()
        .map(|a| client_a.encrypt(a, rng_setup))
        .collect();

    c.bench_function("long_attribute_roundtrip_batch_100", |b| {
        b.iter(|| {
            let rng = &mut rng();
            let mut working = encrypted_base.clone();
            for system in &systems {
                let info = system.attribute_rekey_info(&session_a, &session_b);
                working = system
                    .rekey_batch(&mut working, &info, rng)
                    .expect("rekey batch")
                    .to_vec();
            }
            black_box(working);
        })
    });
}

#[cfg(feature = "json")]
fn bench_json_roundtrip(c: &mut Criterion) {
    let (systems, client_a, _client_b, session_a, session_b, domain_a, domain_b) = setup_system();
    let rng = &mut rng();

    // Pre-generate JSON values
    let json_values: Vec<_> = (0..NUM_ITEMS)
        .map(|i| {
            let json_str = format!(
                r#"{{"pseudonym": "user{}", "data": "value{}", "nested": {{"key": "value"}}}}"#,
                i, i
            );
            let value: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
            PEPJSONValue::from_value(&value)
        })
        .collect();
    let encrypted: Vec<_> = json_values
        .iter()
        .map(|j| client_a.encrypt(j, rng))
        .collect();

    c.bench_function("json_roundtrip_100", |b| {
        b.iter(|| {
            for enc in &encrypted {
                let transcrypted =
                    systems
                        .iter()
                        .fold(enc.clone(), |acc, system: &DistributedTranscryptor| {
                            let info = system
                                .transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
                            system.transcrypt(&acc, &info)
                        });
                black_box(transcrypted);
            }
        })
    });
}

#[cfg(all(feature = "json", feature = "batch"))]
fn bench_json_roundtrip_batch(c: &mut Criterion) {
    let (systems, client_a, _client_b, session_a, session_b, domain_a, domain_b) = setup_system();
    let rng_setup = &mut rng();

    // Pre-generate JSON values
    let json_values: Vec<_> = (0..NUM_ITEMS)
        .map(|i| {
            let json_str = format!(
                r#"{{"pseudonym": "user{}", "data": "value{}", "nested": {{"key": "value"}}}}"#,
                i, i
            );
            let value: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
            PEPJSONValue::from_value(&value)
        })
        .collect();
    let encrypted_base: Vec<_> = json_values
        .iter()
        .map(|j| client_a.encrypt(j, rng_setup))
        .collect();

    c.bench_function("json_roundtrip_batch_100", |b| {
        b.iter(|| {
            let rng = &mut rng();
            let mut working = encrypted_base.clone();
            for system in &systems {
                let info = system.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
                working = system
                    .transcrypt_batch(&mut working, &info, rng)
                    .expect("transcrypt batch")
                    .to_vec();
            }
            black_box(working);
        })
    });
}

#[cfg(all(feature = "long", feature = "json", feature = "batch"))]
criterion_group!(
    benches,
    bench_pseudonym_roundtrip,
    bench_pseudonym_roundtrip_batch,
    bench_attribute_roundtrip,
    bench_attribute_roundtrip_batch,
    bench_long_pseudonym_roundtrip,
    bench_long_pseudonym_roundtrip_batch,
    bench_long_attribute_roundtrip,
    bench_long_attribute_roundtrip_batch,
    bench_json_roundtrip,
    bench_json_roundtrip_batch
);

#[cfg(all(feature = "long", feature = "json", not(feature = "batch")))]
criterion_group!(
    benches,
    bench_pseudonym_roundtrip,
    bench_attribute_roundtrip,
    bench_long_pseudonym_roundtrip,
    bench_long_attribute_roundtrip,
    bench_json_roundtrip
);

#[cfg(all(feature = "long", feature = "batch", not(feature = "json")))]
criterion_group!(
    benches,
    bench_pseudonym_roundtrip,
    bench_pseudonym_roundtrip_batch,
    bench_attribute_roundtrip,
    bench_attribute_roundtrip_batch,
    bench_long_pseudonym_roundtrip,
    bench_long_pseudonym_roundtrip_batch,
    bench_long_attribute_roundtrip,
    bench_long_attribute_roundtrip_batch
);

#[cfg(all(feature = "long", not(feature = "json"), not(feature = "batch")))]
criterion_group!(
    benches,
    bench_pseudonym_roundtrip,
    bench_attribute_roundtrip,
    bench_long_pseudonym_roundtrip,
    bench_long_attribute_roundtrip
);

#[cfg(all(feature = "json", feature = "batch", not(feature = "long")))]
criterion_group!(
    benches,
    bench_pseudonym_roundtrip,
    bench_pseudonym_roundtrip_batch,
    bench_attribute_roundtrip,
    bench_attribute_roundtrip_batch,
    bench_json_roundtrip,
    bench_json_roundtrip_batch
);

#[cfg(all(feature = "json", not(feature = "long"), not(feature = "batch")))]
criterion_group!(
    benches,
    bench_pseudonym_roundtrip,
    bench_attribute_roundtrip,
    bench_json_roundtrip
);

#[cfg(all(feature = "batch", not(feature = "long"), not(feature = "json")))]
criterion_group!(
    benches,
    bench_pseudonym_roundtrip,
    bench_pseudonym_roundtrip_batch,
    bench_attribute_roundtrip,
    bench_attribute_roundtrip_batch
);

#[cfg(not(any(feature = "long", feature = "json", feature = "batch")))]
criterion_group!(
    benches,
    bench_pseudonym_roundtrip,
    bench_attribute_roundtrip
);

criterion_main!(benches);
