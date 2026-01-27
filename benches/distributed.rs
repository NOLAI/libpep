use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use libpep::client::{Client, Distributed};
use libpep::data::records::EncryptedRecord;
use libpep::data::simple::{Attribute, ElGamalEncryptable, Pseudonym};
use libpep::factors::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use libpep::transcryptor::DistributedTranscryptor;
use rand::rng;

#[cfg(feature = "verifiable")]
use libpep::data::traits::{Pseudonymizable, VerifiablePseudonymizable, VerifiableRekeyable};
#[cfg(feature = "verifiable")]
use libpep::transcryptor::Transcryptor;
#[cfg(feature = "verifiable")]
use libpep::verifier::Verifier;

/// Configuration parameters for distributed benchmarks
pub const BENCHMARK_SERVERS: [usize; 4] = [1, 2, 3, 4];
pub const BENCHMARK_ENTITIES: [usize; 4] = [1, 10, 100, 1000];
pub const BENCHMARK_STRUCTURES: [(usize, usize); 4] = [(1, 0), (1, 1), (1, 2), (1, 10)];

/// Setup a distributed PEP system with n transcryptors
pub fn setup_distributed_system(
    n: usize,
) -> (
    Vec<DistributedTranscryptor>,
    Client,
    Client,
    EncryptionContext,
    EncryptionContext,
    PseudonymizationDomain,
    PseudonymizationDomain,
) {
    let rng = &mut rng();

    // Create distributed global keys
    let (_global_public_keys, blinded_global_keys, blinding_factors) =
        libpep::keys::distribution::make_distributed_global_keys(n, rng);

    // Create transcryptors
    let systems: Vec<DistributedTranscryptor> = (0..n)
        .map(|i| {
            let pseudonymization_secret =
                PseudonymizationSecret::from(format!("ps-secret-{i}").as_bytes().into());
            let encryption_secret =
                EncryptionSecret::from(format!("es-secret-{i}").as_bytes().into());
            let blinding_factor = blinding_factors[i];
            DistributedTranscryptor::new(
                pseudonymization_secret,
                encryption_secret,
                blinding_factor,
            )
        })
        .collect();

    // Create encryption contexts
    let session_a = EncryptionContext::from("session-a");
    let session_b = EncryptionContext::from("session-b");

    // Create pseudonymization domains
    let domain_a = PseudonymizationDomain::from("domain-a");
    let domain_b = PseudonymizationDomain::from("domain-b");

    // Create session key shares
    let sks_a = systems
        .iter()
        .map(|system: &DistributedTranscryptor| system.session_key_shares(&session_a))
        .collect::<Vec<_>>();
    let sks_b = systems
        .iter()
        .map(|system: &DistributedTranscryptor| system.session_key_shares(&session_b))
        .collect::<Vec<_>>();

    // Create clients
    let client_a = Client::from_shares(blinded_global_keys, &sks_a);
    let client_b = Client::from_shares(blinded_global_keys, &sks_b);

    (
        systems, client_a, client_b, session_a, session_b, domain_a, domain_b,
    )
}

/// Generate test entities with the given structure
pub fn generate_entities(
    num_entities: usize,
    num_pseudonyms_per_entity: usize,
    num_attributes_per_entity: usize,
    client: &Client,
) -> Vec<(
    Vec<libpep::data::simple::EncryptedPseudonym>,
    Vec<libpep::data::simple::EncryptedAttribute>,
)> {
    let rng = &mut rng();
    (0..num_entities)
        .map(|_| {
            let pseudonyms: Vec<_> = (0..num_pseudonyms_per_entity)
                .map(|_| {
                    let pseudonym = Pseudonym::random(rng);
                    client.encrypt(&pseudonym, rng)
                })
                .collect();
            let attributes: Vec<_> = (0..num_attributes_per_entity)
                .map(|_| {
                    let attribute = Attribute::random(rng);
                    client.encrypt(&attribute, rng)
                })
                .collect();
            (pseudonyms, attributes)
        })
        .collect()
}

/// Process entities individually through all servers
pub fn process_entities_individually(
    entities: &[(
        Vec<libpep::data::simple::EncryptedPseudonym>,
        Vec<libpep::data::simple::EncryptedAttribute>,
    )],
    systems: &[DistributedTranscryptor],
    domain_a: &PseudonymizationDomain,
    domain_b: &PseudonymizationDomain,
    session_a: &EncryptionContext,
    session_b: &EncryptionContext,
) {
    for (pseudonyms, attributes) in entities {
        // Process all pseudonyms for this entity
        for encrypted in pseudonyms {
            let _ = systems
                .iter()
                .fold(*encrypted, |acc, system: &DistributedTranscryptor| {
                    let transcryption_info =
                        system.transcryption_info(domain_a, domain_b, session_a, session_b);
                    system.transcrypt(&acc, &transcryption_info)
                });
        }
        // Process all attributes for this entity
        for encrypted in attributes {
            let _ = systems
                .iter()
                .fold(*encrypted, |acc, system: &DistributedTranscryptor| {
                    let rekey_info = system.attribute_rekey_info(session_a, session_b);
                    system.rekey(&acc, &rekey_info)
                });
        }
    }
}

/// Process entities using batch operations
pub fn process_entities_batch(
    entities: Vec<(
        Vec<libpep::data::simple::EncryptedPseudonym>,
        Vec<libpep::data::simple::EncryptedAttribute>,
    )>,
    systems: &[DistributedTranscryptor],
    domain_a: &PseudonymizationDomain,
    domain_b: &PseudonymizationDomain,
    session_a: &EncryptionContext,
    session_b: &EncryptionContext,
) {
    // Convert entity tuples to EncryptedRecord
    let mut batch: Vec<EncryptedRecord> = entities
        .into_iter()
        .map(|(pseudonyms, attributes)| EncryptedRecord::new(pseudonyms, attributes))
        .collect();

    let mut batch_rng = rand::rng();

    for system in systems {
        let transcryption_info =
            system.transcryption_info(domain_a, domain_b, session_a, session_b);
        batch = match system.transcrypt_batch(&mut batch, &transcryption_info, &mut batch_rng) {
            Ok(result) => result.to_vec(),
            Err(e) => {
                panic!("Batch transcryption failed during benchmark: {e:?}");
            }
        };
    }
}

// Functions are used by criterion_group! macro, but compiler doesn't recognize this
#[allow(dead_code)]
fn bench_distributed_transcrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("distributed_transcrypt_complete");
    group.sample_size(50);

    for num_servers in BENCHMARK_SERVERS.iter() {
        for num_entities in BENCHMARK_ENTITIES.iter() {
            for (num_pseudonyms_per_entity, num_attributes_per_entity) in
                BENCHMARK_STRUCTURES.iter()
            {
                group.bench_with_input(
                    BenchmarkId::from_parameter(format!(
                        "{}servers_{}entities_{}p_{}a",
                        num_servers,
                        num_entities,
                        num_pseudonyms_per_entity,
                        num_attributes_per_entity
                    )),
                    &(
                        num_servers,
                        num_entities,
                        num_pseudonyms_per_entity,
                        num_attributes_per_entity,
                    ),
                    |b,
                     &(
                        &num_servers,
                        &num_entities,
                        &num_pseudonyms_per_entity,
                        &num_attributes_per_entity,
                    )| {
                        let (systems, client_a, _, session_a, session_b, domain_a, domain_b) =
                            setup_distributed_system(num_servers);

                        // Pre-generate all data as entity tuples
                        let entities = generate_entities(
                            num_entities,
                            num_pseudonyms_per_entity,
                            num_attributes_per_entity,
                            &client_a,
                        );

                        b.iter(|| {
                            process_entities_individually(
                                black_box(&entities),
                                black_box(&systems),
                                black_box(&domain_a),
                                black_box(&domain_b),
                                black_box(&session_a),
                                black_box(&session_b),
                            );
                        })
                    },
                );
            }
        }
    }

    group.finish();
}

// Functions are used by criterion_group! macro, but compiler doesn't recognize this
#[allow(dead_code)]
fn bench_distributed_transcrypt_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("distributed_transcrypt_batch");
    group.sample_size(50);

    for num_servers in BENCHMARK_SERVERS.iter() {
        for num_entities in BENCHMARK_ENTITIES.iter() {
            for (num_pseudonyms_per_entity, num_attributes_per_entity) in
                BENCHMARK_STRUCTURES.iter()
            {
                group.bench_with_input(
                    BenchmarkId::from_parameter(format!(
                        "{}servers_{}entities_{}p_{}a",
                        num_servers,
                        num_entities,
                        num_pseudonyms_per_entity,
                        num_attributes_per_entity
                    )),
                    &(
                        num_servers,
                        num_entities,
                        num_pseudonyms_per_entity,
                        num_attributes_per_entity,
                    ),
                    |b,
                     &(
                        &num_servers,
                        &num_entities,
                        &num_pseudonyms_per_entity,
                        &num_attributes_per_entity,
                    )| {
                        let (systems, client_a, _, session_a, session_b, domain_a, domain_b) =
                            setup_distributed_system(num_servers);

                        // Pre-generate all entities as encrypted pseudonym/attribute tuples
                        let encrypted_data = generate_entities(
                            num_entities,
                            num_pseudonyms_per_entity,
                            num_attributes_per_entity,
                            &client_a,
                        );

                        b.iter_batched(
                            || encrypted_data.clone(),
                            |data| {
                                process_entities_batch(
                                    data, &systems, &domain_a, &domain_b, &session_a, &session_b,
                                );
                            },
                            criterion::BatchSize::LargeInput,
                        )
                    },
                );
            }
        }
    }

    group.finish();
}

#[cfg(feature = "verifiable")]
#[allow(dead_code)]
fn bench_verifiable_commitment_generation(c: &mut Criterion) {
    c.bench_function("verifiable_commitment_generation", |b| {
        b.iter_batched(
            || {
                let rng = rand::rng();
                let ps_secret = PseudonymizationSecret::from(b"pseudonymization-secret".to_vec());
                let enc_secret = EncryptionSecret::from(b"encryption-secret".to_vec());
                let transcryptor = Transcryptor::new(ps_secret.clone(), enc_secret.clone());
                let domain_from = PseudonymizationDomain::from("domain-a");
                let domain_to = PseudonymizationDomain::from("domain-b");
                let session_from = EncryptionContext::from("session-a");
                let session_to = EncryptionContext::from("session-b");
                let info = transcryptor.pseudonymization_info(
                    &domain_from,
                    &domain_to,
                    &session_from,
                    &session_to,
                );
                (info, rng)
            },
            |(info, mut rng)| {
                black_box(Transcryptor::pseudonymization_commitments(&info, &mut rng))
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
#[allow(dead_code)]
fn bench_verifiable_commitment_verification(c: &mut Criterion) {
    c.bench_function("verifiable_commitment_verification", |b| {
        b.iter_batched(
            || {
                let mut rng = rand::rng();
                let ps_secret = PseudonymizationSecret::from(b"pseudonymization-secret".to_vec());
                let enc_secret = EncryptionSecret::from(b"encryption-secret".to_vec());
                let transcryptor = Transcryptor::new(ps_secret.clone(), enc_secret.clone());
                let domain_from = PseudonymizationDomain::from("domain-a");
                let domain_to = PseudonymizationDomain::from("domain-b");
                let session_from = EncryptionContext::from("session-a");
                let session_to = EncryptionContext::from("session-b");
                let info = transcryptor.pseudonymization_info(
                    &domain_from,
                    &domain_to,
                    &session_from,
                    &session_to,
                );
                let commitments = Transcryptor::pseudonymization_commitments(&info, &mut rng);
                let verifier = Verifier::new();
                (commitments, verifier)
            },
            |(commitments, verifier)| {
                black_box(verifier.verify_pseudonymization_commitments(&commitments))
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
#[allow(dead_code)]
fn bench_verifiable_pseudonymization(c: &mut Criterion) {
    c.bench_function("verifiable_pseudonymization", |b| {
        b.iter_batched(
            || {
                let mut rng = rand::rng();
                let ps_secret = PseudonymizationSecret::from(b"pseudonymization-secret".to_vec());
                let enc_secret = EncryptionSecret::from(b"encryption-secret".to_vec());
                let transcryptor = Transcryptor::new(ps_secret.clone(), enc_secret.clone());
                let domain_from = PseudonymizationDomain::from("domain-a");
                let domain_to = PseudonymizationDomain::from("domain-b");
                let session_from = EncryptionContext::from("session-a");
                let session_to = EncryptionContext::from("session-b");

                // Create distributed client and encrypt pseudonym
                let (_global_pub, blinded_keys, blinding_factors) =
                    libpep::keys::distribution::make_distributed_global_keys(1, &mut rng);
                let dis_transcryptor = DistributedTranscryptor::new(
                    ps_secret.clone(),
                    enc_secret.clone(),
                    blinding_factors[0],
                );
                let sks = dis_transcryptor.session_key_shares(&session_from);
                let client = Client::from_shares(blinded_keys, &[sks]);
                let pseudonym = Pseudonym::random(&mut rng);
                let encrypted = client.encrypt(&pseudonym, &mut rng);

                let info = transcryptor.pseudonymization_info(
                    &domain_from,
                    &domain_to,
                    &session_from,
                    &session_to,
                );
                (encrypted, info, rng)
            },
            |(encrypted, info, mut rng)| {
                black_box(encrypted.verifiable_pseudonymize(&info, &mut rng))
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
#[allow(dead_code)]
fn bench_verifiable_rekey(c: &mut Criterion) {
    c.bench_function("verifiable_rekey", |b| {
        b.iter_batched(
            || {
                let mut rng = rand::rng();
                let ps_secret = PseudonymizationSecret::from(b"pseudonymization-secret".to_vec());
                let enc_secret = EncryptionSecret::from(b"encryption-secret".to_vec());
                let transcryptor = Transcryptor::new(ps_secret.clone(), enc_secret.clone());
                let session_from = EncryptionContext::from("session-a");
                let session_to = EncryptionContext::from("session-b");

                // Create distributed client and encrypt attribute
                let (_global_pub, blinded_keys, blinding_factors) =
                    libpep::keys::distribution::make_distributed_global_keys(1, &mut rng);
                let dis_transcryptor = DistributedTranscryptor::new(
                    ps_secret.clone(),
                    enc_secret.clone(),
                    blinding_factors[0],
                );
                let sks = dis_transcryptor.session_key_shares(&session_from);
                let client = Client::from_shares(blinded_keys, &[sks]);
                let attribute = Attribute::random(&mut rng);
                let encrypted = client.encrypt(&attribute, &mut rng);

                let info = transcryptor.attribute_rekey_info(&session_from, &session_to);
                (encrypted, info, rng)
            },
            |(encrypted, info, mut rng)| black_box(encrypted.verifiable_rekey(&info, &mut rng)),
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
#[allow(dead_code)]
fn bench_verifiable_pseudonymization_verify(c: &mut Criterion) {
    c.bench_function("verifiable_pseudonymization_verify", |b| {
        b.iter_batched(
            || {
                let mut rng = rand::rng();
                let ps_secret = PseudonymizationSecret::from(b"pseudonymization-secret".to_vec());
                let enc_secret = EncryptionSecret::from(b"encryption-secret".to_vec());
                let transcryptor = Transcryptor::new(ps_secret.clone(), enc_secret.clone());
                let domain_from = PseudonymizationDomain::from("domain-a");
                let domain_to = PseudonymizationDomain::from("domain-b");
                let session_from = EncryptionContext::from("session-a");
                let session_to = EncryptionContext::from("session-b");

                // Create distributed client and encrypt pseudonym
                let (_global_pub, blinded_keys, blinding_factors) =
                    libpep::keys::distribution::make_distributed_global_keys(1, &mut rng);
                let dis_transcryptor = DistributedTranscryptor::new(
                    ps_secret.clone(),
                    enc_secret.clone(),
                    blinding_factors[0],
                );
                let sks = dis_transcryptor.session_key_shares(&session_from);
                let client = Client::from_shares(blinded_keys, &[sks]);
                let pseudonym = Pseudonym::random(&mut rng);
                let encrypted = client.encrypt(&pseudonym, &mut rng);

                let info = transcryptor.pseudonymization_info(
                    &domain_from,
                    &domain_to,
                    &session_from,
                    &session_to,
                );

                let operation_proof = encrypted.verifiable_pseudonymize(&info, &mut rng);
                let factors_proof = Transcryptor::pseudonymization_factors_proof(&info, &mut rng);
                let result = encrypted.pseudonymize(&info);
                let commitments = Transcryptor::pseudonymization_commitments(&info, &mut rng);
                let verifier = Verifier::new();

                (
                    encrypted,
                    result,
                    operation_proof,
                    factors_proof,
                    commitments,
                    verifier,
                )
            },
            |(original, result, operation_proof, factors_proof, commitments, verifier)| {
                black_box(verifier.verify_pseudonymization(
                    &original,
                    &result,
                    &operation_proof,
                    &factors_proof,
                    &commitments,
                ))
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
criterion_group!(
    benches,
    bench_distributed_transcrypt,
    bench_distributed_transcrypt_batch,
    bench_verifiable_commitment_generation,
    bench_verifiable_commitment_verification,
    bench_verifiable_pseudonymization,
    bench_verifiable_rekey,
    bench_verifiable_pseudonymization_verify
);

#[cfg(not(feature = "verifiable"))]
criterion_group!(
    benches,
    bench_distributed_transcrypt,
    bench_distributed_transcrypt_batch
);

criterion_main!(benches);
