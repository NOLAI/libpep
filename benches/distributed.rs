use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use libpep::client::{Client, Distributed};
use libpep::data::records::EncryptedRecord;
use libpep::data::simple::{Attribute, ElGamalEncryptable, Pseudonym};
use libpep::factors::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use libpep::transcryptor::DistributedTranscryptor;
use rand::rng;

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

criterion_group!(
    benches,
    bench_distributed_transcrypt,
    bench_distributed_transcrypt_batch
);

criterion_main!(benches);
