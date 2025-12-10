use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use libpep::core::data::{Attribute, Encryptable, Pseudonym};
use libpep::core::transcryption::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::core::transcryption::secrets::{EncryptionSecret, PseudonymizationSecret};
use libpep::distributed::client::client::PEPClient;
use libpep::distributed::server::setup::make_distributed_global_keys;
use libpep::distributed::server::transcryptor::PEPSystem;
use rand::rng;

/// Setup a distributed PEP system with n transcryptors
fn setup_distributed_system(
    n: usize,
) -> (
    Vec<PEPSystem>,
    PEPClient,
    PEPClient,
    EncryptionContext,
    EncryptionContext,
    PseudonymizationDomain,
    PseudonymizationDomain,
) {
    let rng = &mut rng();

    // Create distributed global keys
    let (_global_public_keys, blinded_global_keys, blinding_factors) =
        make_distributed_global_keys(n, rng);

    // Create transcryptors
    let systems: Vec<PEPSystem> = (0..n)
        .map(|i| {
            let pseudonymization_secret =
                PseudonymizationSecret::from(format!("ps-secret-{i}").as_bytes().into());
            let encryption_secret =
                EncryptionSecret::from(format!("es-secret-{i}").as_bytes().into());
            let blinding_factor = blinding_factors[i];
            PEPSystem::new(pseudonymization_secret, encryption_secret, blinding_factor)
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
        .map(|system| system.session_key_shares(&session_a))
        .collect::<Vec<_>>();
    let sks_b = systems
        .iter()
        .map(|system| system.session_key_shares(&session_b))
        .collect::<Vec<_>>();

    // Create clients
    let client_a = PEPClient::new(blinded_global_keys, &sks_a);
    let client_b = PEPClient::new(blinded_global_keys, &sks_b);

    (
        systems, client_a, client_b, session_a, session_b, domain_a, domain_b,
    )
}

fn bench_client_encrypt_pseudonym(c: &mut Criterion) {
    let (_, client_a, _, _, _, _, _) = setup_distributed_system(3);
    let rng = &mut rng();
    let pseudonym = Pseudonym::random(rng);

    c.bench_function("client_encrypt_pseudonym", |b| {
        b.iter(|| {
            let rng_inner = &mut rand::rng();
            client_a.encrypt_pseudonym(black_box(&pseudonym), rng_inner)
        })
    });
}

fn bench_client_encrypt_attribute(c: &mut Criterion) {
    let (_, client_a, _, _, _, _, _) = setup_distributed_system(3);
    let rng = &mut rng();
    let attribute = Attribute::random(rng);

    c.bench_function("client_encrypt_attribute", |b| {
        b.iter(|| {
            let rng_inner = &mut rand::rng();
            client_a.encrypt_attribute(black_box(&attribute), rng_inner)
        })
    });
}

fn bench_client_decrypt_pseudonym(c: &mut Criterion) {
    let (_, client_a, _, _, _, _, _) = setup_distributed_system(3);
    let rng = &mut rng();
    let pseudonym = Pseudonym::random(rng);
    let encrypted = client_a.encrypt_pseudonym(&pseudonym, rng);

    c.bench_function("client_decrypt_pseudonym", |b| {
        b.iter(|| {
            #[cfg(feature = "elgamal3")]
            let _ = black_box(&client_a)
                .decrypt_pseudonym(black_box(&encrypted))
                .expect("decryption should succeed");
            #[cfg(not(feature = "elgamal3"))]
            let _ = black_box(&client_a).decrypt_pseudonym(black_box(&encrypted));
        })
    });
}

fn bench_client_decrypt_attribute(c: &mut Criterion) {
    let (_, client_a, _, _, _, _, _) = setup_distributed_system(3);
    let rng = &mut rng();
    let attribute = Attribute::random(rng);
    let encrypted = client_a.encrypt_attribute(&attribute, rng);

    c.bench_function("client_decrypt_attribute", |b| {
        b.iter(|| {
            #[cfg(feature = "elgamal3")]
            let _ = black_box(&client_a)
                .decrypt_attribute(black_box(&encrypted))
                .expect("decryption should succeed");
            #[cfg(not(feature = "elgamal3"))]
            let _ = black_box(&client_a).decrypt_attribute(black_box(&encrypted));
        })
    });
}

fn bench_server_rekey_attribute(c: &mut Criterion) {
    let (systems, client_a, _, session_a, session_b, _, _) = setup_distributed_system(3);
    let rng = &mut rng();
    let attribute = Attribute::random(rng);
    let encrypted = client_a.encrypt_attribute(&attribute, rng);
    let rekey_info = systems[0].attribute_rekey_info(&session_a, &session_b);

    c.bench_function("server_rekey_attribute", |b| {
        b.iter(|| systems[0].rekey(black_box(&encrypted), black_box(&rekey_info)))
    });
}

fn bench_server_pseudonymize(c: &mut Criterion) {
    let (systems, client_a, _, session_a, session_b, domain_a, domain_b) =
        setup_distributed_system(3);
    let rng = &mut rng();
    let pseudonym = Pseudonym::random(rng);
    let encrypted = client_a.encrypt_pseudonym(&pseudonym, rng);
    let pseudonymization_info =
        systems[0].pseudonymization_info(&domain_a, &domain_b, &session_a, &session_b);

    c.bench_function("server_pseudonymize", |b| {
        b.iter(|| systems[0].pseudonymize(black_box(&encrypted), black_box(&pseudonymization_info)))
    });
}

fn bench_server_transcrypt(c: &mut Criterion) {
    let (systems, client_a, _, session_a, session_b, domain_a, domain_b) =
        setup_distributed_system(3);
    let rng = &mut rng();
    let pseudonym = Pseudonym::random(rng);
    let encrypted = client_a.encrypt_pseudonym(&pseudonym, rng);
    let transcryption_info =
        systems[0].transcryption_info(&domain_a, &domain_b, &session_a, &session_b);

    c.bench_function("server_transcrypt", |b| {
        b.iter(|| systems[0].transcrypt(black_box(&encrypted), black_box(&transcryption_info)))
    });
}

fn bench_distributed_transcrypt_complete(c: &mut Criterion) {
    let mut group = c.benchmark_group("distributed_transcrypt_complete");

    for n in [2, 3, 5, 7].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, &n| {
            let (systems, client_a, _, session_a, session_b, domain_a, domain_b) =
                setup_distributed_system(n);
            let rng = &mut rng();
            let pseudonym = Pseudonym::random(rng);
            let encrypted = client_a.encrypt_pseudonym(&pseudonym, rng);

            b.iter(|| {
                // Simulate complete transcryption through all servers
                let result = systems.iter().fold(black_box(encrypted), |acc, system| {
                    let transcryption_info = system.transcryption_info(
                        black_box(&domain_a),
                        black_box(&domain_b),
                        black_box(&session_a),
                        black_box(&session_b),
                    );
                    system.transcrypt(&acc, &transcryption_info)
                });
                result
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_client_encrypt_pseudonym,
    bench_client_encrypt_attribute,
    bench_client_decrypt_pseudonym,
    bench_client_decrypt_attribute,
    bench_server_rekey_attribute,
    bench_server_pseudonymize,
    bench_server_transcrypt,
    bench_distributed_transcrypt_complete
);

criterion_main!(benches);
