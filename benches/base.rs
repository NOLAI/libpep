use criterion::{criterion_group, criterion_main, Criterion};
use libpep::arithmetic::group_elements::{GroupElement, G};
use libpep::arithmetic::scalars::ScalarNonZero;
use libpep::core::elgamal::{decrypt, encrypt};
use libpep::core::primitives::{
    rekey, rekey2, rerandomize, reshuffle, reshuffle2, rrsk, rrsk2, rsk, rsk2,
};
use rand::rng;

#[cfg(feature = "verifiable")]
use libpep::core::proved::{
    PseudonymizationFactorCommitments, RSKFactorsProof, RekeyFactorCommitments, VerifiableRSK,
    VerifiableRekey, VerifiableReshuffle,
};

fn setup_keys() -> (ScalarNonZero, GroupElement) {
    let mut rng = rng();
    let secret_key = ScalarNonZero::random(&mut rng);
    let public_key = secret_key * G;
    (secret_key, public_key)
}

fn bench_encrypt(c: &mut Criterion) {
    c.bench_function("encrypt", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                (message, public_key, rng)
            },
            |(message, public_key, mut rng)| encrypt(&message, &public_key, &mut rng),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_decrypt(c: &mut Criterion) {
    c.bench_function("decrypt", |b| {
        b.iter_batched(
            || {
                let (secret_key, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                (encrypted, secret_key)
            },
            |(encrypted, secret_key)| decrypt(&encrypted, &secret_key),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_rerandomize(c: &mut Criterion) {
    c.bench_function("rerandomize", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                (encrypted, public_key, r)
            },
            |(encrypted, _public_key, r)| {
                #[cfg(feature = "elgamal3")]
                {
                    rerandomize(&encrypted, &r)
                }
                #[cfg(not(feature = "elgamal3"))]
                {
                    rerandomize(&encrypted, &_public_key, &r)
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_reshuffle(c: &mut Criterion) {
    c.bench_function("reshuffle", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let s = ScalarNonZero::random(&mut rng);
                (encrypted, s)
            },
            |(encrypted, s)| reshuffle(&encrypted, &s),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_rekey(c: &mut Criterion) {
    c.bench_function("rekey", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let k = ScalarNonZero::random(&mut rng);
                (encrypted, k)
            },
            |(encrypted, k)| rekey(&encrypted, &k),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_rsk(c: &mut Criterion) {
    c.bench_function("rsk", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let s = ScalarNonZero::random(&mut rng);
                let k = ScalarNonZero::random(&mut rng);
                (encrypted, s, k)
            },
            |(encrypted, s, k)| rsk(&encrypted, &s, &k),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_rrsk(c: &mut Criterion) {
    c.bench_function("rrsk", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                let s = ScalarNonZero::random(&mut rng);
                let k = ScalarNonZero::random(&mut rng);
                (encrypted, public_key, r, s, k)
            },
            |(encrypted, _public_key, r, s, k)| {
                #[cfg(feature = "elgamal3")]
                {
                    rrsk(&encrypted, &r, &s, &k)
                }
                #[cfg(not(feature = "elgamal3"))]
                {
                    rrsk(&encrypted, &_public_key, &r, &s, &k)
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_reshuffle2(c: &mut Criterion) {
    c.bench_function("reshuffle2", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let s_from = ScalarNonZero::random(&mut rng);
                let s_to = ScalarNonZero::random(&mut rng);
                (encrypted, s_from, s_to)
            },
            |(encrypted, s_from, s_to)| reshuffle2(&encrypted, &s_from, &s_to),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_rekey2(c: &mut Criterion) {
    c.bench_function("rekey2", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let k_from = ScalarNonZero::random(&mut rng);
                let k_to = ScalarNonZero::random(&mut rng);
                (encrypted, k_from, k_to)
            },
            |(encrypted, k_from, k_to)| rekey2(&encrypted, &k_from, &k_to),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_rsk2(c: &mut Criterion) {
    c.bench_function("rsk2", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let s_from = ScalarNonZero::random(&mut rng);
                let s_to = ScalarNonZero::random(&mut rng);
                let k_from = ScalarNonZero::random(&mut rng);
                let k_to = ScalarNonZero::random(&mut rng);
                (encrypted, s_from, s_to, k_from, k_to)
            },
            |(encrypted, s_from, s_to, k_from, k_to)| {
                rsk2(&encrypted, &s_from, &s_to, &k_from, &k_to)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_rrsk2(c: &mut Criterion) {
    c.bench_function("rrsk2", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                let s_from = ScalarNonZero::random(&mut rng);
                let s_to = ScalarNonZero::random(&mut rng);
                let k_from = ScalarNonZero::random(&mut rng);
                let k_to = ScalarNonZero::random(&mut rng);
                (encrypted, public_key, r, s_from, s_to, k_from, k_to)
            },
            |(encrypted, _public_key, r, s_from, s_to, k_from, k_to)| {
                #[cfg(feature = "elgamal3")]
                {
                    rrsk2(&encrypted, &r, &s_from, &s_to, &k_from, &k_to)
                }
                #[cfg(not(feature = "elgamal3"))]
                {
                    rrsk2(&encrypted, &_public_key, &r, &s_from, &s_to, &k_from, &k_to)
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_verifiable_reshuffle_create(c: &mut Criterion) {
    c.bench_function("verifiable_reshuffle_create", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let s = ScalarNonZero::random(&mut rng);
                (encrypted, s, rng)
            },
            |(encrypted, s, mut rng)| VerifiableReshuffle::new(&encrypted, &s, &mut rng),
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_verifiable_reshuffle_verify(c: &mut Criterion) {
    c.bench_function("verifiable_reshuffle_verify", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let s = ScalarNonZero::random(&mut rng);
                let proof = VerifiableReshuffle::new(&encrypted, &s, &mut rng);
                let result = reshuffle(&encrypted, &s);
                let (commitments, _) = PseudonymizationFactorCommitments::new(&s, &mut rng);
                (encrypted, result, proof, commitments)
            },
            |(encrypted, result, proof, commitments)| {
                proof.verify_reshuffle(&encrypted, &result, &commitments)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_verifiable_rekey_create(c: &mut Criterion) {
    c.bench_function("verifiable_rekey_create", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let k = ScalarNonZero::random(&mut rng);
                (encrypted, k, rng)
            },
            |(encrypted, k, mut rng)| VerifiableRekey::new(&encrypted, &k, &mut rng),
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_verifiable_rekey_verify(c: &mut Criterion) {
    c.bench_function("verifiable_rekey_verify", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let k = ScalarNonZero::random(&mut rng);
                let proof = VerifiableRekey::new(&encrypted, &k, &mut rng);
                let result = rekey(&encrypted, &k);
                let (commitments, _) = RekeyFactorCommitments::new(&k, &mut rng);
                (encrypted, result, proof, commitments)
            },
            |(encrypted, result, proof, commitments)| {
                proof.verify_rekey(&encrypted, &result, &commitments)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_verifiable_rsk_create(c: &mut Criterion) {
    c.bench_function("verifiable_rsk_create", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let s = ScalarNonZero::random(&mut rng);
                let k = ScalarNonZero::random(&mut rng);
                (encrypted, s, k, rng)
            },
            |(encrypted, s, k, mut rng)| VerifiableRSK::new(&encrypted, &s, &k, &mut rng),
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_verifiable_rsk_verify(c: &mut Criterion) {
    c.bench_function("verifiable_rsk_verify", |b| {
        b.iter_batched(
            || {
                let (_, public_key) = setup_keys();
                let mut rng = rand::rng();
                let message = GroupElement::random(&mut rng);
                let encrypted = encrypt(&message, &public_key, &mut rng);
                let s = ScalarNonZero::random(&mut rng);
                let k = ScalarNonZero::random(&mut rng);
                let proof = VerifiableRSK::new(&encrypted, &s, &k, &mut rng);
                let result = rsk(&encrypted, &s, &k);
                let rsk_proof = RSKFactorsProof::new(&s, &k, &mut rng);
                let (reshuffle_commitments, _) =
                    PseudonymizationFactorCommitments::new(&s, &mut rng);
                let (rekey_commitments, _) = RekeyFactorCommitments::new(&k, &mut rng);
                (
                    encrypted,
                    result,
                    proof,
                    rsk_proof,
                    reshuffle_commitments,
                    rekey_commitments,
                )
            },
            |(encrypted, result, proof, rsk_proof, reshuffle_commitments, rekey_commitments)| {
                proof.verify_rsk(
                    &encrypted,
                    &result,
                    &rsk_proof,
                    &reshuffle_commitments,
                    &rekey_commitments,
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
criterion_group!(
    benches,
    bench_encrypt,
    bench_decrypt,
    bench_rerandomize,
    bench_reshuffle,
    bench_rekey,
    bench_rsk,
    bench_rrsk,
    bench_reshuffle2,
    bench_rekey2,
    bench_rsk2,
    bench_rrsk2,
    bench_verifiable_reshuffle_create,
    bench_verifiable_reshuffle_verify,
    bench_verifiable_rekey_create,
    bench_verifiable_rekey_verify,
    bench_verifiable_rsk_create,
    bench_verifiable_rsk_verify
);

#[cfg(not(feature = "verifiable"))]
criterion_group!(
    benches,
    bench_encrypt,
    bench_decrypt,
    bench_rerandomize,
    bench_reshuffle,
    bench_rekey,
    bench_rsk,
    bench_rrsk,
    bench_reshuffle2,
    bench_rekey2,
    bench_rsk2,
    bench_rrsk2
);

criterion_main!(benches);
