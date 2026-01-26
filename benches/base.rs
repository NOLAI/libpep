use criterion::{criterion_group, criterion_main, Criterion};
use libpep::arithmetic::group_elements::{GroupElement, G};
use libpep::arithmetic::scalars::ScalarNonZero;
use libpep::core::elgamal::{decrypt, encrypt};
use libpep::core::primitives::{
    rekey, rekey2, rerandomize, reshuffle, reshuffle2, rrsk, rrsk2, rsk, rsk2,
};
use rand::rng;

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
