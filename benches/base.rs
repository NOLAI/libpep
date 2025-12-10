use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libpep::arithmetic::group_elements::{GroupElement, G};
use libpep::arithmetic::scalars::ScalarNonZero;
use libpep::base::elgamal::{decrypt, encrypt};
use libpep::base::primitives::{
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
    let (_, public_key) = setup_keys();
    let mut rng = rng();
    let message = GroupElement::random(&mut rng);

    c.bench_function("encrypt", |b| {
        b.iter(|| {
            let mut rng_inner = rand::rng();
            encrypt(black_box(&message), black_box(&public_key), &mut rng_inner)
        })
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let (secret_key, public_key) = setup_keys();
    let mut rng = rng();
    let message = GroupElement::random(&mut rng);
    let encrypted = encrypt(&message, &public_key, &mut rng);

    c.bench_function("decrypt", |b| {
        b.iter(|| {
            #[cfg(feature = "elgamal3")]
            let _ = decrypt(black_box(&encrypted), black_box(&secret_key));
            #[cfg(not(feature = "elgamal3"))]
            let _ = decrypt(black_box(&encrypted), black_box(&secret_key));
        })
    });
}

fn bench_rerandomize(c: &mut Criterion) {
    let (_, public_key) = setup_keys();
    let mut rng = rng();
    let message = GroupElement::random(&mut rng);
    let encrypted = encrypt(&message, &public_key, &mut rng);
    let r = ScalarNonZero::random(&mut rng);

    c.bench_function("rerandomize", |b| {
        b.iter(|| {
            #[cfg(feature = "elgamal3")]
            let _ = rerandomize(black_box(&encrypted), black_box(&r));
            #[cfg(not(feature = "elgamal3"))]
            let _ = rerandomize(black_box(&encrypted), black_box(&public_key), black_box(&r));
        })
    });
}

fn bench_reshuffle(c: &mut Criterion) {
    let (_, public_key) = setup_keys();
    let mut rng = rng();
    let message = GroupElement::random(&mut rng);
    let encrypted = encrypt(&message, &public_key, &mut rng);
    let s = ScalarNonZero::random(&mut rng);

    c.bench_function("reshuffle", |b| {
        b.iter(|| reshuffle(black_box(&encrypted), black_box(&s)))
    });
}

fn bench_rekey(c: &mut Criterion) {
    let (_, public_key) = setup_keys();
    let mut rng = rng();
    let message = GroupElement::random(&mut rng);
    let encrypted = encrypt(&message, &public_key, &mut rng);
    let k = ScalarNonZero::random(&mut rng);

    c.bench_function("rekey", |b| {
        b.iter(|| rekey(black_box(&encrypted), black_box(&k)))
    });
}

fn bench_rsk(c: &mut Criterion) {
    let (_, public_key) = setup_keys();
    let mut rng = rng();
    let message = GroupElement::random(&mut rng);
    let encrypted = encrypt(&message, &public_key, &mut rng);
    let s = ScalarNonZero::random(&mut rng);
    let k = ScalarNonZero::random(&mut rng);

    c.bench_function("rsk", |b| {
        b.iter(|| rsk(black_box(&encrypted), black_box(&s), black_box(&k)))
    });
}

fn bench_rrsk(c: &mut Criterion) {
    let (_, public_key) = setup_keys();
    let mut rng = rng();
    let message = GroupElement::random(&mut rng);
    let encrypted = encrypt(&message, &public_key, &mut rng);
    let r = ScalarNonZero::random(&mut rng);
    let s = ScalarNonZero::random(&mut rng);
    let k = ScalarNonZero::random(&mut rng);

    c.bench_function("rrsk", |b| {
        b.iter(|| {
            #[cfg(feature = "elgamal3")]
            let _ = rrsk(
                black_box(&encrypted),
                black_box(&r),
                black_box(&s),
                black_box(&k),
            );
            #[cfg(not(feature = "elgamal3"))]
            let _ = rrsk(
                black_box(&encrypted),
                black_box(&public_key),
                black_box(&r),
                black_box(&s),
                black_box(&k),
            );
        })
    });
}

fn bench_reshuffle2(c: &mut Criterion) {
    let (_, public_key) = setup_keys();
    let mut rng = rng();
    let message = GroupElement::random(&mut rng);
    let encrypted = encrypt(&message, &public_key, &mut rng);
    let s_from = ScalarNonZero::random(&mut rng);
    let s_to = ScalarNonZero::random(&mut rng);

    c.bench_function("reshuffle2", |b| {
        b.iter(|| reshuffle2(black_box(&encrypted), black_box(&s_from), black_box(&s_to)))
    });
}

fn bench_rekey2(c: &mut Criterion) {
    let (_, public_key) = setup_keys();
    let mut rng = rng();
    let message = GroupElement::random(&mut rng);
    let encrypted = encrypt(&message, &public_key, &mut rng);
    let k_from = ScalarNonZero::random(&mut rng);
    let k_to = ScalarNonZero::random(&mut rng);

    c.bench_function("rekey2", |b| {
        b.iter(|| rekey2(black_box(&encrypted), black_box(&k_from), black_box(&k_to)))
    });
}

fn bench_rsk2(c: &mut Criterion) {
    let (_, public_key) = setup_keys();
    let mut rng = rng();
    let message = GroupElement::random(&mut rng);
    let encrypted = encrypt(&message, &public_key, &mut rng);
    let s_from = ScalarNonZero::random(&mut rng);
    let s_to = ScalarNonZero::random(&mut rng);
    let k_from = ScalarNonZero::random(&mut rng);
    let k_to = ScalarNonZero::random(&mut rng);

    c.bench_function("rsk2", |b| {
        b.iter(|| {
            rsk2(
                black_box(&encrypted),
                black_box(&s_from),
                black_box(&s_to),
                black_box(&k_from),
                black_box(&k_to),
            )
        })
    });
}

fn bench_rrsk2(c: &mut Criterion) {
    let (_, public_key) = setup_keys();
    let mut rng = rng();
    let message = GroupElement::random(&mut rng);
    let encrypted = encrypt(&message, &public_key, &mut rng);
    let r = ScalarNonZero::random(&mut rng);
    let s_from = ScalarNonZero::random(&mut rng);
    let s_to = ScalarNonZero::random(&mut rng);
    let k_from = ScalarNonZero::random(&mut rng);
    let k_to = ScalarNonZero::random(&mut rng);

    c.bench_function("rrsk2", |b| {
        b.iter(|| {
            #[cfg(feature = "elgamal3")]
            let _ = rrsk2(
                black_box(&encrypted),
                black_box(&r),
                black_box(&s_from),
                black_box(&s_to),
                black_box(&k_from),
                black_box(&k_to),
            );
            #[cfg(not(feature = "elgamal3"))]
            let _ = rrsk2(
                black_box(&encrypted),
                black_box(&public_key),
                black_box(&r),
                black_box(&s_from),
                black_box(&s_to),
                black_box(&k_from),
                black_box(&k_to),
            );
        })
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
