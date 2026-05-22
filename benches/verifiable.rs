//! Benchmarks for the verifiable transcryption primitives.
//!
//! For each operation we measure:
//!   * `*_create` — running the verifiable operation (generates the proofs).
//!   * `*_verify` — verifying the proof against the input ciphertext and the
//!     forward factor commitment(s).
//!
//! Inputs are generated in the `iter_batched` setup closure so only the
//! operation or verification itself is timed.

#[cfg(feature = "verifiable")]
use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "verifiable")]
use libpep::arithmetic::group_elements::{GroupElement, G};
#[cfg(feature = "verifiable")]
use libpep::arithmetic::scalars::ScalarNonZero;
#[cfg(feature = "verifiable")]
use libpep::core::elgamal::{encrypt, ElGamal};
#[cfg(feature = "verifiable")]
use libpep::core::primitives::{rekey, rekey2, reshuffle, reshuffle2, rrsk, rrsk2, rsk, rsk2};
#[cfg(feature = "verifiable")]
use libpep::core::verifiable::{
    PseudonymizationFactorCommitment, RekeyFactorCommitment, VerifiableRRSK, VerifiableRRSK2,
    VerifiableRSK, VerifiableRSK2, VerifiableRekey, VerifiableRekey2, VerifiableReshuffle,
    VerifiableReshuffle2,
};

#[cfg(feature = "verifiable")]
fn setup_pk() -> GroupElement {
    let mut rng = rand::rng();
    let sk = ScalarNonZero::random(&mut rng);
    sk * G
}

#[cfg(feature = "verifiable")]
fn rrsk_primitive(
    c: &ElGamal,
    _gy: &GroupElement,
    r: &ScalarNonZero,
    s: &ScalarNonZero,
    k: &ScalarNonZero,
) -> ElGamal {
    #[cfg(feature = "elgamal3")]
    {
        let _ = _gy;
        rrsk(c, r, s, k)
    }
    #[cfg(not(feature = "elgamal3"))]
    {
        rrsk(c, _gy, r, s, k)
    }
}

#[cfg(feature = "verifiable")]
fn rrsk2_primitive(
    c: &ElGamal,
    _gy: &GroupElement,
    r: &ScalarNonZero,
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
) -> ElGamal {
    #[cfg(feature = "elgamal3")]
    {
        let _ = _gy;
        rrsk2(c, r, s_from, s_to, k_from, k_to)
    }
    #[cfg(not(feature = "elgamal3"))]
    {
        rrsk2(c, _gy, r, s_from, s_to, k_from, k_to)
    }
}

// ---------------------------------------------------------------------------
// VRS
// ---------------------------------------------------------------------------

#[cfg(feature = "verifiable")]
fn bench_verifiable_reshuffle_create(c: &mut Criterion) {
    c.bench_function("verifiable_reshuffle_create", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
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
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let s = ScalarNonZero::random(&mut rng);
                let proof = VerifiableReshuffle::new(&encrypted, &s, &mut rng);
                let result = reshuffle(&encrypted, &s);
                let commitments = PseudonymizationFactorCommitment::new(&s);
                (encrypted, result, proof, commitments)
            },
            |(encrypted, result, proof, commitments)| {
                proof.verify_reshuffle(&encrypted, &result, &commitments)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

// ---------------------------------------------------------------------------
// VRK
// ---------------------------------------------------------------------------

#[cfg(feature = "verifiable")]
fn bench_verifiable_rekey_create(c: &mut Criterion) {
    c.bench_function("verifiable_rekey_create", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
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
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let k = ScalarNonZero::random(&mut rng);
                let proof = VerifiableRekey::new(&encrypted, &k, &mut rng);
                let result = rekey(&encrypted, &k);
                let commitments = RekeyFactorCommitment::new(&k);
                (encrypted, result, proof, commitments)
            },
            |(encrypted, result, proof, commitments)| {
                proof.verify_rekey(&encrypted, &result, &commitments)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

// ---------------------------------------------------------------------------
// VRSK
// ---------------------------------------------------------------------------

#[cfg(feature = "verifiable")]
fn bench_verifiable_rsk_create(c: &mut Criterion) {
    c.bench_function("verifiable_rsk_create", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
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
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let s = ScalarNonZero::random(&mut rng);
                let k = ScalarNonZero::random(&mut rng);
                let proof = VerifiableRSK::new(&encrypted, &s, &k, &mut rng);
                let result = rsk(&encrypted, &s, &k);
                let rs = PseudonymizationFactorCommitment::new(&s);
                let rk = RekeyFactorCommitment::new(&k);
                (encrypted, result, proof, rs, rk)
            },
            |(encrypted, result, proof, rs, rk)| proof.verify_rsk(&encrypted, &result, &rs, &rk),
            criterion::BatchSize::SmallInput,
        )
    });
}

// ---------------------------------------------------------------------------
// VRS2
// ---------------------------------------------------------------------------

#[cfg(feature = "verifiable")]
fn bench_verifiable_reshuffle2_create(c: &mut Criterion) {
    c.bench_function("verifiable_reshuffle2_create", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let s_from = ScalarNonZero::random(&mut rng);
                let s_to = ScalarNonZero::random(&mut rng);
                (encrypted, s_from, s_to, rng)
            },
            |(encrypted, s_from, s_to, mut rng)| {
                VerifiableReshuffle2::new(&encrypted, &s_from, &s_to, &mut rng)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_verifiable_reshuffle2_verify(c: &mut Criterion) {
    c.bench_function("verifiable_reshuffle2_verify", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let s_from = ScalarNonZero::random(&mut rng);
                let s_to = ScalarNonZero::random(&mut rng);
                let proof = VerifiableReshuffle2::new(&encrypted, &s_from, &s_to, &mut rng);
                let result = reshuffle2(&encrypted, &s_from, &s_to);
                let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
                let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
                (encrypted, result, proof, s_from_com, s_to_com)
            },
            |(encrypted, result, proof, s_from_com, s_to_com)| {
                proof.verify_reshuffle2(&encrypted, &result, &s_from_com, &s_to_com)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

// ---------------------------------------------------------------------------
// VRK2
// ---------------------------------------------------------------------------

#[cfg(feature = "verifiable")]
fn bench_verifiable_rekey2_create(c: &mut Criterion) {
    c.bench_function("verifiable_rekey2_create", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let k_from = ScalarNonZero::random(&mut rng);
                let k_to = ScalarNonZero::random(&mut rng);
                (encrypted, k_from, k_to, rng)
            },
            |(encrypted, k_from, k_to, mut rng)| {
                VerifiableRekey2::new(&encrypted, &k_from, &k_to, &mut rng)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_verifiable_rekey2_verify(c: &mut Criterion) {
    c.bench_function("verifiable_rekey2_verify", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let k_from = ScalarNonZero::random(&mut rng);
                let k_to = ScalarNonZero::random(&mut rng);
                let proof = VerifiableRekey2::new(&encrypted, &k_from, &k_to, &mut rng);
                let result = rekey2(&encrypted, &k_from, &k_to);
                let k_from_com = RekeyFactorCommitment::new(&k_from);
                let k_to_com = RekeyFactorCommitment::new(&k_to);
                (encrypted, result, proof, k_from_com, k_to_com)
            },
            |(encrypted, result, proof, k_from_com, k_to_com)| {
                proof.verify_rekey2(&encrypted, &result, &k_from_com, &k_to_com)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

// ---------------------------------------------------------------------------
// VRSK2
// ---------------------------------------------------------------------------

#[cfg(feature = "verifiable")]
fn bench_verifiable_rsk2_create(c: &mut Criterion) {
    c.bench_function("verifiable_rsk2_create", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let s_from = ScalarNonZero::random(&mut rng);
                let s_to = ScalarNonZero::random(&mut rng);
                let k_from = ScalarNonZero::random(&mut rng);
                let k_to = ScalarNonZero::random(&mut rng);
                (encrypted, s_from, s_to, k_from, k_to, rng)
            },
            |(encrypted, s_from, s_to, k_from, k_to, mut rng)| {
                VerifiableRSK2::new(&encrypted, &s_from, &s_to, &k_from, &k_to, &mut rng)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_verifiable_rsk2_verify(c: &mut Criterion) {
    c.bench_function("verifiable_rsk2_verify", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let s_from = ScalarNonZero::random(&mut rng);
                let s_to = ScalarNonZero::random(&mut rng);
                let k_from = ScalarNonZero::random(&mut rng);
                let k_to = ScalarNonZero::random(&mut rng);
                let proof =
                    VerifiableRSK2::new(&encrypted, &s_from, &s_to, &k_from, &k_to, &mut rng);
                let result = rsk2(&encrypted, &s_from, &s_to, &k_from, &k_to);
                let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
                let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
                let k_from_com = RekeyFactorCommitment::new(&k_from);
                let k_to_com = RekeyFactorCommitment::new(&k_to);
                (
                    encrypted, result, proof, s_from_com, s_to_com, k_from_com, k_to_com,
                )
            },
            |(encrypted, result, proof, s_from_com, s_to_com, k_from_com, k_to_com)| {
                proof.verify_rsk2(
                    &encrypted,
                    &result,
                    &s_from_com,
                    &s_to_com,
                    &k_from_com,
                    &k_to_com,
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

// ---------------------------------------------------------------------------
// VRRSK
// ---------------------------------------------------------------------------

#[cfg(feature = "verifiable")]
fn bench_verifiable_rrsk_create(c: &mut Criterion) {
    c.bench_function("verifiable_rrsk_create", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                let s = ScalarNonZero::random(&mut rng);
                let k = ScalarNonZero::random(&mut rng);
                (encrypted, pk, r, s, k, rng)
            },
            |(encrypted, pk, r, s, k, mut rng)| {
                VerifiableRRSK::new(&encrypted, &pk, &r, &s, &k, &mut rng)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_verifiable_rrsk_verify(c: &mut Criterion) {
    c.bench_function("verifiable_rrsk_verify", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                let s = ScalarNonZero::random(&mut rng);
                let k = ScalarNonZero::random(&mut rng);
                let proof = VerifiableRRSK::new(&encrypted, &pk, &r, &s, &k, &mut rng);
                let result = rrsk_primitive(&encrypted, &pk, &r, &s, &k);
                let rs = PseudonymizationFactorCommitment::new(&s);
                let rk = RekeyFactorCommitment::new(&k);
                (encrypted, pk, result, proof, rs, rk)
            },
            |(encrypted, pk, result, proof, rs, rk)| {
                proof.verify_rrsk(&encrypted, &result, &pk, &rs, &rk)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

// ---------------------------------------------------------------------------
// VRRSK2
// ---------------------------------------------------------------------------

#[cfg(feature = "verifiable")]
fn bench_verifiable_rrsk2_create(c: &mut Criterion) {
    c.bench_function("verifiable_rrsk2_create", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                let s_from = ScalarNonZero::random(&mut rng);
                let s_to = ScalarNonZero::random(&mut rng);
                let k_from = ScalarNonZero::random(&mut rng);
                let k_to = ScalarNonZero::random(&mut rng);
                (encrypted, pk, r, s_from, s_to, k_from, k_to, rng)
            },
            |(encrypted, pk, r, s_from, s_to, k_from, k_to, mut rng)| {
                VerifiableRRSK2::new(
                    &encrypted, &pk, &r, &s_from, &s_to, &k_from, &k_to, &mut rng,
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_verifiable_rrsk2_verify(c: &mut Criterion) {
    c.bench_function("verifiable_rrsk2_verify", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                let s_from = ScalarNonZero::random(&mut rng);
                let s_to = ScalarNonZero::random(&mut rng);
                let k_from = ScalarNonZero::random(&mut rng);
                let k_to = ScalarNonZero::random(&mut rng);
                let proof = VerifiableRRSK2::new(
                    &encrypted, &pk, &r, &s_from, &s_to, &k_from, &k_to, &mut rng,
                );
                let result = rrsk2_primitive(&encrypted, &pk, &r, &s_from, &s_to, &k_from, &k_to);
                let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
                let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
                let k_from_com = RekeyFactorCommitment::new(&k_from);
                let k_to_com = RekeyFactorCommitment::new(&k_to);
                (
                    encrypted, pk, result, proof, s_from_com, s_to_com, k_from_com, k_to_com,
                )
            },
            |(encrypted, pk, result, proof, s_from_com, s_to_com, k_from_com, k_to_com)| {
                proof.verify_rrsk2(
                    &encrypted,
                    &result,
                    &pk,
                    &s_from_com,
                    &s_to_com,
                    &k_from_com,
                    &k_to_com,
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

// ---------------------------------------------------------------------------
// VRR (insecure only — bare rerandomize is unbound to any factor, so it is
// only useful for testing in `insecure` builds).
// ---------------------------------------------------------------------------

#[cfg(all(feature = "verifiable", feature = "insecure"))]
fn bench_verifiable_rerandomize_create(c: &mut Criterion) {
    use libpep::core::verifiable::VerifiableRerandomize;
    c.bench_function("verifiable_rerandomize_create", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                (encrypted, pk, r, rng)
            },
            |(_encrypted, pk, r, mut rng)| VerifiableRerandomize::new(&pk, &r, &mut rng),
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(all(feature = "verifiable", feature = "insecure"))]
fn bench_verifiable_rerandomize_verify(c: &mut Criterion) {
    use libpep::core::primitives::rerandomize;
    use libpep::core::verifiable::VerifiableRerandomize;
    c.bench_function("verifiable_rerandomize_verify", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                let proof = VerifiableRerandomize::new(&pk, &r, &mut rng);
                #[cfg(feature = "elgamal3")]
                let result = rerandomize(&encrypted, &r);
                #[cfg(not(feature = "elgamal3"))]
                let result = rerandomize(&encrypted, &pk, &r);
                (encrypted, pk, result, proof)
            },
            |(encrypted, pk, result, proof)| proof.verify_rerandomized(&encrypted, &result, &pk),
            criterion::BatchSize::SmallInput,
        )
    });
}

// ---------------------------------------------------------------------------
// Non-verifiable baseline benchmarks
//
// Each verifiable operation has a non-verifiable counterpart (just the
// primitive, no proof generation/verification). These baselines use the same
// `setup_pk`/`encrypt` scaffold as the verifiable benches so the create-side
// numbers are directly comparable: a `baseline_rsk` run measures just the
// `rsk(...)` primitive call, whereas `verifiable_rsk_create` measures
// `VerifiableRSK::new(...)` which is the same primitive plus the proof.
// ---------------------------------------------------------------------------

#[cfg(feature = "verifiable")]
fn bench_baseline_reshuffle(c: &mut Criterion) {
    c.bench_function("baseline_reshuffle", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let s = ScalarNonZero::random(&mut rng);
                (encrypted, s)
            },
            |(encrypted, s)| reshuffle(&encrypted, &s),
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_baseline_rekey(c: &mut Criterion) {
    c.bench_function("baseline_rekey", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let k = ScalarNonZero::random(&mut rng);
                (encrypted, k)
            },
            |(encrypted, k)| rekey(&encrypted, &k),
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_baseline_rsk(c: &mut Criterion) {
    c.bench_function("baseline_rsk", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let s = ScalarNonZero::random(&mut rng);
                let k = ScalarNonZero::random(&mut rng);
                (encrypted, s, k)
            },
            |(encrypted, s, k)| rsk(&encrypted, &s, &k),
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_baseline_reshuffle2(c: &mut Criterion) {
    c.bench_function("baseline_reshuffle2", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let s_from = ScalarNonZero::random(&mut rng);
                let s_to = ScalarNonZero::random(&mut rng);
                (encrypted, s_from, s_to)
            },
            |(encrypted, s_from, s_to)| reshuffle2(&encrypted, &s_from, &s_to),
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_baseline_rekey2(c: &mut Criterion) {
    c.bench_function("baseline_rekey2", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let k_from = ScalarNonZero::random(&mut rng);
                let k_to = ScalarNonZero::random(&mut rng);
                (encrypted, k_from, k_to)
            },
            |(encrypted, k_from, k_to)| rekey2(&encrypted, &k_from, &k_to),
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_baseline_rsk2(c: &mut Criterion) {
    c.bench_function("baseline_rsk2", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
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

#[cfg(feature = "verifiable")]
fn bench_baseline_rrsk(c: &mut Criterion) {
    c.bench_function("baseline_rrsk", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                let s = ScalarNonZero::random(&mut rng);
                let k = ScalarNonZero::random(&mut rng);
                (encrypted, pk, r, s, k)
            },
            |(encrypted, pk, r, s, k)| rrsk_primitive(&encrypted, &pk, &r, &s, &k),
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "verifiable")]
fn bench_baseline_rrsk2(c: &mut Criterion) {
    c.bench_function("baseline_rrsk2", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                let s_from = ScalarNonZero::random(&mut rng);
                let s_to = ScalarNonZero::random(&mut rng);
                let k_from = ScalarNonZero::random(&mut rng);
                let k_to = ScalarNonZero::random(&mut rng);
                (encrypted, pk, r, s_from, s_to, k_from, k_to)
            },
            |(encrypted, pk, r, s_from, s_to, k_from, k_to)| {
                rrsk2_primitive(&encrypted, &pk, &r, &s_from, &s_to, &k_from, &k_to)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(all(feature = "verifiable", feature = "insecure"))]
fn bench_baseline_rerandomize(c: &mut Criterion) {
    use libpep::core::primitives::rerandomize;
    c.bench_function("baseline_rerandomize", |b| {
        b.iter_batched(
            || {
                let pk = setup_pk();
                let mut rng = rand::rng();
                let m = GroupElement::random(&mut rng);
                let encrypted = encrypt(&m, &pk, &mut rng);
                let r = ScalarNonZero::random(&mut rng);
                (encrypted, pk, r)
            },
            |(encrypted, _pk, r)| {
                #[cfg(feature = "elgamal3")]
                {
                    let _ = _pk;
                    rerandomize(&encrypted, &r)
                }
                #[cfg(not(feature = "elgamal3"))]
                {
                    rerandomize(&encrypted, &_pk, &r)
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(all(feature = "verifiable", feature = "insecure"))]
criterion_group!(
    benches,
    bench_baseline_reshuffle,
    bench_verifiable_reshuffle_create,
    bench_verifiable_reshuffle_verify,
    bench_baseline_rekey,
    bench_verifiable_rekey_create,
    bench_verifiable_rekey_verify,
    bench_baseline_rsk,
    bench_verifiable_rsk_create,
    bench_verifiable_rsk_verify,
    bench_baseline_reshuffle2,
    bench_verifiable_reshuffle2_create,
    bench_verifiable_reshuffle2_verify,
    bench_baseline_rekey2,
    bench_verifiable_rekey2_create,
    bench_verifiable_rekey2_verify,
    bench_baseline_rsk2,
    bench_verifiable_rsk2_create,
    bench_verifiable_rsk2_verify,
    bench_baseline_rrsk,
    bench_verifiable_rrsk_create,
    bench_verifiable_rrsk_verify,
    bench_baseline_rrsk2,
    bench_verifiable_rrsk2_create,
    bench_verifiable_rrsk2_verify,
    bench_baseline_rerandomize,
    bench_verifiable_rerandomize_create,
    bench_verifiable_rerandomize_verify,
);

#[cfg(all(feature = "verifiable", not(feature = "insecure")))]
criterion_group!(
    benches,
    bench_baseline_reshuffle,
    bench_verifiable_reshuffle_create,
    bench_verifiable_reshuffle_verify,
    bench_baseline_rekey,
    bench_verifiable_rekey_create,
    bench_verifiable_rekey_verify,
    bench_baseline_rsk,
    bench_verifiable_rsk_create,
    bench_verifiable_rsk_verify,
    bench_baseline_reshuffle2,
    bench_verifiable_reshuffle2_create,
    bench_verifiable_reshuffle2_verify,
    bench_baseline_rekey2,
    bench_verifiable_rekey2_create,
    bench_verifiable_rekey2_verify,
    bench_baseline_rsk2,
    bench_verifiable_rsk2_create,
    bench_verifiable_rsk2_verify,
    bench_baseline_rrsk,
    bench_verifiable_rrsk_create,
    bench_verifiable_rrsk_verify,
    bench_baseline_rrsk2,
    bench_verifiable_rrsk2_create,
    bench_verifiable_rrsk2_verify,
);

#[cfg(feature = "verifiable")]
criterion_main!(benches);

#[cfg(not(feature = "verifiable"))]
fn main() {
    eprintln!("verifiable benches require the `verifiable` feature");
}
