//! Benchmarks comparing the two proof encodings at batch sizes m = 1, 10 and 100.
//!
//! The paper's encoding ([`libpep::elgamal::zkps`]) proves one statement per ciphertext: a
//! batch of m needs m proofs of 128 bytes each. The RFC 9497 encoding
//! ([`libpep::elgamal::dleq`]) batches through `ComputeComposites`, so one 64-byte proof covers
//! the whole batch, at the cost of hashing each pair into the composite.
//!
//! Proof sizes are exact and reported by `dleq_proof_size`; the timings depend on the machine
//! and on what else is running on it.

#![allow(clippy::expect_used)]

#[cfg(feature = "verifiable")]
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
#[cfg(feature = "verifiable")]
use libpep::elgamal::arithmetic::group_elements::{GroupElement, G};
#[cfg(feature = "verifiable")]
use libpep::elgamal::arithmetic::scalars::ScalarNonZero;
#[cfg(feature = "verifiable")]
use libpep::elgamal::dleq;
#[cfg(feature = "verifiable")]
use libpep::elgamal::zkps;
#[cfg(feature = "verifiable")]
use libpep::protocol::Context;

#[cfg(feature = "verifiable")]
const SIZES: [usize; 3] = [1, 10, 100];

/// A secret scalar and m pairs `(C_i, D_i = k * C_i)`.
#[cfg(feature = "verifiable")]
fn setup(m: usize) -> (ScalarNonZero, Vec<GroupElement>, Vec<GroupElement>) {
    let rng = &mut rand::rng();
    let k = ScalarNonZero::random(rng);
    let cs: Vec<_> = (0..m).map(|_| GroupElement::random(rng)).collect();
    let ds: Vec<_> = cs.iter().map(|c| k * *c).collect();
    (k, cs, ds)
}

#[cfg(feature = "verifiable")]
fn bench_generate(c: &mut Criterion) {
    let ctx = Context::default();
    let mut group = c.benchmark_group("proof_generate");

    for m in SIZES {
        let (k, cs, ds) = setup(m);

        group.bench_with_input(BenchmarkId::new("rfc9497_batched", m), &m, |b, _| {
            let rng = &mut rand::rng();
            b.iter(|| {
                dleq::generate_proof(&k, &G, &(k * G), &cs, &ds, &ctx, rng)
                    .expect("well-formed lists")
            });
        });

        // The paper's encoding proves each pair separately.
        group.bench_with_input(BenchmarkId::new("paper_per_ciphertext", m), &m, |b, _| {
            let rng = &mut rand::rng();
            b.iter(|| {
                for c_i in &cs {
                    let _ = zkps::create_proof(&k, c_i, rng);
                }
            });
        });
    }
    group.finish();
}

#[cfg(feature = "verifiable")]
fn bench_verify(c: &mut Criterion) {
    let ctx = Context::default();
    let mut group = c.benchmark_group("proof_verify");

    for m in SIZES {
        let (k, cs, ds) = setup(m);
        let rng = &mut rand::rng();
        let batched =
            dleq::generate_proof(&k, &G, &(k * G), &cs, &ds, &ctx, rng).expect("well-formed lists");
        let per_ciphertext: Vec<_> = cs
            .iter()
            .map(|c_i| zkps::create_proof(&k, c_i, rng))
            .collect();

        group.bench_with_input(BenchmarkId::new("rfc9497_batched", m), &m, |b, _| {
            b.iter(|| dleq::verify_proof(&G, &(k * G), &cs, &ds, &batched, &ctx));
        });

        group.bench_with_input(BenchmarkId::new("paper_per_ciphertext", m), &m, |b, _| {
            b.iter(|| {
                for ((pk, proof), c_i) in per_ciphertext.iter().zip(cs.iter()) {
                    let _ = zkps::verify_proof(pk, c_i, proof);
                }
            });
        });
    }
    group.finish();
}

/// Reports the exact wire size of each encoding at every batch size.
///
/// Sizes are deterministic, so this is a measurement of the format rather than of the machine.
#[cfg(feature = "verifiable")]
fn bench_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_size_bytes");
    for m in SIZES {
        let batched = dleq::PROOF_SIZE;
        // The paper's proof carries three elements and a scalar, per ciphertext.
        let per_ciphertext = m * 128;
        println!(
            "m = {m:>3}: rfc9497 batched = {batched:>5} bytes, paper per-ciphertext = {per_ciphertext:>5} bytes"
        );
        group.bench_with_input(BenchmarkId::new("noop", m), &m, |b, _| b.iter(|| m));
    }
    group.finish();
}

#[cfg(feature = "verifiable")]
criterion_group!(benches, bench_generate, bench_verify, bench_proof_size);
#[cfg(feature = "verifiable")]
criterion_main!(benches);

#[cfg(not(feature = "verifiable"))]
fn main() {}
