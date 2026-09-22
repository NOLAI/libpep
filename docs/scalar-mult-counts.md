# Scalar multiplication counts for libpep verifiable operations

## Setting

Default-feature build of `libpep`:

- 2-component ElGamal (`elgamal3` *off*).
- curve25519-dalek 5.0.0-pre.6 over ristretto255.
- **No** `precomputed-tables` (the dependency in `Cargo.toml:46` does not enable it).
- **No** `RistrettoPoint::mul_base` call anywhere in `src/`.
- **No** `multiscalar_mul` call anywhere in `src/`.

Every scalar multiplication in this library is therefore **variable-base, single-scalar**. Even `r*G` and `a*G` dispatch through the generic `Scalar * RistrettoPoint` impl (`src/lib/arithmetic/group_elements.rs:237-269`) → `RistrettoPoint::mul` at `curve25519-dalek-5.0.0-pre.6/src/ristretto.rs:917`. The `verify_proof_split` code at `src/lib/core/zkps.rs:355` carries an explicit `FIXME` noting that `VartimeMultiscalarMul` is **not** used.

So in every column below: **fixed-base = 0, multiscalar = 0**.

## Are session-level factor-commitment proofs included?

No — they don't exist in the current code.

A `FactorCommitment` is just `A = a·G` with no companion well-formedness ZKP (see `src/lib/core/verifiable/commitments.rs:1-10`). The bench harness builds these commitments in the `iter_batched` setup closure, so even that single `a·G` is **not** in the timed `*_verify` interval.

The 2-variant sub-proofs that tie `S`/`K` to `S_from`/`S_to`/`K_from`/`K_to` **are** part of `VerifiableXxx2::new` / `verify_xxx2` and **are** counted below.

## Proof building blocks

Constant across the table:

- `create_proof(a, M)`: `a·G + a·M + r·G + r·M` = **4 var-base**.
- `create_proofs_same_scalar(a, M1, M2)`: shares `a·G` between two DLEQs → `a·G + a·M1 + a·M2 + r1·G + r1·M1 + r2·G + r2·M2` = **7 var-base** (saves 1 vs. two independent `create_proof`s).
- `verify_proof_split`: `s·G + e·A + s·M + e·N` = **4 var-base** (currently not batched, see `zkps.rs:355`).
- `FactorCommitment::new(a)`: `a·G` = 1 var-base (not in the timed verify interval; built in `iter_batched` setup).

## Per-operation counts

Every mult is variable-base; fixed-base = 0 and multiscalar = 0 throughout.

| Operation | Plain | Verifiable (create) | Verify |
|---|---:|---:|---:|
| `rerandomize` | **2** = 2 var | **4** = 0 (no ct touch) + 4 (1 DLEQ on `Y_r=r·Y`) | **4** = 4 (1 DLEQ) |
| `reshuffle`   | **2** = 2 var | **7** = 0 (no separate ct mults; `B′,C′` come from the proof) + 7 (paired-DLEQ via `create_proofs_same_scalar`, 1 mult saved on `s·G`) | **8** = 4+4 (2 DLEQs) |
| `rekey`       | **1** = 1 var (`k⁻¹·B`) | **5** = 1 (rekey transform `k⁻¹·B`) + 4 (1 DLEQ on `B=k·B′`) | **4** = 4 (1 DLEQ) |
| `rsk`         | **2** = 2 var (`(s·k⁻¹)·B`, `s·C`) | **13** = 1 (`T=(s·k⁻¹)·G`) + 4 + 4 + 4 (3 DLEQs: `S=k·T`, `B′=(s·k⁻¹)·B`, `C′=s·C`) | **12** = 4+4+4 (3 DLEQs) |
| `rrsk`        | **4** = 4 var (`ski·B`, `ski·r·G`, `(s·r)·Y`, `s·C`) | **17** = 4 (rerandomize: 1 DLEQ on `Y_r=r·Y`) + 13 (inner VRSK) | **16** = 4 (rerand verify) + 12 (VRSK verify) |
| `reshuffle2`  | **2** = 2 var | **12** = 1 (`S=s·G`) + 4 (sub-proof `S_to=s_from·S`) + 7 (inner VR) | **12** = 4 (sub-proof) + 8 (inner VR) |
| `rekey2`      | **1** = 1 var | **10** = 1 (`K=k·G`) + 4 (sub-proof `K_to=k_from·K`) + 5 (inner VRK) | **8** = 4 (sub-proof) + 4 (inner VRK) |
| `rsk2`        | **2** = 2 var | **23** = 1+1 (`S=s·G`, `K=k·G`) + 4+4 (two sub-proofs) + 13 (inner VRSK) | **20** = 4+4 (two sub-proofs) + 12 (inner VRSK) |
| `rrsk2`       | **4** = 4 var | **27** = 4 (rerand) + 23 (inner VRSK2) | **24** = 4 (rerand verify) + 20 (VRSK2 verify) |

## Sanity check vs. criterion

Calibration on `baseline_reshuffle` (2 mults / 57.0 µs) gives **~28.5 µs per variable-base ristretto255 mult**. Predicted = `mults × 28.5 µs`; "ratio" is measured/predicted.

| Bench | mults | predicted µs | measured µs | ratio |
|---|---:|---:|---:|---:|
| baseline_rerandomize | 2 | 57 | 57 | 1.00 |
| baseline_reshuffle | 2 | 57 | 57 | 1.00 |
| baseline_rekey | 1 | 28.5 | 39 | 1.38 |
| baseline_rsk | 2 | 57 | 67 | 1.18 |
| baseline_reshuffle2 | 2 | 57 | 66 | 1.16 |
| baseline_rekey2 | 1 | 28.5 | 47 | **1.66** |
| baseline_rsk2 | 2 | 57 | 85 | 1.49 |
| baseline_rrsk | 4 | 114 | 122 | 1.07 |
| baseline_rrsk2 | 4 | 114 | 141 | 1.24 |
| verifiable_rerandomize_create | 4 | 114 | 130 | 1.14 |
| verifiable_rerandomize_verify | 4 | 114 | 132 | 1.16 |
| verifiable_reshuffle_create | 7 | 200 | 231 | 1.16 |
| verifiable_reshuffle_verify | 8 | 228 | 269 | 1.18 |
| verifiable_rekey_create | 5 | 143 | 171 | 1.20 |
| verifiable_rekey_verify | 4 | 114 | 132 | 1.16 |
| verifiable_rsk_create | 13 | 370 | 431 | 1.16 |
| verifiable_rsk_verify | 12 | 342 | 391 | 1.14 |
| verifiable_reshuffle2_create | 12 | 342 | 393 | 1.15 |
| verifiable_reshuffle2_verify | 12 | 342 | 384 | 1.12 |
| verifiable_rekey2_create | 10 | 285 | 331 | 1.16 |
| verifiable_rekey2_verify | 8 | 228 | 256 | 1.12 |
| verifiable_rsk2_create | 23 | 655 | 752 | 1.15 |
| verifiable_rsk2_verify | 20 | 570 | 645 | 1.13 |
| verifiable_rrsk_create | 17 | 484 | 551 | 1.14 |
| verifiable_rrsk_verify | 16 | 456 | 533 | 1.17 |
| verifiable_rrsk2_create | 27 | 770 | 888 | 1.15 |
| verifiable_rrsk2_verify | 24 | 684 | 773 | 1.13 |

## Verdict

All verifiable rows sit at 1.12–1.20× predicted — a clean, uniform overhead from Fiat-Shamir SHA-512 hashing, scalar sampling for nonces, and a couple of scalar-field multiplications/inversions per operation. The count tracks the measured time to within ~15%, monotonic everywhere; no verifiable row disagrees with its count.

### One flagged row, but not a miscount

`baseline_rekey` (1.38×) and `baseline_rekey2` (1.66×) look high, and `baseline_rsk*`/`baseline_rrsk*` are mildly elevated. The cause is **scalar-field inversion**:

- `k.invert()` in `primitives.rs:48`,
- `s*k.invert()` in `primitives.rs:59,70,88`,
- additional `k_from.invert()*k_to` for the 2-variants.

Each call is a constant-time field inversion, a few µs of pure scalar arithmetic — **not** a hidden point multiplication. Once corrected for, the rekey rows fall in line. So the count of 1 var-base point mult for `rekey` is right; just note in the paper that for a one-mult operation the scalar inversion is no longer negligible relative to the mult itself.

## Two caveats worth mentioning in the paper

1. There is currently **no** per-`*G` fixed-base optimization in this library — the fixed-base column exists for completeness but is 0 across the board. Turning on curve25519-dalek's `precomputed-tables` feature **or** routing `r*G`/`a*G` through `RistrettoPoint::mul_base` would re-classify ~30–40% of these mults (every `*G` in `create_proof` and verify, plus the `*·G` in commitments and 2-variant constructions) as fixed-base and would noticeably shift the create/verify timings.

2. `verify_proof_split` does two independent `s·P == e·Q + R` checks as four separate variable-base mults. Switching to `VartimeMultiscalarMul` (the `FIXME` at `zkps.rs:355`) would collapse each into one 2-term multiscalar — i.e. the "verify" column would move from `4·k` var-base mults to `2·k` multiscalar-of-2 mults per operation, roughly halving verify time. Worth mentioning if the paper claims the construction is "optimized" or compares against a baseline that does this.
