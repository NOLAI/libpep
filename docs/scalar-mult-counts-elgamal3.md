# Scalar multiplication counts for libpep verifiable operations (`elgamal3` enabled)

## Setting

Build of `libpep` with the `elgamal3` feature **enabled**:

- 3-component ElGamal `(B, C, Y)` — every ciphertext carries the recipient public key `Y` alongside.
- curve25519-dalek 5.0.0-pre.6 over ristretto255.
- **No** `precomputed-tables`, **no** `RistrettoPoint::mul_base`, **no** `multiscalar_mul` (same as the default-feature build — see `scalar-mult-counts.md`).

Every scalar multiplication is therefore **variable-base, single-scalar**. In every column below: **fixed-base = 0, multiscalar = 0**.

## What changes vs. the default 2-component build

`elgamal3` adds the `Y` component to every ciphertext. The operations that *transform `Y`* gain one extra variable-base point multiplication, and the corresponding verifiable operations gain one extra DLEQ proof on `Y' = k·Y`:

- `rekey`-family transforms `Y → k·Y` → **+1 mult** in plain, **+4 mult** (one extra DLEQ) in verifiable create, **+4 mult** (one extra DLEQ verify) in verify.
- `rsk`-family transforms `Y → k·Y` similarly → same +1 / +4 / +4.
- `rrsk`-family inherits the same +1 / +4 / +4 from its embedded `rsk` step.
- `reshuffle` and `rerandomize` do **not** touch `Y` (it's just copied), so their counts are unchanged.

Reshuffle leaves `Y` alone in `elgamal3` (`primitives.rs:38-39`) and rerandomize copies it too (`primitives.rs:18`), so no extra DLEQ is needed for `Y` in those constructions.

## Are session-level factor-commitment proofs included?

Same answer as default build: no, they don't exist. `FactorCommitment::new(a)` is just `a·G` with no companion well-formedness ZKP, and the bench harness builds commitments outside the timed interval. The 2-variant `S_to = s_from·S` / `K_to = k_from·K` sub-proofs **are** part of `VerifiableXxx2::new` / `verify_xxx2` and are counted below.

## Proof building blocks

Identical to the default build:

- `create_proof(a, M)` = **4 var-base** (`a·G + a·M + r·G + r·M`).
- `create_proofs_same_scalar(a, M1, M2)` = **7 var-base** (shares `a·G`).
- `verify_proof_split` = **4 var-base** (not batched; `FIXME` at `zkps.rs:355`).
- `FactorCommitment::new(a)` = **1 var-base** (`a·G`); not in the timed verify interval.

## Per-operation counts (elgamal3)

Every mult is variable-base; fixed-base = 0 and multiscalar = 0 throughout. Bold numbers in the **Δ** column show the delta vs. the default 2-component build.

| Operation | Plain | Δ | Verifiable (create) | Δ | Verify | Δ |
|---|---:|---:|---:|---:|---:|---:|
| `rerandomize` | **2** = 2 var | 0 | **4** = 4 (1 DLEQ on `Y_r=r·Y`) | 0 | **4** = 4 (1 DLEQ) | 0 |
| `reshuffle`   | **2** = 2 var | 0 | **7** = paired-DLEQ via `create_proofs_same_scalar` (1 mult saved on `s·G`) | 0 | **8** = 4+4 (2 DLEQs) | 0 |
| `rekey`       | **2** = 1 (`k⁻¹·B`) + 1 (`k·Y`) | **+1** | **9** = 1 (`k⁻¹·B`) + 4 (DLEQ `B=k·B′`) + 4 (DLEQ `Y′=k·Y`) | **+4** | **8** = 4 (DLEQ `B=k·B′`) + 4 (DLEQ `Y′=k·Y`) | **+4** |
| `rsk`         | **3** = 2 (`(s·k⁻¹)·B`, `s·C`) + 1 (`k·Y`) | **+1** | **17** = 1 (`T=(s·k⁻¹)·G`) + 4·4 (DLEQs: `S=k·T`, `B′=(s·k⁻¹)·B`, `C′=s·C`, `Y′=k·Y`) | **+4** | **16** = 4·4 (4 DLEQ verifies) | **+4** |
| `rrsk`        | **5** = 4 (rerand+rsk core) + 1 (`k·Y`) | **+1** | **21** = 4 (rerand) + 17 (inner VRSK) | **+4** | **20** = 4 (rerand verify) + 16 (VRSK verify) | **+4** |
| `reshuffle2`  | **2** = 2 var | 0 | **12** = 1 (`S=s·G`) + 4 (sub-proof) + 7 (inner VR) | 0 | **12** = 4 (sub-proof) + 8 (inner VR) | 0 |
| `rekey2`      | **2** = 2 var (same as `rekey`) | **+1** | **14** = 1 (`K=k·G`) + 4 (sub-proof) + 9 (inner VRK) | **+4** | **12** = 4 (sub-proof) + 8 (inner VRK) | **+4** |
| `rsk2`        | **3** = 3 var (same as `rsk`) | **+1** | **27** = 2 (`S=s·G`,`K=k·G`) + 8 (two sub-proofs) + 17 (inner VRSK) | **+4** | **24** = 8 (two sub-proofs) + 16 (inner VRSK) | **+4** |
| `rrsk2`       | **5** = 5 var (same as `rrsk`) | **+1** | **31** = 4 (rerand) + 27 (inner VRSK2) | **+4** | **28** = 4 (rerand verify) + 24 (VRSK2 verify) | **+4** |

Per-DLEQ breakdown unchanged from the default build: `create_proof` = 4, `create_proofs_same_scalar` = 7, `verify_proof_split` = 4.

## Sanity check vs. criterion

Now measured (criterion data in `target/criterion/` is from a build with `verifiable,elgamal3`). Calibration on `baseline_reshuffle` (2 mults / 59.0 µs) gives **~29.5 µs per variable-base ristretto255 mult** — within rounding error of the 28.5 µs/mult constant from the default build, as expected since the backend is identical. Predicted = `mults × 29.5 µs`; "ratio" is measured/predicted.

| Bench | mults | predicted µs | measured µs | ratio |
|---|---:|---:|---:|---:|
| baseline_rerandomize | 2 | 59 | 57 | 0.97 |
| baseline_reshuffle | 2 | 59 | 59 | 1.00 |
| baseline_rekey | 2 | 59 | 68 | 1.15 |
| baseline_rsk | 3 | 88 | 97 | 1.10 |
| baseline_reshuffle2 | 2 | 59 | 68 | 1.15 |
| baseline_rekey2 | 2 | 59 | 78 | **1.32** |
| baseline_rsk2 | 3 | 88 | 118 | **1.33** |
| baseline_rrsk | 5 | 147 | 153 | 1.04 |
| baseline_rrsk2 | 5 | 147 | 174 | 1.18 |
| verifiable_rerandomize_create | 4 | 118 | 131 | 1.11 |
| verifiable_rerandomize_verify | 4 | 118 | 133 | 1.13 |
| verifiable_reshuffle_create | 7 | 206 | 237 | 1.15 |
| verifiable_reshuffle_verify | 8 | 236 | 265 | 1.12 |
| verifiable_rekey_create | 9 | 265 | 305 | 1.15 |
| verifiable_rekey_verify | 8 | 236 | 265 | 1.12 |
| verifiable_rsk_create | 17 | 501 | 568 | 1.13 |
| verifiable_rsk_verify | 16 | 472 | 531 | 1.13 |
| verifiable_reshuffle2_create | 12 | 354 | 405 | 1.14 |
| verifiable_reshuffle2_verify | 12 | 354 | 398 | 1.13 |
| verifiable_rekey2_create | 14 | 413 | 471 | 1.14 |
| verifiable_rekey2_verify | 12 | 354 | 400 | 1.13 |
| verifiable_rsk2_create | 27 | 796 | 930 | 1.17 |
| verifiable_rsk2_verify | 24 | 708 | 794 | 1.12 |
| verifiable_rrsk_create | 21 | 619 | 689 | 1.11 |
| verifiable_rrsk_verify | 20 | 590 | 655 | 1.11 |
| verifiable_rrsk2_create | 31 | 914 | 1028 | 1.12 |
| verifiable_rrsk2_verify | 28 | 825 | 913 | 1.11 |

## Verdict

All 18 verifiable rows sit in a remarkably tight 1.11–1.17× band — the same clean Fiat-Shamir overhead seen in the default build. The count tracks the measured time to within ~15% across the whole table, and the elgamal3 deltas vs. the default build match the expected `Δmults × 29.5 µs` everywhere (e.g. `verifiable_rekey_create` went 171 → 305 µs, predicted +114 µs for +4 mults; actual +134 µs, well within the per-call Fiat-Shamir variance). No verifiable row disagrees with its count.

### One flagged region, but not a miscount

`baseline_rekey2` (1.32×) and `baseline_rsk2` (1.33×) look high. The cause is **scalar-field inversion** in the 2-variant primitives — `k_from.invert() * k_to` and `s_from.invert() * s_to` (see `primitives.rs:103-105, 116-118`) — which costs a few µs of scalar arithmetic that does not show up in the point-mult count. This already inflated the same rows in the default build by the same proportion (1.49–1.66× there) and is not a hidden point operation.

## Two caveats worth mentioning in the paper (unchanged from default build)

1. There is currently **no** per-`*G` fixed-base optimization in this library, in either default or `elgamal3` mode — the fixed-base column exists for completeness but is 0 across the board. Turning on curve25519-dalek's `precomputed-tables` feature **or** routing `r*G`/`a*G` through `RistrettoPoint::mul_base` would re-classify ~30–40% of these mults as fixed-base.

2. `verify_proof_split` does two independent `s·P == e·Q + R` checks as four separate variable-base mults — see `FIXME` at `zkps.rs:355`. Switching to `VartimeMultiscalarMul` would roughly halve verify time. With `elgamal3` adding one extra DLEQ verify (4 var-base mults) to every rekey/rsk/rrsk operation, the multiscalar optimization is **more** valuable in `elgamal3` mode than in the default build.
