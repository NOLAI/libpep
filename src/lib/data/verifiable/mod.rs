//! Verifiable data-layer types.
//!
//! Mirrors the structure of [`crate::data`]: per non-verifiable module
//! (`simple`, `long`, `records`, `json`) there is a matching verifiable
//! module here that contains the proof types and the verifiable-operation
//! impls. Verifier-side and prover-side traits live in [`traits`].

pub mod traits;

pub mod simple;

#[cfg(feature = "long")]
pub mod long;

pub mod records;

#[cfg(feature = "json")]
pub mod json;

/// Under `elgamal3` each ciphertext carries its own `gy`. Verifiable batch
/// proofs in this layer fold a single `gy` into their Fiat-Shamir transcript;
/// silently picking `gy = first.gy` would let an attacker mix ciphertexts
/// encrypted under different ephemeral keys into one batch and have only the
/// first item's rerandomization actually checked. This helper enforces that
/// all items share a `gy` and returns it, or `None` on mismatch (empty input
/// is also `None` — there is nothing to verify against).
#[cfg(feature = "elgamal3")]
#[inline]
pub(crate) fn shared_gy(
    originals: &[crate::core::elgamal::ElGamal],
) -> Option<crate::arithmetic::group_elements::GroupElement> {
    let first = originals.first()?;
    if originals.iter().all(|c| c.gy == first.gy) {
        Some(first.gy)
    } else {
        None
    }
}
