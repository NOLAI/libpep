//! Verifiable data-layer types.
//!
//! Mirrors the structure of [`crate::data`]: per data module (`simple`, `long`, `records`,
//! `json`) there is a matching module here with the proof types and the verifiable operations,
//! generic over the group in a `generic` submodule. The prover-side and verifier-side traits
//! live in [`traits`], and [`batch`] holds the batch proofs, which are generic over the item
//! type.

pub mod traits;

/// The public key carried by every one of `ciphertexts`, which a proof over all of them folds
/// into its transcript, or `None` if they carry different keys. Picking the first one's key
/// would let a prover mix ciphertexts under different keys and have only the first one
/// checked. Without ciphertexts there is no key to bind, and the generator stands in.
#[cfg(feature = "elgamal3")]
pub(crate) fn common_gy<G: crate::elgamal::arithmetic::group::Group>(
    ciphertexts: &[crate::elgamal::generic::ElGamal<G>],
) -> Option<G::Element> {
    let Some(first) = ciphertexts.first() else {
        return Some(G::generator());
    };
    ciphertexts
        .iter()
        .all(|c| c.gy == first.gy)
        .then_some(first.gy)
}

#[cfg(feature = "batch")]
pub mod batch;

pub mod simple;

#[cfg(feature = "long")]
pub mod long;

pub mod records;

#[cfg(feature = "json")]
pub mod json;
