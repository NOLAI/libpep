//! Helpers shared by the batch and long verifiable proofs.

#[cfg(all(feature = "elgamal3", any(feature = "batch", feature = "long")))]
use crate::elgamal::arithmetic::group::Group;
#[cfg(all(feature = "elgamal3", any(feature = "batch", feature = "long")))]
use crate::elgamal::ElGamal;

/// The public key carried by every one of `ciphertexts`, which a proof over all of them folds
/// into its transcript, or `None` if they carry different keys. Picking the first one's key
/// would let a prover mix ciphertexts under different keys and have only the first one
/// checked. Without ciphertexts there is no key to bind, and the generator stands in.
#[cfg(all(feature = "elgamal3", any(feature = "batch", feature = "long")))]
pub(crate) fn common_gy<G: Group>(ciphertexts: &[ElGamal<G>]) -> Option<G::Element> {
    let Some(first) = ciphertexts.first() else {
        return Some(G::generator());
    };
    ciphertexts
        .iter()
        .all(|c| c.gy == first.gy)
        .then_some(first.gy)
}
