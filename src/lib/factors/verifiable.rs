//! Verifiable factor derivation using Carter-Wegman universal hashing: the alternative of
//! Section 3.3.1 of the paper, not the preferred scheme (see [Security](#security)).
//!
//! Factor commitments are publicly computable from master public keys, so
//! the transcryptor does not need to publish a per-domain / per-session
//! commitment for every factor it uses. The verifier reconstructs them
//! from a single master public-key pair plus the domain / session identifier.
//!
//! # Construction
//!
//! For a domain `d`, the reshuffling factor is derived as:
//! ```text
//! s_d = x₁ · H₁(d) + x₂ · H₂(d)
//! ```
//! and its forward commitment as:
//! ```text
//! S_d = s_d · G = H₁(d) · X₁ + H₂(d) · X₂
//! ```
//! where `X₁ = x₁·G` and `X₂ = x₂·G` are the master public keys.
//!
//! # Security
//!
//! Section 3.3.1 of the paper: the factors are not independent. One derived factor reveals
//! nothing about another, but `n + 1` of them (with `n` transcryptors) determine the master
//! secret and so every factor. Because the derivation is linear in the public hashes, the same
//! holds for the values the factors multiply: two pseudonyms of one subject in known domains
//! give that subject's pseudonym in every domain, and two session keys give every session key.
//! The commitment scheme of [`crate::factors::commitments`] with the default derivation has no
//! such structure and is the preferred scheme; choose this derivation only where commitment
//! storage is the binding constraint and that trade-off is acceptable.
//!
//! The types are generic over the [`Group`].

use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::arithmetic::hashing::hash_to_nonzero_scalar;
use crate::elgamal::verifiable::{
    FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment,
};
use crate::factors::types::{AttributeRekeyFactor, PseudonymRekeyFactor, ReshuffleFactor};
use rand_core::{CryptoRng, Rng};

/// Extract the payload of a pseudonymization domain, returning `None` for the
/// `Global` variant (under `global-pseudonyms` it produces a unit factor).
fn domain_payload(domain: &PseudonymizationDomain) -> Option<&str> {
    match domain {
        #[cfg(feature = "legacy")]
        PseudonymizationDomain::Specific { payload, .. } => Some(payload.as_str()),
        #[cfg(not(feature = "legacy"))]
        PseudonymizationDomain::Specific(payload) => Some(payload.as_str()),
        #[cfg(feature = "global-pseudonyms")]
        PseudonymizationDomain::Global => None,
    }
}

/// Extract the payload of an encryption context, returning `None` for the
/// `Global` variant (under `offline` it produces a unit factor).
fn context_payload(context: &EncryptionContext) -> Option<&str> {
    match context {
        #[cfg(feature = "legacy")]
        EncryptionContext::Specific { payload, .. } => Some(payload.as_str()),
        #[cfg(not(feature = "legacy"))]
        EncryptionContext::Specific(payload) => Some(payload.as_str()),
        #[cfg(feature = "offline")]
        EncryptionContext::Global => None,
    }
}

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Master pseudonymization secret with two Carter-Wegman components.
#[derive(Clone, zeroize::Zeroize)]
#[zeroize(bound = "")]
pub struct MasterPseudonymizationSecret<G: Group> {
    pub(crate) x1: G::Scalar,
    pub(crate) x2: G::Scalar,
}

impl<G: Group> std::fmt::Debug for MasterPseudonymizationSecret<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not leak secret scalars via Debug formatting (e.g. logs).
        f.write_str("MasterPseudonymizationSecret(…)")
    }
}

/// Master pseudonymization public key: `(X₁, X₂) = (x₁·G, x₂·G)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct MasterPseudonymizationPublicKey<G: Group> {
    /// `X₁ = x₁·G`.
    pub x1: G::Element,
    /// `X₂ = x₂·G`.
    pub x2: G::Element,
}

/// Master rekeying secret with two Carter-Wegman components.
#[derive(Clone, zeroize::Zeroize)]
#[zeroize(bound = "")]
pub struct MasterRekeyingSecret<G: Group> {
    pub(crate) y1: G::Scalar,
    pub(crate) y2: G::Scalar,
}

impl<G: Group> std::fmt::Debug for MasterRekeyingSecret<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not leak secret scalars via Debug formatting (e.g. logs).
        f.write_str("MasterRekeyingSecret(…)")
    }
}

/// Master rekeying public key: `(Y₁, Y₂) = (y₁·G, y₂·G)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct MasterRekeyingPublicKey<G: Group> {
    /// `Y₁ = y₁·G`.
    pub y1: G::Element,
    /// `Y₂ = y₂·G`.
    pub y2: G::Element,
}

/// Combine `a*x + b*y` for non-zero scalars `a, x, b, y`. Returns the result
/// as `G::Scalar` if non-zero. (With negligible probability over random
/// `x, y` the sum can be zero; the caller should treat that as a
/// configuration / key-generation error.)
fn cw_combine<G: Group>(a: &G::Scalar, x: &G::Scalar, b: &G::Scalar, y: &G::Scalar) -> G::Scalar {
    let sum = G::ScalarCanBeZero::from(*a * *x) + G::ScalarCanBeZero::from(*b * *y);
    G::Scalar::try_from(sum).unwrap_or_else(|_| {
        panic!("Carter-Wegman derived factor is zero — regenerate master secret")
    })
}

impl<G: Group> MasterPseudonymizationSecret<G> {
    /// Generate a new random master pseudonymization secret.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self {
            x1: G::random_scalar(rng),
            x2: G::random_scalar(rng),
        }
    }

    /// Derive the public key from this secret.
    pub fn public_key(&self) -> MasterPseudonymizationPublicKey<G> {
        MasterPseudonymizationPublicKey {
            x1: self.x1 * G::generator(),
            x2: self.x2 * G::generator(),
        }
    }

    /// Derive the reshuffle factor of a domain: `s_d = x₁ · H₁(d) + x₂ · H₂(d)`.
    pub fn derive_reshuffle_factor(&self, domain: &PseudonymizationDomain) -> ReshuffleFactor<G> {
        ReshuffleFactor(derive::<G>(
            b"reshuffle",
            domain_payload(domain),
            &self.x1,
            &self.x2,
        ))
    }
}

impl<G: Group> MasterRekeyingSecret<G> {
    /// Generate a new random master rekeying secret.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self {
            y1: G::random_scalar(rng),
            y2: G::random_scalar(rng),
        }
    }

    /// Derive the public key from this secret.
    pub fn public_key(&self) -> MasterRekeyingPublicKey<G> {
        MasterRekeyingPublicKey {
            y1: self.y1 * G::generator(),
            y2: self.y2 * G::generator(),
        }
    }

    /// Derive the pseudonym rekey factor of a session: `k_s = y₁ · H₁(s) + y₂ · H₂(s)`.
    pub fn derive_pseudonym_rekey_factor(
        &self,
        context: &EncryptionContext,
    ) -> PseudonymRekeyFactor<G> {
        PseudonymRekeyFactor(derive::<G>(
            b"pseudonym_rekey",
            context_payload(context),
            &self.y1,
            &self.y2,
        ))
    }

    /// Derive the attribute rekey factor of a session.
    pub fn derive_attribute_rekey_factor(
        &self,
        context: &EncryptionContext,
    ) -> AttributeRekeyFactor<G> {
        AttributeRekeyFactor(derive::<G>(
            b"attribute_rekey",
            context_payload(context),
            &self.y1,
            &self.y2,
        ))
    }
}

impl<G: Group> MasterPseudonymizationPublicKey<G> {
    /// Compute the commitment `S_d = s_d·G` to the reshuffle factor of a domain.
    pub fn compute_reshuffle_commitment(
        &self,
        domain: &PseudonymizationDomain,
    ) -> PseudonymizationFactorCommitment<G> {
        PseudonymizationFactorCommitment(FactorCommitment(commit::<G>(
            b"reshuffle",
            domain_payload(domain),
            &self.x1,
            &self.x2,
        )))
    }
}

impl<G: Group> MasterRekeyingPublicKey<G> {
    /// Compute the commitment `K_s = k_s·G` to the pseudonym rekey factor of a session.
    pub fn compute_pseudonym_rekey_commitment(
        &self,
        context: &EncryptionContext,
    ) -> RekeyFactorCommitment<G> {
        RekeyFactorCommitment(FactorCommitment(commit::<G>(
            b"pseudonym_rekey",
            context_payload(context),
            &self.y1,
            &self.y2,
        )))
    }

    /// Compute the commitment to the attribute rekey factor of a session.
    pub fn compute_attribute_rekey_commitment(
        &self,
        context: &EncryptionContext,
    ) -> RekeyFactorCommitment<G> {
        RekeyFactorCommitment(FactorCommitment(commit::<G>(
            b"attribute_rekey",
            context_payload(context),
            &self.y1,
            &self.y2,
        )))
    }
}

/// `a · H₁(id) + b · H₂(id)` under the label of the factor kind, or one for the global domain or
/// context.
fn derive<G: Group>(label: &[u8], id: Option<&str>, a: &G::Scalar, b: &G::Scalar) -> G::Scalar {
    match id {
        Some(id) => cw_combine::<G>(
            &hash_to_scalar_1::<G>(label, id.as_bytes()),
            a,
            &hash_to_scalar_2::<G>(label, id.as_bytes()),
            b,
        ),
        None => G::scalar_one(),
    }
}

/// `H₁(id) · A + H₂(id) · B`, the commitment to [`derive`] from the public keys `A = a·G` and
/// `B = b·G`, or `G` for the global domain or context.
fn commit<G: Group>(label: &[u8], id: Option<&str>, a: &G::Element, b: &G::Element) -> G::Element {
    match id {
        Some(id) => {
            hash_to_scalar_1::<G>(label, id.as_bytes()) * *a
                + hash_to_scalar_2::<G>(label, id.as_bytes()) * *b
        }
        None => G::generator(),
    }
}

/// First hash-to-scalar function H₁.
pub(crate) fn hash_to_scalar_1<G: Group>(typ: &[u8], input: &[u8]) -> G::Scalar {
    hash_to_nonzero_scalar::<G>(&[b"h1:", typ, b":", input])
}

/// Second hash-to-scalar function H₂.
pub(crate) fn hash_to_scalar_2<G: Group>(typ: &[u8], input: &[u8]) -> G::Scalar {
    hash_to_nonzero_scalar::<G>(&[b"h2:", typ, b":", input])
}

impl<G: Group> Drop for MasterPseudonymizationSecret<G> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl<G: Group> Drop for MasterRekeyingSecret<G> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl<G: Group> zeroize::ZeroizeOnDrop for MasterPseudonymizationSecret<G> {}
impl<G: Group> zeroize::ZeroizeOnDrop for MasterRekeyingSecret<G> {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::contexts::{EncryptionContext, PseudonymizationDomain};
    use crate::elgamal::arithmetic::group_elements::G;
    use crate::elgamal::arithmetic::Ristretto255;
    use crate::factors::Factor;

    #[test]
    fn test_master_pseudonymization_key_derivation() {
        let mut rng = rand::rng();
        let secret = MasterPseudonymizationSecret::<Ristretto255>::random(&mut rng);
        let public = secret.public_key();
        let domain = PseudonymizationDomain::from("test_domain");
        let factor = secret.derive_reshuffle_factor(&domain);
        let commitment = public.compute_reshuffle_commitment(&domain);
        // The commitment computed from the public key must equal s_d·G.
        assert_eq!(commitment.point(), factor.scalar() * G);
    }

    #[test]
    fn test_master_rekeying_key_derivation() {
        let mut rng = rand::rng();
        let secret = MasterRekeyingSecret::<Ristretto255>::random(&mut rng);
        let public = secret.public_key();
        let context = EncryptionContext::from("test_session");
        let factor = secret.derive_pseudonym_rekey_factor(&context);
        let commitment = public.compute_pseudonym_rekey_commitment(&context);
        assert_eq!(commitment.point(), factor.scalar() * G);
    }

    #[test]
    fn test_hash_functions_independence() {
        let input = b"test_input";
        let h1 = hash_to_scalar_1::<Ristretto255>(b"type", input);
        let h2 = hash_to_scalar_2::<Ristretto255>(b"type", input);
        assert_ne!(h1, h2);
    }
}
