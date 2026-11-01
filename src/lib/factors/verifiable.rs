//! Factor derivation with Carter-Wegman universal hashing: the alternative to published factor
//! commitments, not the preferred scheme (see [Security](#security)).
//!
//! The commitments to the factors can be computed from the master public keys, so the
//! transcryptor does not publish a commitment per domain or session. The verifier computes them
//! from one pair of master public keys and the domain or session identifier.
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
//! The factors are not independent. One derived factor reveals
//! nothing about another, but `n + 1` of them (with `n` transcryptors) determine the master
//! secret and so every factor. Because the derivation is linear in the public hashes, the same
//! holds for the values the factors multiply: two pseudonyms of one subject in known domains
//! give that subject's pseudonym in every domain, and two session keys give every session key.
//! The commitment scheme of [`crate::factors::commitments`] with the default derivation has no
//! such structure and is the preferred scheme; choose this derivation only where commitment
//! storage is the binding constraint and that trade-off is acceptable.

use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::elgamal::arithmetic::ciphersuite::{
    Ciphersuite, ElementOf, ScalarCanBeZeroOf, ScalarOf,
};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::arithmetic::hashing::hash_to_nonzero_scalar_generic;
use crate::elgamal::arithmetic::Ristretto255Sha512;
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
pub struct MasterPseudonymizationSecret<C: Ciphersuite = Ristretto255Sha512> {
    pub(crate) x1: ScalarOf<C>,
    pub(crate) x2: ScalarOf<C>,
}

impl<C: Ciphersuite> std::fmt::Debug for MasterPseudonymizationSecret<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not leak secret scalars via Debug formatting (e.g. logs).
        f.write_str("MasterPseudonymizationSecret(…)")
    }
}

/// Master pseudonymization public key: `(X₁, X₂) = (x₁·G, x₂·G)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct MasterPseudonymizationPublicKey<C: Ciphersuite = Ristretto255Sha512> {
    /// `X₁ = x₁·G`.
    pub x1: ElementOf<C>,
    /// `X₂ = x₂·G`.
    pub x2: ElementOf<C>,
}

/// Master rekeying secret with two Carter-Wegman components.
#[derive(Clone, zeroize::Zeroize)]
#[zeroize(bound = "")]
pub struct MasterRekeyingSecret<C: Ciphersuite = Ristretto255Sha512> {
    pub(crate) y1: ScalarOf<C>,
    pub(crate) y2: ScalarOf<C>,
}

impl<C: Ciphersuite> std::fmt::Debug for MasterRekeyingSecret<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not leak secret scalars via Debug formatting (e.g. logs).
        f.write_str("MasterRekeyingSecret(…)")
    }
}

/// Master rekeying public key: `(Y₁, Y₂) = (y₁·G, y₂·G)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct MasterRekeyingPublicKey<C: Ciphersuite = Ristretto255Sha512> {
    /// `Y₁ = y₁·G`.
    pub y1: ElementOf<C>,
    /// `Y₂ = y₂·G`.
    pub y2: ElementOf<C>,
}

/// Combine `a*x + b*y` for non-zero scalars `a, x, b, y`. Returns the result
/// as `ScalarOf<C>` if non-zero. (With negligible probability over random
/// `x, y` the sum can be zero; the caller should treat that as a
/// configuration / key-generation error.)
fn cw_combine<C: Ciphersuite>(
    a: &ScalarOf<C>,
    x: &ScalarOf<C>,
    b: &ScalarOf<C>,
    y: &ScalarOf<C>,
) -> ScalarOf<C> {
    let sum = ScalarCanBeZeroOf::<C>::from(*a * *x) + ScalarCanBeZeroOf::<C>::from(*b * *y);
    ScalarOf::<C>::try_from(sum).unwrap_or_else(|_| {
        panic!("Carter-Wegman derived factor is zero — regenerate master secret")
    })
}

impl MasterPseudonymizationSecret {
    /// Generate a new random master pseudonymization secret, for ristretto255 with SHA-512.
    ///
    /// See [`random_generic`](MasterPseudonymizationSecret::random_generic) for another ciphersuite.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::random_generic(rng)
    }
}

impl<C: Ciphersuite> MasterPseudonymizationSecret<C> {
    /// Generate a new random master pseudonymization secret, for ciphersuite `C`.
    pub fn random_generic<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self {
            x1: C::Group::random_scalar(rng),
            x2: C::Group::random_scalar(rng),
        }
    }

    /// Derive the public key from this secret.
    pub fn public_key(&self) -> MasterPseudonymizationPublicKey<C> {
        MasterPseudonymizationPublicKey {
            x1: self.x1 * C::Group::generator(),
            x2: self.x2 * C::Group::generator(),
        }
    }

    /// Derive the reshuffle factor of a domain: `s_d = x₁ · H₁(d) + x₂ · H₂(d)`.
    pub fn derive_reshuffle_factor(
        &self,
        domain: &PseudonymizationDomain,
    ) -> ReshuffleFactor<C::Group> {
        ReshuffleFactor(derive::<C>(
            b"reshuffle",
            domain_payload(domain),
            &self.x1,
            &self.x2,
        ))
    }
}

impl MasterRekeyingSecret {
    /// Generate a new random master rekeying secret, for ristretto255 with SHA-512.
    ///
    /// See [`random_generic`](MasterRekeyingSecret::random_generic) for another ciphersuite.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::random_generic(rng)
    }
}

impl<C: Ciphersuite> MasterRekeyingSecret<C> {
    /// Generate a new random master rekeying secret, for ciphersuite `C`.
    pub fn random_generic<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self {
            y1: C::Group::random_scalar(rng),
            y2: C::Group::random_scalar(rng),
        }
    }

    /// Derive the public key from this secret.
    pub fn public_key(&self) -> MasterRekeyingPublicKey<C> {
        MasterRekeyingPublicKey {
            y1: self.y1 * C::Group::generator(),
            y2: self.y2 * C::Group::generator(),
        }
    }

    /// Derive the pseudonym rekey factor of a session: `k_s = y₁ · H₁(s) + y₂ · H₂(s)`.
    pub fn derive_pseudonym_rekey_factor(
        &self,
        context: &EncryptionContext,
    ) -> PseudonymRekeyFactor<C::Group> {
        PseudonymRekeyFactor(derive::<C>(
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
    ) -> AttributeRekeyFactor<C::Group> {
        AttributeRekeyFactor(derive::<C>(
            b"attribute_rekey",
            context_payload(context),
            &self.y1,
            &self.y2,
        ))
    }
}

impl<C: Ciphersuite> MasterPseudonymizationPublicKey<C> {
    /// Compute the commitment `S_d = s_d·G` to the reshuffle factor of a domain.
    pub fn compute_reshuffle_commitment(
        &self,
        domain: &PseudonymizationDomain,
    ) -> PseudonymizationFactorCommitment<C::Group> {
        PseudonymizationFactorCommitment(FactorCommitment(commit::<C>(
            b"reshuffle",
            domain_payload(domain),
            &self.x1,
            &self.x2,
        )))
    }
}

impl<C: Ciphersuite> MasterRekeyingPublicKey<C> {
    /// Compute the commitment `K_s = k_s·G` to the pseudonym rekey factor of a session.
    pub fn compute_pseudonym_rekey_commitment(
        &self,
        context: &EncryptionContext,
    ) -> RekeyFactorCommitment<C::Group> {
        RekeyFactorCommitment(FactorCommitment(commit::<C>(
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
    ) -> RekeyFactorCommitment<C::Group> {
        RekeyFactorCommitment(FactorCommitment(commit::<C>(
            b"attribute_rekey",
            context_payload(context),
            &self.y1,
            &self.y2,
        )))
    }
}

/// `a · H₁(id) + b · H₂(id)` under the label of the factor kind, or one for the global domain or
/// context.
fn derive<C: Ciphersuite>(
    label: &[u8],
    id: Option<&str>,
    a: &ScalarOf<C>,
    b: &ScalarOf<C>,
) -> ScalarOf<C> {
    match id {
        Some(id) => cw_combine::<C>(
            &hash_to_scalar_1::<C>(label, id.as_bytes()),
            a,
            &hash_to_scalar_2::<C>(label, id.as_bytes()),
            b,
        ),
        None => C::Group::scalar_one(),
    }
}

/// `H₁(id) · A + H₂(id) · B`, the commitment to [`derive`] from the public keys `A = a·G` and
/// `B = b·G`, or `G` for the global domain or context.
fn commit<C: Ciphersuite>(
    label: &[u8],
    id: Option<&str>,
    a: &ElementOf<C>,
    b: &ElementOf<C>,
) -> ElementOf<C> {
    match id {
        Some(id) => {
            hash_to_scalar_1::<C>(label, id.as_bytes()) * *a
                + hash_to_scalar_2::<C>(label, id.as_bytes()) * *b
        }
        None => C::Group::generator(),
    }
}

/// First hash-to-scalar function H₁.
pub(crate) fn hash_to_scalar_1<C: Ciphersuite>(typ: &[u8], input: &[u8]) -> ScalarOf<C> {
    hash_to_nonzero_scalar_generic::<C>(&[b"h1:", typ, b":", input])
}

/// Second hash-to-scalar function H₂.
pub(crate) fn hash_to_scalar_2<C: Ciphersuite>(typ: &[u8], input: &[u8]) -> ScalarOf<C> {
    hash_to_nonzero_scalar_generic::<C>(&[b"h2:", typ, b":", input])
}

impl<C: Ciphersuite> Drop for MasterPseudonymizationSecret<C> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl<C: Ciphersuite> Drop for MasterRekeyingSecret<C> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl<C: Ciphersuite> zeroize::ZeroizeOnDrop for MasterPseudonymizationSecret<C> {}
impl<C: Ciphersuite> zeroize::ZeroizeOnDrop for MasterRekeyingSecret<C> {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::contexts::{EncryptionContext, PseudonymizationDomain};
    use crate::elgamal::arithmetic::group_elements::G;
    use crate::elgamal::arithmetic::Ristretto255Sha512;
    use crate::factors::Factor;

    #[test]
    fn test_master_pseudonymization_key_derivation() {
        let mut rng = rand::rng();
        let secret = MasterPseudonymizationSecret::<Ristretto255Sha512>::random(&mut rng);
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
        let secret = MasterRekeyingSecret::<Ristretto255Sha512>::random(&mut rng);
        let public = secret.public_key();
        let context = EncryptionContext::from("test_session");
        let factor = secret.derive_pseudonym_rekey_factor(&context);
        let commitment = public.compute_pseudonym_rekey_commitment(&context);
        assert_eq!(commitment.point(), factor.scalar() * G);
    }

    #[test]
    fn test_hash_functions_independence() {
        let input = b"test_input";
        let h1 = hash_to_scalar_1::<Ristretto255Sha512>(b"type", input);
        let h2 = hash_to_scalar_2::<Ristretto255Sha512>(b"type", input);
        assert_ne!(h1, h2);
    }
}
