//! Verifiable factor derivation generic over the [`Group`].

use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::arithmetic::hashing::hash_to_nonzero_scalar;
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
#[derive(Clone)]
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

/// Master pseudonymization public key: `(X₁, X₂) = (x₁·G::generator(), x₂·G::generator())`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct MasterPseudonymizationPublicKey<G: Group> {
    /// `X₁ = x₁·G`.
    pub x1: G::Element,
    /// `X₂ = x₂·G`.
    pub x2: G::Element,
}

/// Master rekeying secret with two Carter-Wegman components.
#[derive(Clone)]
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

/// Master rekeying public key: `(Y₁, Y₂) = (y₁·G::generator(), y₂·G::generator())`.
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

    /// Derive a reshuffling factor for a specific domain:
    /// `s_d = x₁ · H₁(d) + x₂ · H₂(d)`.
    pub fn derive_reshuffle_factor(&self, domain: &PseudonymizationDomain) -> G::Scalar {
        match domain_payload(domain) {
            Some(payload) => {
                let h1 = hash_to_scalar_1::<G>(b"reshuffle", payload.as_bytes());
                let h2 = hash_to_scalar_2::<G>(b"reshuffle", payload.as_bytes());
                cw_combine::<G>(&h1, &self.x1, &h2, &self.x2)
            }
            None => G::scalar_one(),
        }
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

    /// Derive a pseudonym rekeying factor for a specific session:
    /// `k_s = y₁ · H₁(s) + y₂ · H₂(s)`.
    pub fn derive_pseudonym_rekey_factor(&self, context: &EncryptionContext) -> G::Scalar {
        match context_payload(context) {
            Some(payload) => {
                let h1 = hash_to_scalar_1::<G>(b"pseudonym_rekey", payload.as_bytes());
                let h2 = hash_to_scalar_2::<G>(b"pseudonym_rekey", payload.as_bytes());
                cw_combine::<G>(&h1, &self.y1, &h2, &self.y2)
            }
            None => G::scalar_one(),
        }
    }

    /// Derive an attribute rekeying factor for a specific session.
    pub fn derive_attribute_rekey_factor(&self, context: &EncryptionContext) -> G::Scalar {
        match context_payload(context) {
            Some(payload) => {
                let h1 = hash_to_scalar_1::<G>(b"attribute_rekey", payload.as_bytes());
                let h2 = hash_to_scalar_2::<G>(b"attribute_rekey", payload.as_bytes());
                cw_combine::<G>(&h1, &self.y1, &h2, &self.y2)
            }
            None => G::scalar_one(),
        }
    }
}

impl<G: Group> MasterPseudonymizationPublicKey<G> {
    /// Compute the reshuffle factor commitment `S_d = s_d·G` for a domain.
    pub fn compute_reshuffle_commitment(&self, domain: &PseudonymizationDomain) -> G::Element {
        match domain_payload(domain) {
            Some(payload) => {
                let h1 = hash_to_scalar_1::<G>(b"reshuffle", payload.as_bytes());
                let h2 = hash_to_scalar_2::<G>(b"reshuffle", payload.as_bytes());
                h1 * self.x1 + h2 * self.x2
            }
            None => G::generator(),
        }
    }
}

impl<G: Group> MasterRekeyingPublicKey<G> {
    /// Compute the pseudonym rekey factor commitment `K_s = k_s·G` for a
    /// session.
    pub fn compute_pseudonym_rekey_commitment(&self, context: &EncryptionContext) -> G::Element {
        match context_payload(context) {
            Some(payload) => {
                let h1 = hash_to_scalar_1::<G>(b"pseudonym_rekey", payload.as_bytes());
                let h2 = hash_to_scalar_2::<G>(b"pseudonym_rekey", payload.as_bytes());
                h1 * self.y1 + h2 * self.y2
            }
            None => G::generator(),
        }
    }

    /// Compute the attribute rekey factor commitment for a session.
    pub fn compute_attribute_rekey_commitment(&self, context: &EncryptionContext) -> G::Element {
        match context_payload(context) {
            Some(payload) => {
                let h1 = hash_to_scalar_1::<G>(b"attribute_rekey", payload.as_bytes());
                let h2 = hash_to_scalar_2::<G>(b"attribute_rekey", payload.as_bytes());
                h1 * self.y1 + h2 * self.y2
            }
            None => G::generator(),
        }
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
