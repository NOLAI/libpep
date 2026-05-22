//! Verifiable factor derivation using Carter-Wegman universal hashing.
//!
//! Factor commitments are publicly computable from master public keys, so
//! the transcryptor does not need to publish a per-domain / per-session
//! commitment for every factor it uses — the verifier reconstructs them
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

use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::{ScalarCanBeZero, ScalarNonZero};
use crate::factors::contexts::{EncryptionContext, PseudonymizationDomain};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

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
#[derive(Clone, Debug)]
pub struct MasterPseudonymizationSecret {
    pub(crate) x1: ScalarNonZero,
    pub(crate) x2: ScalarNonZero,
}

/// Master pseudonymization public key: `(X₁, X₂) = (x₁·G, x₂·G)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasterPseudonymizationPublicKey {
    pub x1: GroupElement,
    pub x2: GroupElement,
}

/// Master rekeying secret with two Carter-Wegman components.
#[derive(Clone, Debug)]
pub struct MasterRekeyingSecret {
    pub(crate) y1: ScalarNonZero,
    pub(crate) y2: ScalarNonZero,
}

/// Master rekeying public key: `(Y₁, Y₂) = (y₁·G, y₂·G)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasterRekeyingPublicKey {
    pub y1: GroupElement,
    pub y2: GroupElement,
}

/// Combine `a*x + b*y` for non-zero scalars `a, x, b, y`. Returns the result
/// as `ScalarNonZero` if non-zero. (With negligible probability over random
/// `x, y` the sum can be zero; the caller should treat that as a
/// configuration / key-generation error.)
fn cw_combine(
    a: &ScalarNonZero,
    x: &ScalarNonZero,
    b: &ScalarNonZero,
    y: &ScalarNonZero,
) -> ScalarNonZero {
    let lhs = ScalarCanBeZero::from(a * x);
    let rhs = ScalarCanBeZero::from(b * y);
    let sum = lhs + rhs;
    ScalarNonZero::try_from(sum).unwrap_or_else(|_| {
        panic!("Carter-Wegman derived factor is zero — regenerate master secret")
    })
}

impl MasterPseudonymizationSecret {
    /// Generate a new random master pseudonymization secret.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            x1: ScalarNonZero::random(rng),
            x2: ScalarNonZero::random(rng),
        }
    }

    /// Derive the public key from this secret.
    pub fn public_key(&self) -> MasterPseudonymizationPublicKey {
        MasterPseudonymizationPublicKey {
            x1: self.x1 * G,
            x2: self.x2 * G,
        }
    }

    /// Derive a reshuffling factor for a specific domain:
    /// `s_d = x₁ · H₁(d) + x₂ · H₂(d)`.
    pub fn derive_reshuffle_factor(&self, domain: &PseudonymizationDomain) -> ScalarNonZero {
        match domain_payload(domain) {
            Some(payload) => {
                let h1 = hash_to_scalar_1(b"reshuffle", payload.as_bytes());
                let h2 = hash_to_scalar_2(b"reshuffle", payload.as_bytes());
                cw_combine(&h1, &self.x1, &h2, &self.x2)
            }
            None => ScalarNonZero::one(),
        }
    }
}

impl MasterRekeyingSecret {
    /// Generate a new random master rekeying secret.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            y1: ScalarNonZero::random(rng),
            y2: ScalarNonZero::random(rng),
        }
    }

    /// Derive the public key from this secret.
    pub fn public_key(&self) -> MasterRekeyingPublicKey {
        MasterRekeyingPublicKey {
            y1: self.y1 * G,
            y2: self.y2 * G,
        }
    }

    /// Derive a pseudonym rekeying factor for a specific session:
    /// `k_s = y₁ · H₁(s) + y₂ · H₂(s)`.
    pub fn derive_pseudonym_rekey_factor(&self, context: &EncryptionContext) -> ScalarNonZero {
        match context_payload(context) {
            Some(payload) => {
                let h1 = hash_to_scalar_1(b"pseudonym_rekey", payload.as_bytes());
                let h2 = hash_to_scalar_2(b"pseudonym_rekey", payload.as_bytes());
                cw_combine(&h1, &self.y1, &h2, &self.y2)
            }
            None => ScalarNonZero::one(),
        }
    }

    /// Derive an attribute rekeying factor for a specific session.
    pub fn derive_attribute_rekey_factor(&self, context: &EncryptionContext) -> ScalarNonZero {
        match context_payload(context) {
            Some(payload) => {
                let h1 = hash_to_scalar_1(b"attribute_rekey", payload.as_bytes());
                let h2 = hash_to_scalar_2(b"attribute_rekey", payload.as_bytes());
                cw_combine(&h1, &self.y1, &h2, &self.y2)
            }
            None => ScalarNonZero::one(),
        }
    }
}

impl MasterPseudonymizationPublicKey {
    /// Compute the reshuffle factor commitment `S_d = s_d·G` for a domain.
    pub fn compute_reshuffle_commitment(&self, domain: &PseudonymizationDomain) -> GroupElement {
        match domain_payload(domain) {
            Some(payload) => {
                let h1 = hash_to_scalar_1(b"reshuffle", payload.as_bytes());
                let h2 = hash_to_scalar_2(b"reshuffle", payload.as_bytes());
                h1 * self.x1 + h2 * self.x2
            }
            None => G,
        }
    }
}

impl MasterRekeyingPublicKey {
    /// Compute the pseudonym rekey factor commitment `K_s = k_s·G` for a
    /// session.
    pub fn compute_pseudonym_rekey_commitment(&self, context: &EncryptionContext) -> GroupElement {
        match context_payload(context) {
            Some(payload) => {
                let h1 = hash_to_scalar_1(b"pseudonym_rekey", payload.as_bytes());
                let h2 = hash_to_scalar_2(b"pseudonym_rekey", payload.as_bytes());
                h1 * self.y1 + h2 * self.y2
            }
            None => G,
        }
    }

    /// Compute the attribute rekey factor commitment for a session.
    pub fn compute_attribute_rekey_commitment(&self, context: &EncryptionContext) -> GroupElement {
        match context_payload(context) {
            Some(payload) => {
                let h1 = hash_to_scalar_1(b"attribute_rekey", payload.as_bytes());
                let h2 = hash_to_scalar_2(b"attribute_rekey", payload.as_bytes());
                h1 * self.y1 + h2 * self.y2
            }
            None => G,
        }
    }
}

/// First hash-to-scalar function H₁.
fn hash_to_scalar_1(typ: &[u8], input: &[u8]) -> ScalarNonZero {
    let mut hasher = Sha512::new();
    hasher.update(b"h1:");
    hasher.update(typ);
    hasher.update(b":");
    hasher.update(input);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    ScalarNonZero::from_hash(&bytes)
}

/// Second hash-to-scalar function H₂.
fn hash_to_scalar_2(typ: &[u8], input: &[u8]) -> ScalarNonZero {
    let mut hasher = Sha512::new();
    hasher.update(b"h2:");
    hasher.update(typ);
    hasher.update(b":");
    hasher.update(input);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    ScalarNonZero::from_hash(&bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_master_pseudonymization_key_derivation() {
        let mut rng = rand::rng();
        let secret = MasterPseudonymizationSecret::random(&mut rng);
        let public = secret.public_key();
        let domain = PseudonymizationDomain::from("test_domain");
        let factor = secret.derive_reshuffle_factor(&domain);
        let commitment = public.compute_reshuffle_commitment(&domain);
        // The commitment computed from the public key must equal s_d·G.
        assert_eq!(commitment, factor * G);
    }

    #[test]
    fn test_master_rekeying_key_derivation() {
        let mut rng = rand::rng();
        let secret = MasterRekeyingSecret::random(&mut rng);
        let public = secret.public_key();
        let context = EncryptionContext::from("test_session");
        let factor = secret.derive_pseudonym_rekey_factor(&context);
        let commitment = public.compute_pseudonym_rekey_commitment(&context);
        assert_eq!(commitment, factor * G);
    }

    #[test]
    fn test_hash_functions_independence() {
        let input = b"test_input";
        let h1 = hash_to_scalar_1(b"type", input);
        let h2 = hash_to_scalar_2(b"type", input);
        assert_ne!(h1, h2);
    }
}
