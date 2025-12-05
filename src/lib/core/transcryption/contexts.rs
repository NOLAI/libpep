//! Specification of [PseudonymizationDomain]s and [EncryptionContext]s and transcryption between them.
//! Based on a simple string representations, this module provides the necessary types to describe
//! transcryption between different domains and sessions.

use super::secrets::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymisation_factor,
    EncryptionSecret, PseudonymizationSecret,
};
use crate::arithmetic::scalars::ScalarNonZero;
use derive_more::From;

/// Pseudonymization domains are used to describe the domain in which pseudonyms exist (typically,
/// a user's role or usergroup).
///
/// With the `global-pseudonyms` feature enabled, domains can be `Global` (for pseudonyms that work across all domains).
/// With the `legacy` feature enabled, specific domains include an `audience_type` field.
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum PseudonymizationDomain {
    #[cfg(feature = "global-pseudonyms")]
    /// Global domain for pseudonyms
    Global,
    #[cfg(feature = "legacy")]
    /// Specific domain with payload and audience type (legacy mode)
    Specific { payload: String, audience_type: u32 },
    #[cfg(not(feature = "legacy"))]
    /// Specific domain with payload only
    Specific(String),
}

/// Encryption contexts are used to describe the context in which ciphertexts exist (typically, a
/// user's session).
///
/// With the `offline` feature enabled, contexts can be `Global` (for offline encryption).
/// With the `legacy` feature enabled, specific contexts include an `audience_type` field.
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum EncryptionContext {
    #[cfg(feature = "offline")]
    /// Global context for offline encryption
    Global,
    #[cfg(feature = "legacy")]
    /// Specific context with payload and audience type (legacy mode)
    Specific { payload: String, audience_type: u32 },
    #[cfg(not(feature = "legacy"))]
    /// Specific context with payload only
    Specific(String),
}

impl PseudonymizationDomain {
    /// Create a specific domain from a string payload
    #[cfg(feature = "legacy")]
    pub fn from(payload: &str) -> Self {
        PseudonymizationDomain::Specific {
            payload: payload.to_string(),
            audience_type: 0,
        }
    }

    /// Create a specific domain from a string payload
    #[cfg(not(feature = "legacy"))]
    pub fn from(payload: &str) -> Self {
        PseudonymizationDomain::Specific(payload.to_string())
    }

    /// Create a global domain (available only with global-pseudonyms feature)
    #[cfg(feature = "global-pseudonyms")]
    pub fn global() -> Self {
        PseudonymizationDomain::Global
    }

    /// Create a specific domain with audience type (legacy mode)
    #[cfg(feature = "legacy")]
    pub fn from_audience(payload: &str, audience_type: u32) -> Self {
        PseudonymizationDomain::Specific {
            payload: payload.to_string(),
            audience_type,
        }
    }
}
impl EncryptionContext {
    /// Create a specific context from a string payload
    #[cfg(feature = "legacy")]
    pub fn from(payload: &str) -> Self {
        EncryptionContext::Specific {
            payload: payload.to_string(),
            audience_type: 0,
        }
    }

    /// Create a specific context from a string payload
    #[cfg(not(feature = "legacy"))]
    pub fn from(payload: &str) -> Self {
        EncryptionContext::Specific(payload.to_string())
    }

    /// Create a global context (available only with offline feature)
    #[cfg(feature = "offline")]
    pub fn global() -> Self {
        EncryptionContext::Global
    }

    /// Create a specific context with audience type (legacy mode)
    #[cfg(feature = "legacy")]
    pub fn from_audience(payload: &str, audience_type: u32) -> Self {
        EncryptionContext::Specific {
            payload: payload.to_string(),
            audience_type,
        }
    }
}

/// High-level type for the factor used to [`rerandomize`](crate::base::primitives::rerandomize) an [ElGamal](crate::base::elgamal::ElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct RerandomizeFactor(pub(crate) ScalarNonZero);
/// High-level type for the factor used to [`reshuffle`](crate::base::primitives::reshuffle) an [ElGamal](crate::base::elgamal::ElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct ReshuffleFactor(pub ScalarNonZero);
/// Trait for rekey factors that can be extracted to a scalar.
pub trait RekeyFactor {
    fn scalar(&self) -> ScalarNonZero;
}

/// High-level type for the factor used to [`rekey`](crate::base::primitives::rekey) an [ElGamal](crate::base::elgamal::ElGamal) ciphertext for pseudonyms.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct PseudonymRekeyFactor(pub(crate) ScalarNonZero);

impl RekeyFactor for PseudonymRekeyFactor {
    fn scalar(&self) -> ScalarNonZero {
        self.0
    }
}

/// High-level type for the factor used to [`rekey`](crate::base::primitives::rekey) an [ElGamal](crate::base::elgamal::ElGamal) ciphertext for attributes.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct AttributeRekeyFactor(pub(crate) ScalarNonZero);

impl RekeyFactor for AttributeRekeyFactor {
    fn scalar(&self) -> ScalarNonZero {
        self.0
    }
}

/// High-level type for the factors used to [`rsk`](crate::base::primitives::rsk) an [ElGamal](crate::base::elgamal::ElGamal) ciphertext for pseudonyms.
/// Contains both the reshuffle factor (`s`) and the rekey factor (`k`).
#[derive(Eq, PartialEq, Clone, Copy, Debug, From)]
pub struct PseudonymRSKFactors {
    /// Reshuffle factor - transforms pseudonyms between different domains
    pub s: ReshuffleFactor,
    /// Rekey factor - transforms pseudonyms between different sessions
    pub k: PseudonymRekeyFactor,
}

/// The information required to perform n-PEP pseudonymization from one domain and session to another.
/// The pseudonymization info consists of a reshuffle and rekey factor.
/// For efficiency, we do not actually use the [`rsk2`](crate::base::primitives::rsk2) operation, but instead use the regular [`rsk`](crate::base::primitives::rsk) operation
/// with precomputed reshuffle and rekey factors, which is equivalent but more efficient.
pub type PseudonymizationInfo = PseudonymRSKFactors;

/// The information required to perform n-PEP rekeying of pseudonyms from one session to another.
/// For efficiency, we do not actually use the [`rekey2`](crate::base::primitives::rekey2) operation, but instead use the regular [`rekey`](crate::base::primitives::rekey) operation
/// with a precomputed rekey factor, which is equivalent but more efficient.
pub type PseudonymRekeyInfo = PseudonymRekeyFactor;

/// The information required to perform n-PEP rekeying of attributes from one session to another.
/// For efficiency, we do not actually use the [`rekey2`](crate::base::primitives::rekey2) operation, but instead use the regular [`rekey`](crate::base::primitives::rekey) operation
/// with a precomputed rekey factor, which is equivalent but more efficient.
pub type AttributeRekeyInfo = AttributeRekeyFactor;
impl PseudonymizationInfo {
    /// Compute the pseudonymization info given pseudonymization domains, sessions and secrets.
    pub fn new(
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let s_from = make_pseudonymisation_factor(pseudonymization_secret, domain_from);
        let s_to = make_pseudonymisation_factor(pseudonymization_secret, domain_to);
        let reshuffle_factor = ReshuffleFactor(s_from.0.invert() * s_to.0);
        let rekey_factor = PseudonymRekeyInfo::new(session_from, session_to, encryption_secret);
        Self {
            s: reshuffle_factor,
            k: rekey_factor,
        }
    }

    /// Reverse the pseudonymization info (i.e., switch the direction of the pseudonymization).
    pub fn reverse(&self) -> Self {
        Self {
            s: ReshuffleFactor(self.s.0.invert()),
            k: PseudonymRekeyFactor(self.k.0.invert()),
        }
    }
}
impl PseudonymRekeyInfo {
    /// Compute the rekey info for pseudonyms given sessions and secrets.
    pub fn new(
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_from = make_pseudonym_rekey_factor(encryption_secret, session_from);
        let k_to = make_pseudonym_rekey_factor(encryption_secret, session_to);
        PseudonymRekeyFactor(k_from.0.invert() * k_to.0)
    }

    /// Reverse the rekey info (i.e., switch the direction of the rekeying).
    pub fn reverse(&self) -> Self {
        PseudonymRekeyFactor(self.0.invert())
    }
}

impl AttributeRekeyInfo {
    /// Compute the rekey info for attributes given sessions and secrets.
    pub fn new(
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_from = make_attribute_rekey_factor(encryption_secret, session_from);
        let k_to = make_attribute_rekey_factor(encryption_secret, session_to);
        AttributeRekeyFactor(k_from.0.invert() * k_to.0)
    }

    /// Reverse the rekey info (i.e., switch the direction of the rekeying).
    pub fn reverse(&self) -> Self {
        AttributeRekeyFactor(self.0.invert())
    }
}
impl From<PseudonymizationInfo> for PseudonymRekeyInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        x.k
    }
}

/// The information required for transcryption, containing both pseudonymization info and attribute rekey info.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct TranscryptionInfo {
    pub pseudonym: PseudonymizationInfo,
    pub attribute: AttributeRekeyInfo,
}

impl TranscryptionInfo {
    /// Compute the transcryption info given pseudonymization domains, sessions and secrets.
    pub fn new(
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        Self {
            pseudonym: PseudonymizationInfo::new(
                domain_from,
                domain_to,
                session_from,
                session_to,
                pseudonymization_secret,
                encryption_secret,
            ),
            attribute: AttributeRekeyInfo::new(session_from, session_to, encryption_secret),
        }
    }

    /// Reverse the transcryption info (i.e., switch the direction of the transcryption).
    pub fn reverse(&self) -> Self {
        Self {
            pseudonym: self.pseudonym.reverse(),
            attribute: self.attribute.reverse(),
        }
    }
}
