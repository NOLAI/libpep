//! Specification of [PseudonymizationDomain]s and [EncryptionContext]s and transcryption between them.
//! Based on a simple string representations, this module provides the necessary types to describe
//! transcryption between different domains and sessions.

use crate::high_level::keys::{EncryptionSecret, PseudonymizationSecret};
use crate::high_level::utils::{make_pseudonymisation_factor, make_rekey_factor};
use crate::internal::arithmetic::ScalarNonZero;
use derive_more::{Deref, From};
use serde::{Deserialize, Serialize};

/// Pseudonymization domains are used to describe the domain in which pseudonyms exist (typically,
/// a user's role or usergroup).
/// With the `legacy-pep-repo-compatible` feature enabled, pseudonymization domains also include
/// an `audience_type` field, which is used to distinguish between different types of audiences.
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, Serialize, Deserialize)]
#[cfg(feature = "legacy-pep-repo-compatible")]
pub struct PseudonymizationDomain {
    #[deref]
    pub payload: String,
    pub audience_type: u32,
}
/// Encryption contexts are used to describe the context in which ciphertexts exist (typically, a
/// user's session).
/// With the `legacy-pep-repo-compatible` feature enabled, encryption contexts also include
/// an `audience_type` field, which is used to distinguish between different types of audiences.
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, Serialize, Deserialize)]
#[cfg(feature = "legacy-pep-repo-compatible")]
pub struct EncryptionContext {
    #[deref]
    pub payload: String,
    pub audience_type: u32,
}

/// Pseudonymization domains are used to describe the domain in which pseudonyms exist (typically,
/// a user's role or usergroup).
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, Serialize, Deserialize)]
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
pub struct PseudonymizationDomain(pub String);
/// Encryption contexts are used to describe the domain in which ciphertexts exist (typically, a
/// user's  session).
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, Serialize, Deserialize)]
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
pub struct EncryptionContext(pub String);

impl PseudonymizationDomain {
    #[cfg(feature = "legacy-pep-repo-compatible")]
    pub fn from(payload: &str) -> Self {
        PseudonymizationDomain {
            payload: payload.to_string(),
            audience_type: 0,
        }
    }
    #[cfg(not(feature = "legacy-pep-repo-compatible"))]
    pub fn from(payload: &str) -> Self {
        PseudonymizationDomain(payload.to_string())
    }

    #[cfg(feature = "legacy-pep-repo-compatible")]
    pub fn from_audience(payload: &str, audience_type: u32) -> Self {
        PseudonymizationDomain {
            payload: payload.to_string(),
            audience_type,
        }
    }
}
impl EncryptionContext {
    #[cfg(feature = "legacy-pep-repo-compatible")]
    pub fn from(payload: &str) -> Self {
        EncryptionContext {
            payload: payload.to_string(),
            audience_type: 0,
        }
    }
    #[cfg(not(feature = "legacy-pep-repo-compatible"))]
    pub fn from(payload: &str) -> Self {
        EncryptionContext(payload.to_string())
    }

    #[cfg(feature = "legacy-pep-repo-compatible")]
    pub fn from_audience(payload: &str, audience_type: u32) -> Self {
        EncryptionContext {
            payload: payload.to_string(),
            audience_type,
        }
    }
}

/// High-level type for the factor used to [`rerandomize`](crate::low_level::primitives::rerandomize) an [ElGamal](crate::low_level::elgamal::ElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct RerandomizeFactor(pub(crate) ScalarNonZero);
/// High-level type for the factor used to [`reshuffle`](crate::low_level::primitives::reshuffle) an [ElGamal](crate::low_level::elgamal::ElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct ReshuffleFactor(pub ScalarNonZero);
/// High-level type for the factor used to [`rekey`](crate::low_level::primitives::rekey) an [ElGamal](crate::low_level::elgamal::ElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct RekeyFactor(pub(crate) ScalarNonZero);

/// High-level type for the factors used to [`rsk`](crate::low_level::primitives::rsk) an [ElGamal](crate::low_level::elgamal::ElGamal) ciphertext.
#[derive(Eq, PartialEq, Clone, Copy, Debug, From)]
pub struct RSKFactors {
    pub s: ReshuffleFactor,
    pub k: RekeyFactor,
}

/// The information required to perform n-PEP pseudonymization from one domain and session to another.
/// The pseudonymization info consists of a reshuffle and rekey factor.
/// For efficiency, we do not actually use the [`rsk2`](crate::low_level::primitives::rsk2) operation, but instead use the regular [`rsk`](crate::low_level::primitives::rsk) operation
/// with precomputed reshuffle and rekey factors, which is equivalent but more efficient.
pub type PseudonymizationInfo = RSKFactors;

/// The information required to perform n-PEP rekeying from one session to another.
/// For efficiency, we do not actually use the [`rekey2`](crate::low_level::primitives::rekey2) operation, but instead use the regular [`rekey`](crate::low_level::primitives::rekey) operation
/// with a precomputed rekey factor, which is equivalent but more efficient.
pub type RekeyInfo = RekeyFactor;
impl PseudonymizationInfo {
    /// Compute the pseudonymization info given pseudonymization domains, sessions and secrets.
    pub fn new(
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let s_from = make_pseudonymisation_factor(pseudonymization_secret, domain_from);
        let s_to = make_pseudonymisation_factor(pseudonymization_secret, domain_to);
        let reshuffle_factor = ReshuffleFactor::from(s_from.0.invert() * s_to.0);
        let rekey_factor = RekeyInfo::new(session_from, session_to, encryption_secret);
        Self {
            s: reshuffle_factor,
            k: rekey_factor,
        }
    }

    /// Reverse the pseudonymization info (i.e., switch the direction of the pseudonymization).
    pub fn reverse(&self) -> Self {
        Self {
            s: ReshuffleFactor::from(self.s.0.invert()),
            k: RekeyFactor::from(self.k.0.invert()),
        }
    }
}
impl RekeyInfo {
    /// Compute the rekey info given sessions and secrets.
    pub fn new(
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_from = if let Some(session_from) = session_from {
            make_rekey_factor(encryption_secret, session_from)
        } else {
            RekeyFactor(ScalarNonZero::one())
        };
        let k_to = if let Some(session_to) = session_to {
            make_rekey_factor(encryption_secret, session_to)
        } else {
            RekeyFactor(ScalarNonZero::one())
        };
        Self::from(k_from.0.invert() * k_to.0)
    }
    /// Reverse the rekey info (i.e., switch the direction of the rekeying).
    pub fn reverse(&self) -> Self {
        Self::from(self.0.invert())
    }
}
impl From<PseudonymizationInfo> for RekeyInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        x.k
    }
}

/// Type alias for transcryption info, which is equivalent to pseudonymization info.
pub type TranscryptionInfo = PseudonymizationInfo;
