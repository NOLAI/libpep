//! Cryptographic factor types for rerandomization, reshuffling, and rekeying operations.

use crate::arithmetic::scalars::ScalarNonZero;
use derive_more::From;

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
        domain_from: &crate::core::factors::contexts::PseudonymizationDomain,
        domain_to: &crate::core::factors::contexts::PseudonymizationDomain,
        session_from: &crate::core::factors::contexts::EncryptionContext,
        session_to: &crate::core::factors::contexts::EncryptionContext,
        pseudonymization_secret: &crate::core::factors::PseudonymizationSecret,
        encryption_secret: &crate::core::factors::EncryptionSecret,
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
