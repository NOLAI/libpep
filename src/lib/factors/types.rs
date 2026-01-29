//! Cryptographic factor types for rerandomization, reshuffling, and rekeying operations.

use crate::arithmetic::scalars::ScalarNonZero;
use crate::factors::EncryptionContext;
use derive_more::From;

/// High-level type for the factor used to [`rerandomize`](crate::core::primitives::rerandomize) an [ElGamal](crate::core::elgamal::ElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct RerandomizeFactor(pub(crate) ScalarNonZero);

/// High-level type for the factor used to [`reshuffle`](crate::core::primitives::reshuffle) an [ElGamal](crate::core::elgamal::ElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct ReshuffleFactor(pub ScalarNonZero);

/// Trait for rekey factors that can be extracted to a scalar.
pub trait RekeyFactor {
    fn scalar(&self) -> ScalarNonZero;
}

/// High-level type for the factor used to [`rekey`](crate::core::primitives::rekey) an [ElGamal](crate::core::elgamal::ElGamal) ciphertext for pseudonyms.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct PseudonymRekeyFactor(pub(crate) ScalarNonZero);

impl RekeyFactor for PseudonymRekeyFactor {
    fn scalar(&self) -> ScalarNonZero {
        self.0
    }
}

/// High-level type for the factor used to [`rekey`](crate::core::primitives::rekey) an [ElGamal](crate::core::elgamal::ElGamal) ciphertext for attributes.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct AttributeRekeyFactor(pub(crate) ScalarNonZero);

impl RekeyFactor for AttributeRekeyFactor {
    fn scalar(&self) -> ScalarNonZero {
        self.0
    }
}

/// High-level type for the factors used to [`rsk`](crate::core::primitives::rsk) an [ElGamal](crate::core::elgamal::ElGamal) ciphertext for pseudonyms.
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
/// For efficiency, we do not actually use the [`rsk2`](crate::core::primitives::rsk2) operation, but instead use the regular [`rsk`](crate::core::primitives::rsk) operation
/// with precomputed reshuffle and rekey factors, which is equivalent but more efficient.
pub type PseudonymizationInfo = PseudonymRSKFactors;

/// The information required to perform n-PEP rekeying of pseudonyms from one session to another.
/// For efficiency, we do not actually use the [`rekey2`](crate::core::primitives::rekey2) operation, but instead use the regular [`rekey`](crate::core::primitives::rekey) operation
/// with a precomputed rekey factor, which is equivalent but more efficient.
pub type PseudonymRekeyInfo = PseudonymRekeyFactor;

/// The information required to perform n-PEP rekeying of attributes from one session to another.
/// For efficiency, we do not actually use the [`rekey2`](crate::core::primitives::rekey2) operation, but instead use the regular [`rekey`](crate::core::primitives::rekey) operation
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
        domain_from: &crate::factors::contexts::PseudonymizationDomain,
        domain_to: &crate::factors::contexts::PseudonymizationDomain,
        session_from: &crate::factors::contexts::EncryptionContext,
        session_to: &crate::factors::contexts::EncryptionContext,
        pseudonymization_secret: &crate::factors::PseudonymizationSecret,
        encryption_secret: &crate::factors::EncryptionSecret,
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

/// A trait for types that can provide rekey information for a specific rekey info type.
///
/// This trait is parameterized by the rekey info type, allowing different implementations
/// for different encrypted types (e.g., `AttributeRekeyInfo` vs `PseudonymRekeyInfo`).
///
/// # Examples
///
/// ```rust,ignore
/// // Transcryptor implements RekeyInfoProvider for both types
/// let attr_info: AttributeRekeyInfo = transcryptor.rekey_info(&from_ctx, &to_ctx);
/// let pseudo_info: PseudonymRekeyInfo = transcryptor.rekey_info(&from_ctx, &to_ctx);
/// ```
pub trait RekeyInfoProvider<Info> {
    /// Get the rekey information for transcryption between encryption contexts.
    fn rekey_info(&self, session_from: &EncryptionContext, session_to: &EncryptionContext) -> Info;
}
