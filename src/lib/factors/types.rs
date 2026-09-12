//! Factor types for rerandomization, reshuffling and rekeying, and the info types that bundle
//! the factors needed for one transcryption.
//!
//! A *factor* is a single scalar operand of a PEP [primitive](crate::elgamal::primitives). An
//! *info* is what a transcryptor computes for a transcryption from one domain and session to
//! another: the factor ratios between the two, bundled per data type.

use crate::elgamal::arithmetic::scalars::ScalarNonZero;
use derive_more::From;

/// High-level type for the factor used to [`rerandomize`](crate::elgamal::primitives::rerandomize) an [ElGamal](crate::elgamal::ElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct RerandomizeFactor(pub(crate) ScalarNonZero);

impl RerandomizeFactor {
    /// The scalar value of this factor.
    pub fn scalar(&self) -> ScalarNonZero {
        self.0
    }
}

/// High-level type for the factor used to [`reshuffle`](crate::elgamal::primitives::reshuffle) an [ElGamal](crate::elgamal::ElGamal) ciphertext.
///
/// Pseudonym unlinkability holds only while reshuffle factors remain secret: anyone who learns
/// the factors of two domains (or their ratio) can link pseudonyms between those domains.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct ReshuffleFactor(pub(crate) ScalarNonZero);

impl ReshuffleFactor {
    /// The scalar value of this factor.
    pub fn scalar(&self) -> ScalarNonZero {
        self.0
    }
}

/// Trait for rekey factors that can be extracted to a scalar.
pub trait RekeyFactor {
    fn scalar(&self) -> ScalarNonZero;
}

/// High-level type for the factor used to [`rekey`](crate::elgamal::primitives::rekey) an [ElGamal](crate::elgamal::ElGamal) ciphertext for pseudonyms.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct PseudonymRekeyFactor(pub(crate) ScalarNonZero);

impl RekeyFactor for PseudonymRekeyFactor {
    fn scalar(&self) -> ScalarNonZero {
        self.0
    }
}

/// High-level type for the factor used to [`rekey`](crate::elgamal::primitives::rekey) an [ElGamal](crate::elgamal::ElGamal) ciphertext for attributes.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct AttributeRekeyFactor(pub(crate) ScalarNonZero);

impl RekeyFactor for AttributeRekeyFactor {
    fn scalar(&self) -> ScalarNonZero {
        self.0
    }
}

/// The information required to perform n-PEP pseudonymization from one domain and session to another:
/// a reshuffle factor `s` and a pseudonym rekey factor `k`, each the ratio between the factors
/// of the source and target.
///
/// For efficiency, we do not actually use the [`rsk2`](crate::elgamal::primitives::rsk2) operation, but instead use the regular [`rsk`](crate::elgamal::primitives::rsk) operation
/// with precomputed reshuffle and rekey factors, which is equivalent but more efficient.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PseudonymizationInfo {
    /// Reshuffle factor - transforms pseudonyms between different domains
    pub s: ReshuffleFactor,
    /// Rekey factor - transforms pseudonyms between different sessions
    pub k: PseudonymRekeyFactor,
}

impl PseudonymizationInfo {
    /// Reverse the pseudonymization info (i.e., switch the direction of the pseudonymization).
    pub fn reverse(&self) -> Self {
        Self {
            s: ReshuffleFactor(self.s.0.invert()),
            k: PseudonymRekeyFactor(self.k.0.invert()),
        }
    }
}

/// The information required to perform n-PEP rekeying of pseudonyms from one session to another:
/// the ratio between the pseudonym rekey factors of the source and target session.
///
/// For efficiency, we do not actually use the [`rekey2`](crate::elgamal::primitives::rekey2) operation, but instead use the regular [`rekey`](crate::elgamal::primitives::rekey) operation
/// with a precomputed rekey factor, which is equivalent but more efficient.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct PseudonymRekeyInfo {
    /// Rekey factor - transforms pseudonyms between different sessions
    pub k: PseudonymRekeyFactor,
}

impl PseudonymRekeyInfo {
    /// Reverse the rekey info (i.e., switch the direction of the rekeying).
    pub fn reverse(&self) -> Self {
        Self {
            k: PseudonymRekeyFactor(self.k.0.invert()),
        }
    }
}

impl From<PseudonymizationInfo> for PseudonymRekeyInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        Self { k: x.k }
    }
}

/// The information required to perform n-PEP rekeying of attributes from one session to another:
/// the ratio between the attribute rekey factors of the source and target session.
///
/// For efficiency, we do not actually use the [`rekey2`](crate::elgamal::primitives::rekey2) operation, but instead use the regular [`rekey`](crate::elgamal::primitives::rekey) operation
/// with a precomputed rekey factor, which is equivalent but more efficient.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct AttributeRekeyInfo {
    /// Rekey factor - transforms attributes between different sessions
    pub k: AttributeRekeyFactor,
}

impl AttributeRekeyInfo {
    /// Reverse the rekey info (i.e., switch the direction of the rekeying).
    pub fn reverse(&self) -> Self {
        Self {
            k: AttributeRekeyFactor(self.k.0.invert()),
        }
    }
}

/// The information required for transcryption, containing both pseudonymization info and attribute rekey info.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct TranscryptionInfo {
    pub pseudonym: PseudonymizationInfo,
    pub attribute: AttributeRekeyInfo,
}

impl TranscryptionInfo {
    /// Reverse the transcryption info (i.e., switch the direction of the transcryption).
    pub fn reverse(&self) -> Self {
        Self {
            pseudonym: self.pseudonym.reverse(),
            attribute: self.attribute.reverse(),
        }
    }
}
