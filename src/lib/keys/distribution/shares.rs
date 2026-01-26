//! Session key shares for distributed transcryptors.
//!
//! This module defines session key shares which are parts of session keys provided by individual
//! transcryptors. By combining all shares with blinded global secret keys, session keys can be derived.

use super::blinding::BlindingFactor;
use crate::arithmetic::scalars::ScalarNonZero;
use crate::factors::{AttributeRekeyFactor, PseudonymRekeyFactor, RekeyFactor};
use derive_more::{Deref, From};

/// A pseudonym session key share, which is a part of a pseudonym session key provided by one transcryptor.
/// By combining all pseudonym session key shares and the [`BlindedPseudonymGlobalSecretKey`](crate::core::keys::distribution::BlindedPseudonymGlobalSecretKey), a pseudonym session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymSessionKeyShare(pub(crate) ScalarNonZero);

/// An attribute session key share, which is a part of an attribute session key provided by one transcryptor.
/// By combining all attribute session key shares and the [`BlindedAttributeGlobalSecretKey`](crate::core::keys::distribution::BlindedAttributeGlobalSecretKey), an attribute session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AttributeSessionKeyShare(pub(crate) ScalarNonZero);

/// A pair of session key shares containing both pseudonym and attribute shares.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionKeyShares {
    pub pseudonym: PseudonymSessionKeyShare,
    pub attribute: AttributeSessionKeyShare,
}

impl PseudonymSessionKeyShare {
    /// Decode from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        ScalarNonZero::from_bytes(bytes).map(Self)
    }
    /// Decode from a slice of bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        ScalarNonZero::from_slice(slice).map(Self)
    }
    /// Decode from a hexadecimal string.
    pub fn from_hex(s: &str) -> Option<Self> {
        ScalarNonZero::from_hex(s).map(Self)
    }
}

impl AttributeSessionKeyShare {
    /// Decode from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        ScalarNonZero::from_bytes(bytes).map(Self)
    }
    /// Decode from a slice of bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        ScalarNonZero::from_slice(slice).map(Self)
    }
    /// Decode from a hexadecimal string.
    pub fn from_hex(s: &str) -> Option<Self> {
        ScalarNonZero::from_hex(s).map(Self)
    }
}

/// Trait for creating session key shares from rekey factors.
/// This enables polymorphic share generation for both pseudonym and attribute keys.
pub trait MakeSessionKeyShare<R: RekeyFactor>: Sized {
    /// Create a session key share from a rekey factor and blinding factor.
    fn from_rekey_factor(rekey_factor: &R, blinding_factor: &BlindingFactor) -> Self;
}

impl MakeSessionKeyShare<PseudonymRekeyFactor> for PseudonymSessionKeyShare {
    fn from_rekey_factor(
        rekey_factor: &PseudonymRekeyFactor,
        blinding_factor: &BlindingFactor,
    ) -> Self {
        PseudonymSessionKeyShare(rekey_factor.scalar() * **blinding_factor)
    }
}

impl MakeSessionKeyShare<AttributeRekeyFactor> for AttributeSessionKeyShare {
    fn from_rekey_factor(
        rekey_factor: &AttributeRekeyFactor,
        blinding_factor: &BlindingFactor,
    ) -> Self {
        AttributeSessionKeyShare(rekey_factor.scalar() * **blinding_factor)
    }
}

/// Create a session key share from a rekey factor and blinding factor.
/// Automatically works for both pseudonym and attribute key shares based on the types.
pub fn make_session_key_share<R, S>(rekey_factor: &R, blinding_factor: &BlindingFactor) -> S
where
    R: RekeyFactor,
    S: MakeSessionKeyShare<R>,
{
    S::from_rekey_factor(rekey_factor, blinding_factor)
}

/// Create a [`PseudonymSessionKeyShare`] from a [`PseudonymRekeyFactor`] and a [`BlindingFactor`].
pub fn make_pseudonym_session_key_share(
    rekey_factor: &PseudonymRekeyFactor,
    blinding_factor: &BlindingFactor,
) -> PseudonymSessionKeyShare {
    make_session_key_share(rekey_factor, blinding_factor)
}

/// Create an [`AttributeSessionKeyShare`] from an [`AttributeRekeyFactor`] and a [`BlindingFactor`].
pub fn make_attribute_session_key_share(
    rekey_factor: &AttributeRekeyFactor,
    blinding_factor: &BlindingFactor,
) -> AttributeSessionKeyShare {
    make_session_key_share(rekey_factor, blinding_factor)
}

/// Create [`SessionKeyShares`] (both pseudonym and attribute) from rekey factors and a blinding factor.
pub fn make_session_key_shares(
    pseudonym_rekey_factor: &PseudonymRekeyFactor,
    attribute_rekey_factor: &AttributeRekeyFactor,
    blinding_factor: &BlindingFactor,
) -> SessionKeyShares {
    SessionKeyShares {
        pseudonym: make_pseudonym_session_key_share(pseudonym_rekey_factor, blinding_factor),
        attribute: make_attribute_session_key_share(attribute_rekey_factor, blinding_factor),
    }
}
