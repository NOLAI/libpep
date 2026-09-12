//! Session key shares for distributed transcryptors.
//!
//! A session key share is one transcryptor's contribution to a session key. Combining all shares
//! with the corresponding [blinded global secret key](super::blinding) yields the session key;
//! a single share reveals nothing about it on its own.
//!
//! Shares are protocol material, not keys: no data is encrypted towards them and they have no
//! associated public key, so they do not implement [`SecretKey`].

use super::blinding::{
    BlindedAttributeGlobalSecretKey, BlindedGlobalSecretKey, BlindedPseudonymGlobalSecretKey,
    BlindingFactor,
};
use crate::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
use crate::factors::{AttributeRekeyFactor, PseudonymRekeyFactor, RekeyFactor};
use crate::keys::{AttributeSessionSecretKey, PseudonymSessionSecretKey, SecretKey};

/// One transcryptor's contribution to a session key.
///
/// The associated types tie a share to the rekey factor it is made from, the blinded global
/// secret key it is combined with, and the session secret key that combination yields.
pub trait SessionKeyShare: Sized {
    /// The rekey factor this share is made from.
    type RekeyFactor: RekeyFactor;
    /// The blinded global secret key this share is combined with.
    type BlindedGlobalSecretKey: BlindedGlobalSecretKey;
    /// The session secret key that combining the shares yields.
    type SessionSecretKey: SecretKey;

    /// The scalar value of this share.
    fn value(&self) -> &ScalarNonZero;

    /// Construct from a raw scalar.
    fn from_scalar(scalar: ScalarNonZero) -> Self;

    /// Create a share from a rekey factor and this transcryptor's blinding factor.
    ///
    /// The share is the product of the two, so that the blinding factors cancel out against the
    /// blinded global secret key when the shares are combined.
    fn from_rekey_factor(
        rekey_factor: &Self::RekeyFactor,
        blinding_factor: &BlindingFactor,
    ) -> Self {
        Self::from_scalar(rekey_factor.scalar() * *blinding_factor.value())
    }

    /// Encode as a byte array.
    fn to_bytes(&self) -> [u8; 32] {
        self.value().to_bytes()
    }

    /// Encode as a hexadecimal string.
    fn to_hex(&self) -> String {
        self.value().to_hex()
    }

    /// Decode from a byte array.
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        ScalarNonZero::from_bytes(bytes).map(Self::from_scalar)
    }

    /// Decode from a slice of bytes.
    fn from_slice(slice: &[u8]) -> Option<Self> {
        ScalarNonZero::from_slice(slice).map(Self::from_scalar)
    }

    /// Decode from a hexadecimal string.
    fn from_hex(s: &str) -> Option<Self> {
        ScalarNonZero::from_hex(s).map(Self::from_scalar)
    }
}

/// A pseudonym session key share, which is a part of a pseudonym session key provided by one transcryptor.
/// By combining all pseudonym session key shares and the [`BlindedPseudonymGlobalSecretKey`], a pseudonym session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymSessionKeyShare(pub(crate) ScalarNonZero);

/// An attribute session key share, which is a part of an attribute session key provided by one transcryptor.
/// By combining all attribute session key shares and the [`BlindedAttributeGlobalSecretKey`], an attribute session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AttributeSessionKeyShare(pub(crate) ScalarNonZero);

macro_rules! impl_session_key_share {
    ($($t:ty { rekey: $rf:ty, blinded: $b:ty, session: $sk:ty }),+ $(,)?) => {$(
        impl SessionKeyShare for $t {
            type RekeyFactor = $rf;
            type BlindedGlobalSecretKey = $b;
            type SessionSecretKey = $sk;

            fn value(&self) -> &ScalarNonZero {
                &self.0
            }
            fn from_scalar(scalar: ScalarNonZero) -> Self {
                Self(scalar)
            }
        }
    )+};
}

impl_session_key_share!(
    PseudonymSessionKeyShare {
        rekey: PseudonymRekeyFactor,
        blinded: BlindedPseudonymGlobalSecretKey,
        session: PseudonymSessionSecretKey
    },
    AttributeSessionKeyShare {
        rekey: AttributeRekeyFactor,
        blinded: BlindedAttributeGlobalSecretKey,
        session: AttributeSessionSecretKey
    },
);

/// A pair of session key shares containing both pseudonym and attribute shares.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionKeyShares {
    pub pseudonym: PseudonymSessionKeyShare,
    pub attribute: AttributeSessionKeyShare,
}

/// Create a session key share from a rekey factor and blinding factor.
/// Automatically works for both pseudonym and attribute key shares based on the types.
pub fn make_session_key_share<S: SessionKeyShare>(
    rekey_factor: &S::RekeyFactor,
    blinding_factor: &BlindingFactor,
) -> S {
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
