//! Session key shares generic over the [`Group`].

use super::super::blinding::generic::{
    BlindedAttributeGlobalSecretKey, BlindedGlobalSecretKey, BlindedPseudonymGlobalSecretKey,
    BlindingFactor,
};
use crate::elgamal::arithmetic::group::Group;
use crate::factors::types::generic::{AttributeRekeyFactor, PseudonymRekeyFactor, RekeyFactor};
use crate::keys::traits::{decode_hex, SecretKey};
use crate::keys::types::generic::{AttributeSessionSecretKey, PseudonymSessionSecretKey};

/// One transcryptor's contribution to a session key.
///
/// The associated types tie a share to the rekey factor it is made from, the blinded global
/// secret key it is combined with, and the session secret key that combination yields.
pub trait SessionKeyShare: Sized {
    /// The group the share is a scalar of.
    type Group: Group;
    /// The rekey factor this share is made from.
    type RekeyFactor: RekeyFactor<Group = Self::Group>;
    /// The blinded global secret key this share is combined with.
    type BlindedGlobalSecretKey: BlindedGlobalSecretKey<Group = Self::Group>;
    /// The session secret key that combining the shares yields.
    type SessionSecretKey: SecretKey<Group = Self::Group>;

    /// The scalar value of this share.
    fn value(&self) -> &<Self::Group as Group>::Scalar;

    /// Construct from a raw scalar.
    fn from_scalar(scalar: <Self::Group as Group>::Scalar) -> Self;

    /// Create a share from a rekey factor and this transcryptor's blinding factor.
    ///
    /// The share is the product of the two, so that the blinding factors cancel out against the
    /// blinded global secret key when the shares are combined.
    fn from_rekey_factor(
        rekey_factor: &Self::RekeyFactor,
        blinding_factor: &BlindingFactor<Self::Group>,
    ) -> Self {
        Self::from_scalar(rekey_factor.scalar() * *blinding_factor.value())
    }

    /// Encode as a byte array.
    fn to_bytes(&self) -> <Self::Group as Group>::ScalarBytes {
        Self::Group::serialize_scalar(self.value())
    }

    /// Encode as a hexadecimal string.
    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from a byte array.
    fn from_bytes(bytes: &<Self::Group as Group>::ScalarBytes) -> Option<Self> {
        Self::from_slice(bytes.as_ref())
    }

    /// Decode from a slice of bytes.
    fn from_slice(slice: &[u8]) -> Option<Self> {
        Self::Group::deserialize_scalar(slice).map(Self::from_scalar)
    }

    /// Decode from a hexadecimal string.
    fn from_hex(s: &str) -> Option<Self> {
        decode_hex::<<Self::Group as Group>::ScalarBytes>(s)
            .and_then(|b| Self::from_slice(b.as_ref()))
    }
}

/// A pseudonym session key share, which is a part of a pseudonym session key provided by one transcryptor.
/// By combining all pseudonym session key shares and the [`BlindedPseudonymGlobalSecretKey`], a pseudonym session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct PseudonymSessionKeyShare<G: Group>(pub(crate) G::Scalar);

/// An attribute session key share, which is a part of an attribute session key provided by one transcryptor.
/// By combining all attribute session key shares and the [`BlindedAttributeGlobalSecretKey`], an attribute session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct AttributeSessionKeyShare<G: Group>(pub(crate) G::Scalar);

macro_rules! impl_session_key_share {
    ($($t:ident { rekey: $rf:ident, blinded: $b:ident, session: $sk:ident }),+ $(,)?) => {$(
        impl<G: Group> SessionKeyShare for $t<G> {
            type Group = G;
            type RekeyFactor = $rf<G>;
            type BlindedGlobalSecretKey = $b<G>;
            type SessionSecretKey = $sk<G>;

            fn value(&self) -> &G::Scalar {
                &self.0
            }
            fn from_scalar(scalar: G::Scalar) -> Self {
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
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct SessionKeyShares<G: Group> {
    pub pseudonym: PseudonymSessionKeyShare<G>,
    pub attribute: AttributeSessionKeyShare<G>,
}

/// Create a session key share from a rekey factor and blinding factor.
/// Automatically works for both pseudonym and attribute key shares based on the types.
pub fn make_session_key_share<S: SessionKeyShare>(
    rekey_factor: &S::RekeyFactor,
    blinding_factor: &BlindingFactor<S::Group>,
) -> S {
    S::from_rekey_factor(rekey_factor, blinding_factor)
}

/// Create a [`PseudonymSessionKeyShare`] from a [`PseudonymRekeyFactor`] and a [`BlindingFactor`].
pub fn make_pseudonym_session_key_share<G: Group>(
    rekey_factor: &PseudonymRekeyFactor<G>,
    blinding_factor: &BlindingFactor<G>,
) -> PseudonymSessionKeyShare<G> {
    make_session_key_share(rekey_factor, blinding_factor)
}

/// Create an [`AttributeSessionKeyShare`] from an [`AttributeRekeyFactor`] and a [`BlindingFactor`].
pub fn make_attribute_session_key_share<G: Group>(
    rekey_factor: &AttributeRekeyFactor<G>,
    blinding_factor: &BlindingFactor<G>,
) -> AttributeSessionKeyShare<G> {
    make_session_key_share(rekey_factor, blinding_factor)
}

/// Create [`SessionKeyShares`] (both pseudonym and attribute) from rekey factors and a blinding factor.
pub fn make_session_key_shares<G: Group>(
    pseudonym_rekey_factor: &PseudonymRekeyFactor<G>,
    attribute_rekey_factor: &AttributeRekeyFactor<G>,
    blinding_factor: &BlindingFactor<G>,
) -> SessionKeyShares<G> {
    SessionKeyShares {
        pseudonym: make_pseudonym_session_key_share(pseudonym_rekey_factor, blinding_factor),
        attribute: make_attribute_session_key_share(attribute_rekey_factor, blinding_factor),
    }
}
