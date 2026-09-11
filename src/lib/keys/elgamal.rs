//! The ElGamal instantiation of the key [role traits](super::traits).
//!
//! These traits supply the concrete representation — a [`GroupElement`] for public keys, a
//! [`ScalarNonZero`] for secret keys — and the derivation `pk = sk * G` that relates them. They
//! stand to [`PublicKey`]/[`SecretKey`] as
//! [`ElGamalEncryptable`](crate::data::simple::ElGamalEncryptable) stands to
//! [`Encryptable`](crate::data::traits::Encryptable): the role lives in the high-level layer, the
//! scheme-specific mechanics live here.
//!
//! An alternative scheme would supply its own pair of sub-traits alongside these, and implement
//! the same role traits, rather than changing them.

use super::traits::{PublicKey, SecretKey};
use super::types::*;
use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
use crate::elgamal::arithmetic::scalars::ScalarNonZero;

/// An ElGamal public key: a [`GroupElement`] of the form `sk * G`.
pub trait ElGamalPublicKey: PublicKey {
    /// The group element this key wraps.
    fn value(&self) -> &GroupElement;

    /// Construct from a raw group element.
    ///
    /// Prefer deriving the public key from its secret key with [`SecretKey::public_key`]; this
    /// constructor exists for decoding keys received from elsewhere.
    fn from_point(point: GroupElement) -> Self;
}

/// An ElGamal secret key: a [`ScalarNonZero`] whose public key is `sk * G`.
pub trait ElGamalSecretKey: SecretKey<PublicKeyType = Self::ElGamalPublicKeyType> {
    /// The ElGamal public key this secret key derives.
    type ElGamalPublicKeyType: ElGamalPublicKey;

    /// The scalar this key wraps.
    fn value(&self) -> &ScalarNonZero;

    /// Construct from a raw scalar.
    fn from_scalar(scalar: ScalarNonZero) -> Self;
}

macro_rules! impl_elgamal_public_key {
    ($($t:ty),+ $(,)?) => {$(
        impl ElGamalPublicKey for $t {
            fn value(&self) -> &GroupElement {
                &self.0
            }
            fn from_point(point: GroupElement) -> Self {
                Self(point)
            }
        }

        impl PublicKey for $t {
            fn to_bytes(&self) -> [u8; 32] {
                ElGamalPublicKey::value(self).to_bytes()
            }
            fn to_hex(&self) -> String {
                ElGamalPublicKey::value(self).to_hex()
            }
            fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
                GroupElement::from_bytes(bytes).map(<$t>::from_point)
            }
            fn from_slice(slice: &[u8]) -> Option<Self> {
                GroupElement::from_slice(slice).map(<$t>::from_point)
            }
            fn from_hex(s: &str) -> Option<Self> {
                GroupElement::from_hex(s).map(<$t>::from_point)
            }
        }
    )+};
}

macro_rules! impl_elgamal_secret_key {
    ($($t:ty => $pk:ty),+ $(,)?) => {$(
        impl ElGamalSecretKey for $t {
            type ElGamalPublicKeyType = $pk;

            fn value(&self) -> &ScalarNonZero {
                &self.0
            }
            fn from_scalar(scalar: ScalarNonZero) -> Self {
                Self(scalar)
            }
        }

        impl SecretKey for $t {
            type PublicKeyType = $pk;

            /// Derives the public key as `sk * G`.
            ///
            /// This is the only use of the basepoint outside the
            /// [`elgamal`](crate::elgamal) module.
            fn public_key(&self) -> Self::PublicKeyType {
                <$pk>::from_point(*ElGamalSecretKey::value(self) * G)
            }
        }
    )+};
}

impl_elgamal_public_key!(
    PseudonymGlobalPublicKey,
    AttributeGlobalPublicKey,
    PseudonymSessionPublicKey,
    AttributeSessionPublicKey,
);

impl_elgamal_secret_key!(
    PseudonymGlobalSecretKey => PseudonymGlobalPublicKey,
    AttributeGlobalSecretKey => AttributeGlobalPublicKey,
    PseudonymSessionSecretKey => PseudonymSessionPublicKey,
    AttributeSessionSecretKey => AttributeSessionPublicKey,
);
