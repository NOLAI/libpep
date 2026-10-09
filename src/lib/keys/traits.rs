//! Traits for public and secret keys.
//!
//! Only the global and session keys that data is encrypted towards and decrypted with implement
//! these traits. The intermediate material of the distributed setup (blinding factors, blinded
//! global secret keys, session key shares) is not a key and deliberately does not; see
//! [`distribution`](super::distribution).

use super::types::*;
use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
use crate::elgamal::arithmetic::scalars::ScalarNonZero;

/// A public key: a [`GroupElement`] of the form `sk * G`, which can be encoded to and decoded
/// from byte arrays and hex strings.
pub trait PublicKey: Sized {
    /// The group element this key wraps.
    fn value(&self) -> &GroupElement;

    /// Construct from a raw group element.
    ///
    /// Prefer deriving the public key from its secret key with [`SecretKey::public_key`]; this
    /// constructor is for keys received from elsewhere.
    fn from_point(point: GroupElement) -> Self;

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
        GroupElement::from_bytes(bytes).map(Self::from_point)
    }

    /// Decode from a slice of bytes.
    fn from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::from_slice(slice).map(Self::from_point)
    }

    /// Decode from a hexadecimal string.
    fn from_hex(s: &str) -> Option<Self> {
        GroupElement::from_hex(s).map(Self::from_point)
    }
}

/// A secret key: a [`ScalarNonZero`] whose public key is `sk * G`.
///
/// Secret keys are not encoded, as they should not be shared. Secret material is read through
/// explicit [`value`](Self::value) calls rather than `Deref`, so every read is visible at the
/// call site.
pub trait SecretKey: Sized {
    /// The public key associated with this secret key.
    type PublicKeyType: PublicKey;

    /// The scalar this key wraps.
    fn value(&self) -> &ScalarNonZero;

    /// Construct from a raw scalar.
    fn from_scalar(scalar: ScalarNonZero) -> Self;

    /// Derive the associated public key as `sk * G`.
    fn public_key(&self) -> Self::PublicKeyType {
        Self::PublicKeyType::from_point(*self.value() * G)
    }
}

macro_rules! impl_key_pair {
    ($($pk:ident / $sk:ident),+ $(,)?) => {$(
        impl PublicKey for $pk {
            fn value(&self) -> &GroupElement {
                &self.0
            }
            fn from_point(point: GroupElement) -> Self {
                Self(point)
            }
        }

        impl SecretKey for $sk {
            type PublicKeyType = $pk;

            fn value(&self) -> &ScalarNonZero {
                &self.0
            }
            fn from_scalar(scalar: ScalarNonZero) -> Self {
                Self(scalar)
            }
        }
    )+};
}

impl_key_pair!(
    PseudonymGlobalPublicKey / PseudonymGlobalSecretKey,
    AttributeGlobalPublicKey / AttributeGlobalSecretKey,
    PseudonymSessionPublicKey / PseudonymSessionSecretKey,
    AttributeSessionPublicKey / AttributeSessionSecretKey,
);

/// Provides the key of type `K` that an operation needs.
///
/// The *data* decides which key an operation requires: every [`Encryptable`] names it as
/// [`PublicKeyType`], so a [`Pseudonym`] needs a [`PseudonymSessionPublicKey`] and an
/// [`Attribute`] an [`AttributeSessionPublicKey`]. This trait is what a caller may hand over to
/// satisfy that requirement: the specific key itself, or a bundle to take it from.
///
/// Because `K` comes from the data type, a bundle can only ever yield the matching half. Passing
/// [`SessionPublicKeys`] where a pseudonym is encrypted selects `pseudonym`, and there is no
/// impl that would hand an attribute key to a pseudonym operation, so the key separation of the
/// two kinds of data cannot be crossed by choosing a different argument.
///
/// [`Encryptable`]: crate::data::traits::Encryptable
/// [`PublicKeyType`]: crate::data::traits::Encryptable::PublicKeyType
/// [`Pseudonym`]: crate::data::simple::Pseudonym
/// [`Attribute`]: crate::data::simple::Attribute
pub trait KeyProvider<K> {
    fn get_key(&self) -> K;
}

/// Every key provides itself, so an operation that takes a [`KeyProvider`] still accepts the one
/// specific key it needs.
impl<K: Copy> KeyProvider<K> for K {
    fn get_key(&self) -> K {
        *self
    }
}

impl KeyProvider<PseudonymSessionPublicKey> for SessionPublicKeys {
    fn get_key(&self) -> PseudonymSessionPublicKey {
        self.pseudonym
    }
}

impl KeyProvider<AttributeSessionPublicKey> for SessionPublicKeys {
    fn get_key(&self) -> AttributeSessionPublicKey {
        self.attribute
    }
}

impl KeyProvider<PseudonymSessionPublicKey> for SessionKeys {
    fn get_key(&self) -> PseudonymSessionPublicKey {
        self.pseudonym.public
    }
}

impl KeyProvider<AttributeSessionPublicKey> for SessionKeys {
    fn get_key(&self) -> AttributeSessionPublicKey {
        self.attribute.public
    }
}

impl KeyProvider<PseudonymSessionSecretKey> for SessionKeys {
    fn get_key(&self) -> PseudonymSessionSecretKey {
        self.pseudonym.secret
    }
}

impl KeyProvider<AttributeSessionSecretKey> for SessionKeys {
    fn get_key(&self) -> AttributeSessionSecretKey {
        self.attribute.secret
    }
}

impl KeyProvider<SessionPublicKeys> for SessionKeys {
    fn get_key(&self) -> SessionPublicKeys {
        self.public()
    }
}

impl KeyProvider<PseudonymGlobalPublicKey> for GlobalPublicKeys {
    fn get_key(&self) -> PseudonymGlobalPublicKey {
        self.pseudonym
    }
}

impl KeyProvider<AttributeGlobalPublicKey> for GlobalPublicKeys {
    fn get_key(&self) -> AttributeGlobalPublicKey {
        self.attribute
    }
}

impl KeyProvider<PseudonymGlobalSecretKey> for GlobalSecretKeys {
    fn get_key(&self) -> PseudonymGlobalSecretKey {
        self.pseudonym
    }
}

impl KeyProvider<AttributeGlobalSecretKey> for GlobalSecretKeys {
    fn get_key(&self) -> AttributeGlobalSecretKey {
        self.attribute
    }
}
