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

/// Trait to provide the correct key from SessionKeys or GlobalPublicKeys based on the key type.
/// This enables polymorphic key access in the Client.
pub trait KeyProvider<K> {
    fn get_key(&self) -> &K;
}

impl KeyProvider<PseudonymSessionPublicKey> for SessionKeys {
    fn get_key(&self) -> &PseudonymSessionPublicKey {
        &self.pseudonym.public
    }
}

impl KeyProvider<AttributeSessionPublicKey> for SessionKeys {
    fn get_key(&self) -> &AttributeSessionPublicKey {
        &self.attribute.public
    }
}

impl KeyProvider<PseudonymSessionSecretKey> for SessionKeys {
    fn get_key(&self) -> &PseudonymSessionSecretKey {
        &self.pseudonym.secret
    }
}

impl KeyProvider<AttributeSessionSecretKey> for SessionKeys {
    fn get_key(&self) -> &AttributeSessionSecretKey {
        &self.attribute.secret
    }
}

impl KeyProvider<SessionKeys> for SessionKeys {
    fn get_key(&self) -> &SessionKeys {
        self
    }
}

impl KeyProvider<PseudonymGlobalPublicKey> for GlobalPublicKeys {
    fn get_key(&self) -> &PseudonymGlobalPublicKey {
        &self.pseudonym
    }
}

impl KeyProvider<AttributeGlobalPublicKey> for GlobalPublicKeys {
    fn get_key(&self) -> &AttributeGlobalPublicKey {
        &self.attribute
    }
}

impl KeyProvider<GlobalPublicKeys> for GlobalPublicKeys {
    fn get_key(&self) -> &GlobalPublicKeys {
        self
    }
}
