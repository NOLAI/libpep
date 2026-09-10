//! Traits for public and secret keys.
//!
//! These traits cover *keys* only: the global and session keys that data is actually encrypted
//! towards and decrypted with. Intermediate protocol material from the distributed setup
//! (blinded global secret keys, session key shares, blinding factors) deliberately does **not**
//! implement them — see [`crate::keys::distribution`].

use super::types::*;
use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
use crate::elgamal::arithmetic::scalars::ScalarNonZero;

/// A trait for public keys, which can be encoded and decoded from byte arrays and hex strings.
pub trait PublicKey: Sized {
    fn value(&self) -> &GroupElement;

    /// Construct a public key from a raw group element.
    ///
    /// Prefer deriving the public key from its secret key with [`SecretKey::public_key`]; this
    /// constructor exists for decoding keys received from elsewhere.
    fn from_point(point: GroupElement) -> Self;

    fn to_bytes(&self) -> [u8; 32] {
        self.value().to_bytes()
    }
    fn to_hex(&self) -> String {
        self.value().to_hex()
    }
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        GroupElement::from_bytes(bytes).map(Self::from_point)
    }
    fn from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::from_slice(slice).map(Self::from_point)
    }
    fn from_hex(s: &str) -> Option<Self> {
        GroupElement::from_hex(s).map(Self::from_point)
    }
}

/// A trait for secret keys, for which we do not allow encoding as secret keys should not be shared.
///
/// Secret material is read through explicit [`value`](Self::value) calls rather than `Deref`, so
/// every read of a secret scalar is visible at the call site.
pub trait SecretKey: Sized {
    /// The public key associated with this secret key.
    type PublicKeyType: PublicKey;

    fn value(&self) -> &ScalarNonZero;

    /// Construct a secret key from a raw scalar.
    fn from_scalar(scalar: ScalarNonZero) -> Self;

    /// Derive the associated public key.
    ///
    /// This is the only place outside the [`elgamal`](crate::elgamal) module where the basepoint
    /// is used, so the mapping from secret to public key lives in one place.
    fn public_key(&self) -> Self::PublicKeyType {
        Self::PublicKeyType::from_point(*self.value() * G)
    }
}

macro_rules! impl_public_key {
    ($($t:ty),+ $(,)?) => {$(
        impl PublicKey for $t {
            fn value(&self) -> &GroupElement {
                &self.0
            }
            fn from_point(point: GroupElement) -> Self {
                Self(point)
            }
        }
    )+};
}

macro_rules! impl_secret_key {
    ($($t:ty => $pk:ty),+ $(,)?) => {$(
        impl SecretKey for $t {
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

impl_public_key!(
    PseudonymGlobalPublicKey,
    AttributeGlobalPublicKey,
    PseudonymSessionPublicKey,
    AttributeSessionPublicKey,
);

impl_secret_key!(
    PseudonymGlobalSecretKey => PseudonymGlobalPublicKey,
    AttributeGlobalSecretKey => AttributeGlobalPublicKey,
    PseudonymSessionSecretKey => PseudonymSessionPublicKey,
    AttributeSessionSecretKey => AttributeSessionPublicKey,
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
