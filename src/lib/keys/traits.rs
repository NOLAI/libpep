//! Traits for public and secret keys.
//!
//! Only the global and session keys that data is encrypted towards and decrypted with implement
//! these traits. The intermediate material of the distributed setup (blinding factors, blinded
//! global secret keys, session key shares) is not a key and deliberately does not; see
//! [`distribution`](super::distribution).

use super::types::generic::*;
use crate::elgamal::arithmetic::group::{Bytes, Group};

/// A public key: a group element of the form `sk * G`, which can be encoded to and decoded
/// from byte arrays and hex strings.
pub trait PublicKey: Sized {
    /// The group the key is an element of.
    type Group: Group;

    /// The group element this key wraps.
    fn value(&self) -> &<Self::Group as Group>::Element;

    /// Construct from a raw group element.
    ///
    /// Prefer deriving the public key from its secret key with [`SecretKey::public_key`]; this
    /// constructor is for keys received from elsewhere.
    fn from_point(point: <Self::Group as Group>::Element) -> Self;

    /// Encode as a byte array.
    fn to_bytes(&self) -> <Self::Group as Group>::ElementBytes {
        Self::Group::serialize_element(self.value())
    }

    /// Encode as a hexadecimal string.
    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from a byte array.
    fn from_bytes(bytes: &<Self::Group as Group>::ElementBytes) -> Option<Self> {
        Self::from_slice(bytes.as_ref())
    }

    /// Decode from a slice of bytes.
    fn from_slice(slice: &[u8]) -> Option<Self> {
        Self::Group::deserialize_element(slice).map(Self::from_point)
    }

    /// Decode from a hexadecimal string.
    fn from_hex(s: &str) -> Option<Self> {
        decode_hex::<<Self::Group as Group>::ElementBytes>(s)
            .and_then(|b| Self::from_slice(b.as_ref()))
    }
}

/// A secret key: a scalar whose public key is `sk * G`.
///
/// Secret keys are not encoded, as they should not be shared. Secret material is read through
/// explicit [`value`](Self::value) calls rather than `Deref`, so every read is visible at the
/// call site.
pub trait SecretKey: Sized {
    /// The group the key is a scalar of.
    type Group: Group;

    /// The public key associated with this secret key.
    type PublicKeyType: PublicKey<Group = Self::Group>;

    /// The scalar this key wraps.
    fn value(&self) -> &<Self::Group as Group>::Scalar;

    /// Construct from a raw scalar.
    fn from_scalar(scalar: <Self::Group as Group>::Scalar) -> Self;

    /// Derive the associated public key as `sk * G`.
    fn public_key(&self) -> Self::PublicKeyType {
        Self::PublicKeyType::from_point(Self::Group::scalar_mult_gen(self.value()))
    }
}

/// Decode a hexadecimal string of exactly the length of `B`.
pub(crate) fn decode_hex<B: Bytes>(s: &str) -> Option<B> {
    if s.len() != 2 * B::len() {
        return None;
    }
    let mut out = B::zeroed();
    hex::decode_to_slice(s, out.as_mut()).ok()?;
    Some(out)
}

macro_rules! impl_key_pair {
    ($($pk:ident / $sk:ident),+ $(,)?) => {$(
        impl<G: Group> PublicKey for $pk<G> {
            type Group = G;

            fn value(&self) -> &G::Element {
                &self.0
            }
            fn from_point(point: G::Element) -> Self {
                Self(point)
            }
        }

        impl<G: Group> SecretKey for $sk<G> {
            type Group = G;
            type PublicKeyType = $pk<G>;

            fn value(&self) -> &G::Scalar {
                &self.0
            }
            fn from_scalar(scalar: G::Scalar) -> Self {
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
    fn get_key(&self) -> K;
}

impl<G: Group> KeyProvider<PseudonymSessionPublicKey<G>> for SessionKeys<G> {
    fn get_key(&self) -> PseudonymSessionPublicKey<G> {
        self.pseudonym.public
    }
}

impl<G: Group> KeyProvider<AttributeSessionPublicKey<G>> for SessionKeys<G> {
    fn get_key(&self) -> AttributeSessionPublicKey<G> {
        self.attribute.public
    }
}

impl<G: Group> KeyProvider<PseudonymSessionSecretKey<G>> for SessionKeys<G> {
    fn get_key(&self) -> PseudonymSessionSecretKey<G> {
        self.pseudonym.secret
    }
}

impl<G: Group> KeyProvider<AttributeSessionSecretKey<G>> for SessionKeys<G> {
    fn get_key(&self) -> AttributeSessionSecretKey<G> {
        self.attribute.secret
    }
}

impl<G: Group> KeyProvider<SessionKeys<G>> for SessionKeys<G> {
    fn get_key(&self) -> SessionKeys<G> {
        *self
    }
}

impl<G: Group> KeyProvider<SessionPublicKeys<G>> for SessionKeys<G> {
    fn get_key(&self) -> SessionPublicKeys<G> {
        self.public_keys()
    }
}

impl<G: Group> KeyProvider<PseudonymGlobalPublicKey<G>> for GlobalPublicKeys<G> {
    fn get_key(&self) -> PseudonymGlobalPublicKey<G> {
        self.pseudonym
    }
}

impl<G: Group> KeyProvider<AttributeGlobalPublicKey<G>> for GlobalPublicKeys<G> {
    fn get_key(&self) -> AttributeGlobalPublicKey<G> {
        self.attribute
    }
}

impl<G: Group> KeyProvider<GlobalPublicKeys<G>> for GlobalPublicKeys<G> {
    fn get_key(&self) -> GlobalPublicKeys<G> {
        *self
    }
}
