//! Traits for public and secret keys.

use super::types::*;
use crate::arithmetic::group_elements::GroupElement;
use crate::arithmetic::scalars::ScalarNonZero;

/// A trait for public keys, which can be encoded and decoded from byte arrays and hex strings.
pub trait PublicKey {
    fn value(&self) -> &GroupElement;
    fn to_bytes(&self) -> [u8; 32] {
        self.value().to_bytes()
    }
    fn to_hex(&self) -> String {
        self.value().to_hex()
    }
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self>
    where
        Self: Sized;
    fn from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized;
    fn from_hex(s: &str) -> Option<Self>
    where
        Self: Sized;
}

/// A trait for secret keys, for which we do not allow encoding as secret keys should not be shared.
pub trait SecretKey {
    fn value(&self) -> &ScalarNonZero;
}

impl PublicKey for PseudonymGlobalPublicKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }

    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        GroupElement::from_bytes(bytes).map(Self::from)
    }
    fn from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::from_slice(slice).map(PseudonymGlobalPublicKey::from)
    }
    fn from_hex(s: &str) -> Option<Self> {
        GroupElement::from_hex(s).map(PseudonymGlobalPublicKey::from)
    }
}

impl SecretKey for PseudonymGlobalSecretKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

impl PublicKey for AttributeGlobalPublicKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }

    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        GroupElement::from_bytes(bytes).map(Self::from)
    }
    fn from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::from_slice(slice).map(AttributeGlobalPublicKey::from)
    }
    fn from_hex(s: &str) -> Option<Self> {
        GroupElement::from_hex(s).map(AttributeGlobalPublicKey::from)
    }
}

impl SecretKey for AttributeGlobalSecretKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

impl PublicKey for PseudonymSessionPublicKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        GroupElement::from_bytes(bytes).map(Self::from)
    }
    fn from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::from_slice(slice).map(PseudonymSessionPublicKey::from)
    }
    fn from_hex(s: &str) -> Option<Self> {
        GroupElement::from_hex(s).map(PseudonymSessionPublicKey::from)
    }
}

impl SecretKey for PseudonymSessionSecretKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

impl PublicKey for AttributeSessionPublicKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        GroupElement::from_bytes(bytes).map(Self::from)
    }
    fn from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::from_slice(slice).map(AttributeSessionPublicKey::from)
    }
    fn from_hex(s: &str) -> Option<Self> {
        GroupElement::from_hex(s).map(AttributeSessionPublicKey::from)
    }
}

impl SecretKey for AttributeSessionSecretKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

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
