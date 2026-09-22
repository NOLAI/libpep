//! Key type definitions for global and session keys.
//!
//! Keys are split into separate Attribute and Pseudonym encryption keys to prevent pseudonym values
//! from being leaked by falsely presenting them as attributes.

use crate::elgamal::arithmetic::group_elements::GroupElement;
use crate::elgamal::arithmetic::scalars::ScalarNonZero;
use derive_more::{Deref, From};

/// A pair of global public keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GlobalPublicKeys {
    pub pseudonym: PseudonymGlobalPublicKey,
    pub attribute: AttributeGlobalPublicKey,
}

/// A pair of global secret keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Debug)]
pub struct GlobalSecretKeys {
    pub pseudonym: PseudonymGlobalSecretKey,
    pub attribute: AttributeGlobalSecretKey,
}

/// A global public key for pseudonyms, associated with the [`PseudonymGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt pseudonyms, if no session key is available or using a session key may leak information.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymGlobalPublicKey(pub(crate) GroupElement);

/// A global secret key for pseudonyms from which session keys are derived.
#[derive(Copy, Clone, Debug)]
pub struct PseudonymGlobalSecretKey(pub(crate) ScalarNonZero);

/// A global public key for attributes, associated with the [`AttributeGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt attributes, if no session key is available or using a session key may leak information.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AttributeGlobalPublicKey(pub(crate) GroupElement);

/// A global secret key for attributes from which session keys are derived.
#[derive(Copy, Clone, Debug)]
pub struct AttributeGlobalSecretKey(pub(crate) ScalarNonZero);

/// Session keys for both pseudonyms and attributes.
/// Organized by key type (pseudonym/attribute) rather than by public/secret.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionKeys {
    pub pseudonym: PseudonymSessionKeys,
    pub attribute: AttributeSessionKeys,
}

/// The public halves of [`SessionKeys`]: what a sender needs to encrypt towards a session, and what
/// a transcryptor needs to rerandomize ciphertexts encrypted for it.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionPublicKeys {
    pub pseudonym: PseudonymSessionPublicKey,
    pub attribute: AttributeSessionPublicKey,
}

impl SessionKeys {
    /// The public keys of this session.
    pub fn public_keys(&self) -> SessionPublicKeys {
        SessionPublicKeys {
            pseudonym: self.pseudonym.public,
            attribute: self.attribute.public,
        }
    }
}

impl From<&SessionKeys> for SessionPublicKeys {
    fn from(keys: &SessionKeys) -> Self {
        keys.public_keys()
    }
}

/// A pseudonym session key pair containing both public and secret keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PseudonymSessionKeys {
    pub public: PseudonymSessionPublicKey,
    pub secret: PseudonymSessionSecretKey,
}

/// An attribute session key pair containing both public and secret keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AttributeSessionKeys {
    pub public: AttributeSessionPublicKey,
    pub secret: AttributeSessionSecretKey,
}

/// A session public key used to encrypt pseudonyms, associated with a [`PseudonymSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymSessionPublicKey(pub(crate) GroupElement);

/// A session secret key used to decrypt pseudonyms with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymSessionSecretKey(pub(crate) ScalarNonZero);

/// A session public key used to encrypt attributes, associated with a [`AttributeSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AttributeSessionPublicKey(pub(crate) GroupElement);

/// A session secret key used to decrypt attributes with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AttributeSessionSecretKey(pub(crate) ScalarNonZero);

// Session public keys travel with a batch so downstream operations know the
// recipient public key. Converting a key mirrors the math behind ciphertext
// rekeying, but acts on the *key* itself; the methods are named `convert` to
// distinguish them from message-level rekeying.
#[cfg(all(feature = "batch-pk", not(feature = "elgamal3")))]
impl PseudonymSessionPublicKey {
    /// Convert this session public key to its rekeyed counterpart by applying
    /// a pseudonym rekey factor. The new key is `factor*self`.
    pub fn convert(&self, factor: &crate::factors::PseudonymRekeyFactor) -> Self {
        use crate::factors::types::RekeyFactor;
        Self(factor.scalar() * self.0)
    }
}

#[cfg(all(feature = "batch-pk", not(feature = "elgamal3")))]
impl AttributeSessionPublicKey {
    /// Convert this session public key to its rekeyed counterpart by applying
    /// an attribute rekey factor. The new key is `factor*self`.
    pub fn convert(&self, factor: &crate::factors::AttributeRekeyFactor) -> Self {
        use crate::factors::types::RekeyFactor;
        Self(factor.scalar() * self.0)
    }
}

#[cfg(all(feature = "batch-pk", not(feature = "elgamal3")))]
impl SessionPublicKeys {
    /// Convert this session public key bundle to its rekeyed counterpart, applying the
    /// pseudonym rekey factor to the pseudonym half and the attribute rekey
    /// factor to the attribute half.
    pub fn convert(
        &self,
        pseudonym: &crate::factors::PseudonymRekeyFactor,
        attribute: &crate::factors::AttributeRekeyFactor,
    ) -> Self {
        Self {
            pseudonym: self.pseudonym.convert(pseudonym),
            attribute: self.attribute.convert(attribute),
        }
    }
}
