//! Key type definitions for global and session keys.
//!
//! Keys are split into separate Attribute and Pseudonym encryption keys to prevent pseudonym values
//! from being leaked by falsely presenting them as attributes.

use crate::arithmetic::group_elements::GroupElement;
use crate::arithmetic::scalars::ScalarNonZero;
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
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymGlobalPublicKey(pub(crate) GroupElement);

/// A global secret key for pseudonyms from which session keys are derived.
#[derive(Copy, Clone, Debug, From)]
pub struct PseudonymGlobalSecretKey(pub(crate) ScalarNonZero);

/// A global public key for attributes, associated with the [`AttributeGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt attributes, if no session key is available or using a session key may leak information.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AttributeGlobalPublicKey(pub(crate) GroupElement);

/// A global secret key for attributes from which session keys are derived.
#[derive(Copy, Clone, Debug, From)]
pub struct AttributeGlobalSecretKey(pub(crate) ScalarNonZero);

/// Session keys for both pseudonyms and attributes.
/// Organized by key type (pseudonym/attribute) rather than by public/secret.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionKeys {
    pub pseudonym: PseudonymSessionKeys,
    pub attribute: AttributeSessionKeys,
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
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymSessionPublicKey(pub(crate) GroupElement);

/// A session secret key used to decrypt pseudonyms with.
#[derive(Copy, Clone, Debug, Deref, From, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymSessionSecretKey(pub(crate) ScalarNonZero);

/// A session public key used to encrypt attributes, associated with a [`AttributeSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AttributeSessionPublicKey(pub(crate) GroupElement);

/// A session secret key used to decrypt attributes with.
#[derive(Copy, Clone, Debug, Deref, From, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AttributeSessionSecretKey(pub(crate) ScalarNonZero);
