//! Key types generic over the [`Group`].

use crate::elgamal::arithmetic::group::Group;
use derive_more::{Deref, From};

/// A pair of global public keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct GlobalPublicKeys<G: Group> {
    /// The global public key for pseudonyms.
    pub pseudonym: PseudonymGlobalPublicKey<G>,
    /// The global public key for attributes.
    pub attribute: AttributeGlobalPublicKey<G>,
}

/// A pair of global secret keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone)]
pub struct GlobalSecretKeys<G: Group> {
    /// The global secret key for pseudonyms.
    pub pseudonym: PseudonymGlobalSecretKey<G>,
    /// The global secret key for attributes.
    pub attribute: AttributeGlobalSecretKey<G>,
}

/// A global public key for pseudonyms, associated with the [`PseudonymGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt pseudonyms, if no session key is available or using a session key may leak information.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct PseudonymGlobalPublicKey<G: Group>(pub(crate) G::Element);

/// A global secret key for pseudonyms from which session keys are derived.
#[derive(Copy, Clone)]
pub struct PseudonymGlobalSecretKey<G: Group>(pub(crate) G::Scalar);

/// A global public key for attributes, associated with the [`AttributeGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt attributes, if no session key is available or using a session key may leak information.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct AttributeGlobalPublicKey<G: Group>(pub(crate) G::Element);

/// A global secret key for attributes from which session keys are derived.
#[derive(Copy, Clone)]
pub struct AttributeGlobalSecretKey<G: Group>(pub(crate) G::Scalar);

/// Session keys for both pseudonyms and attributes.
/// Organized by key type (pseudonym/attribute) rather than by public/secret.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct SessionKeys<G: Group> {
    /// The session key pair for pseudonyms.
    pub pseudonym: PseudonymSessionKeys<G>,
    /// The session key pair for attributes.
    pub attribute: AttributeSessionKeys<G>,
}

/// The public halves of [`SessionKeys`]: what a sender needs to encrypt towards a session, and what
/// a transcryptor needs to rerandomize ciphertexts encrypted for it.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct SessionPublicKeys<G: Group> {
    /// The session public key for pseudonyms.
    pub pseudonym: PseudonymSessionPublicKey<G>,
    /// The session public key for attributes.
    pub attribute: AttributeSessionPublicKey<G>,
}

impl<G: Group> SessionKeys<G> {
    /// The public keys of this session.
    pub fn public(&self) -> SessionPublicKeys<G> {
        SessionPublicKeys {
            pseudonym: self.pseudonym.public,
            attribute: self.attribute.public,
        }
    }
}

impl<G: Group> From<&SessionKeys<G>> for SessionPublicKeys<G> {
    fn from(keys: &SessionKeys<G>) -> Self {
        keys.public()
    }
}

/// A pseudonym session key pair containing both public and secret keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct PseudonymSessionKeys<G: Group> {
    /// The public key.
    pub public: PseudonymSessionPublicKey<G>,
    /// The secret key.
    pub secret: PseudonymSessionSecretKey<G>,
}

/// An attribute session key pair containing both public and secret keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct AttributeSessionKeys<G: Group> {
    /// The public key.
    pub public: AttributeSessionPublicKey<G>,
    /// The secret key.
    pub secret: AttributeSessionSecretKey<G>,
}

/// A session public key used to encrypt pseudonyms, associated with a [`PseudonymSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct PseudonymSessionPublicKey<G: Group>(pub(crate) G::Element);

/// A session secret key used to decrypt pseudonyms with.
#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct PseudonymSessionSecretKey<G: Group>(pub(crate) G::Scalar);

/// A session public key used to encrypt attributes, associated with a [`AttributeSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct AttributeSessionPublicKey<G: Group>(pub(crate) G::Element);

/// A session secret key used to decrypt attributes with.
#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct AttributeSessionSecretKey<G: Group>(pub(crate) G::Scalar);

redacted_debug!(
    PseudonymGlobalSecretKey<G>,
    AttributeGlobalSecretKey<G>,
    PseudonymSessionSecretKey<G>,
    AttributeSessionSecretKey<G>,
    GlobalSecretKeys<G>,
);

zeroize_fields!(
    PseudonymGlobalSecretKey<G> { 0 },
    AttributeGlobalSecretKey<G> { 0 },
    PseudonymSessionSecretKey<G> { 0 },
    AttributeSessionSecretKey<G> { 0 },
    GlobalSecretKeys<G> { pseudonym, attribute },
    PseudonymSessionKeys<G> { secret },
    AttributeSessionKeys<G> { secret },
    SessionKeys<G> { pseudonym, attribute },
);
