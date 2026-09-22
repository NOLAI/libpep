//! Pseudonyms, attributes and their encrypted versions, generic over the [`Group`].

use crate::data::simple::{ElGamalEncryptable, ElGamalEncrypted};
#[cfg(feature = "batch")]
use crate::data::traits::BatchEncryptable;
use crate::data::traits::{Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
#[cfg(feature = "batch")]
use crate::errors::BatchError;
use crate::factors::types::generic::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, RerandomizeFactor,
    TranscryptionInfo,
};
use crate::keys::traits::{PublicKey, SecretKey};
use crate::keys::types::generic::*;
use derive_more::Deref;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A pseudonym (in the background, this is a group element) that can be used to identify a user
/// within a specific context, which can be encrypted, rekeyed and reshuffled.
///
/// Pseudonyms in different domains are unlinkable because
/// [reshuffling](crate::elgamal::primitives::reshuffle) obliviously evaluates the Diffie-Hellman PRF
/// on them. This requires origin pseudonyms to be uniformly random or lizard-encoded; see the
/// security note on [`ElGamalEncryptable`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref)]
pub struct Pseudonym<G: Group> {
    pub value: G::Element,
}
/// An attribute (in the background, this is a group element), which should not be identifiable
/// and can be encrypted and rekeyed, but not reshuffled.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref)]
pub struct Attribute<G: Group> {
    pub value: G::Element,
}
/// An encrypted pseudonym, which is an [`ElGamal`] encryption of a [`Pseudonym`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref)]
pub struct EncryptedPseudonym<G: Group> {
    pub value: ElGamal<G>,
}
/// An encrypted attribute, which is an [`ElGamal`] encryption of an [`Attribute`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref)]
pub struct EncryptedAttribute<G: Group> {
    pub value: ElGamal<G>,
}

impl<G: Group> Encryptable for Pseudonym<G> {
    type Group = G;
    type EncryptedType = EncryptedPseudonym<G>;
    type PublicKeyType = PseudonymSessionPublicKey<G>;
    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = PseudonymGlobalPublicKey<G>;

    fn encrypt<R>(&self, public_key: &Self::PublicKeyType, rng: &mut R) -> Self::EncryptedType
    where
        R: Rng + CryptoRng,
    {
        EncryptedPseudonym::from_value(crate::elgamal::generic::encrypt(
            self.value(),
            public_key.value(),
            rng,
        ))
    }

    #[cfg(feature = "offline")]
    fn encrypt_global<R>(
        &self,
        public_key: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType
    where
        R: Rng + CryptoRng,
    {
        EncryptedPseudonym::from_value(crate::elgamal::generic::encrypt(
            self.value(),
            public_key.value(),
            rng,
        ))
    }
}

impl<G: Group> Encryptable for Attribute<G> {
    type Group = G;
    type EncryptedType = EncryptedAttribute<G>;
    type PublicKeyType = AttributeSessionPublicKey<G>;
    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = AttributeGlobalPublicKey<G>;

    fn encrypt<R>(&self, public_key: &Self::PublicKeyType, rng: &mut R) -> Self::EncryptedType
    where
        R: Rng + CryptoRng,
    {
        EncryptedAttribute::from_value(crate::elgamal::generic::encrypt(
            self.value(),
            public_key.value(),
            rng,
        ))
    }

    #[cfg(feature = "offline")]
    fn encrypt_global<R>(
        &self,
        public_key: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType
    where
        R: Rng + CryptoRng,
    {
        EncryptedAttribute::from_value(crate::elgamal::generic::encrypt(
            self.value(),
            public_key.value(),
            rng,
        ))
    }
}

impl<G: Group> ElGamalEncryptable for Pseudonym<G> {
    fn value(&self) -> &G::Element {
        &self.value
    }
    fn from_value(value: G::Element) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}

impl<G: Group> ElGamalEncryptable for Attribute<G> {
    fn value(&self) -> &G::Element {
        &self.value
    }
    fn from_value(value: G::Element) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}

impl<G: Group> Encrypted for EncryptedPseudonym<G> {
    type Group = G;
    type UnencryptedType = Pseudonym<G>;
    type SecretKeyType = PseudonymSessionSecretKey<G>;
    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = PseudonymGlobalSecretKey<G>;

    #[cfg(feature = "elgamal3")]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Option<Self::UnencryptedType> {
        crate::elgamal::generic::decrypt(self.value(), secret_key.value())
            .map(Pseudonym::from_value)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Self::UnencryptedType {
        Pseudonym::from_value(crate::elgamal::generic::decrypt(
            self.value(),
            secret_key.value(),
        ))
    }

    #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
    fn decrypt_global(
        &self,
        secret_key: &Self::GlobalSecretKeyType,
    ) -> Option<Self::UnencryptedType> {
        crate::elgamal::generic::decrypt(self.value(), secret_key.value())
            .map(Pseudonym::from_value)
    }

    #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
    fn decrypt_global(&self, secret_key: &Self::GlobalSecretKeyType) -> Self::UnencryptedType {
        Pseudonym::from_value(crate::elgamal::generic::decrypt(
            self.value(),
            secret_key.value(),
        ))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize<R>(&self, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let r = G::random_scalar(rng);
        self.rerandomize_known(&RerandomizeFactor(r))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let r = G::random_scalar(rng);
        self.rerandomize_known(public_key, &RerandomizeFactor(r))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor<G>) -> Self {
        EncryptedPseudonym::from_value(crate::elgamal::primitives::rerandomize(
            self.value(),
            &factor.0,
        ))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize_known(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        factor: &RerandomizeFactor<G>,
    ) -> Self {
        EncryptedPseudonym::from_value(crate::elgamal::primitives::rerandomize(
            self.value(),
            public_key.value(),
            &factor.0,
        ))
    }
}

impl<G: Group> Encrypted for EncryptedAttribute<G> {
    type Group = G;
    type UnencryptedType = Attribute<G>;
    type SecretKeyType = AttributeSessionSecretKey<G>;
    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = AttributeGlobalSecretKey<G>;

    #[cfg(feature = "elgamal3")]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Option<Self::UnencryptedType> {
        crate::elgamal::generic::decrypt(self.value(), secret_key.value())
            .map(Attribute::from_value)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Self::UnencryptedType {
        Attribute::from_value(crate::elgamal::generic::decrypt(
            self.value(),
            secret_key.value(),
        ))
    }

    #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
    fn decrypt_global(
        &self,
        secret_key: &Self::GlobalSecretKeyType,
    ) -> Option<Self::UnencryptedType> {
        crate::elgamal::generic::decrypt(self.value(), secret_key.value())
            .map(Attribute::from_value)
    }

    #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
    fn decrypt_global(&self, secret_key: &Self::GlobalSecretKeyType) -> Self::UnencryptedType {
        Attribute::from_value(crate::elgamal::generic::decrypt(
            self.value(),
            secret_key.value(),
        ))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize<R>(&self, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let r = G::random_scalar(rng);
        self.rerandomize_known(&RerandomizeFactor(r))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let r = G::random_scalar(rng);
        self.rerandomize_known(public_key, &RerandomizeFactor(r))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor<G>) -> Self {
        EncryptedAttribute::from_value(crate::elgamal::primitives::rerandomize(
            self.value(),
            &factor.0,
        ))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize_known(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        factor: &RerandomizeFactor<G>,
    ) -> Self {
        EncryptedAttribute::from_value(crate::elgamal::primitives::rerandomize(
            self.value(),
            public_key.value(),
            &factor.0,
        ))
    }
}

impl<G: Group> ElGamalEncrypted for EncryptedPseudonym<G> {
    type UnencryptedType = Pseudonym<G>;

    fn value(&self) -> &ElGamal<G> {
        &self.value
    }
    fn from_value(value: ElGamal<G>) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}
impl<G: Group> ElGamalEncrypted for EncryptedAttribute<G> {
    type UnencryptedType = Attribute<G>;

    fn value(&self) -> &ElGamal<G> {
        &self.value
    }
    fn from_value(value: ElGamal<G>) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}

// Transcryption trait implementations

impl<G: Group> Pseudonymizable for EncryptedPseudonym<G> {
    fn pseudonymize_raw(&self, info: &PseudonymizationInfo<G>) -> Self {
        EncryptedPseudonym::from_value(crate::elgamal::primitives::rsk(
            self.value(),
            &info.s.0,
            &info.k.0,
        ))
    }
}

impl<G: Group> Rekeyable for EncryptedPseudonym<G> {
    type RekeyInfo = PseudonymRekeyInfo<G>;

    fn rekey_raw(&self, info: &Self::RekeyInfo) -> Self {
        EncryptedPseudonym::from_value(crate::elgamal::primitives::rekey(self.value(), &info.k.0))
    }
}

impl<G: Group> Rekeyable for EncryptedAttribute<G> {
    type RekeyInfo = AttributeRekeyInfo<G>;

    fn rekey_raw(&self, info: &Self::RekeyInfo) -> Self {
        EncryptedAttribute::from_value(crate::elgamal::primitives::rekey(self.value(), &info.k.0))
    }
}

impl<G: Group> Transcryptable for EncryptedPseudonym<G> {
    fn transcrypt_raw(&self, info: &TranscryptionInfo<G>) -> Self {
        self.pseudonymize_raw(&info.pseudonym)
    }
}

impl<G: Group> Transcryptable for EncryptedAttribute<G> {
    fn transcrypt_raw(&self, info: &TranscryptionInfo<G>) -> Self {
        self.rekey_raw(&info.attribute)
    }
}
#[cfg(feature = "batch")]
impl<G: Group> crate::data::traits::HasStructure for EncryptedPseudonym<G> {
    type Structure = ();

    fn structure(&self) -> Self::Structure {}
}

#[cfg(feature = "batch")]
impl<G: Group> crate::data::traits::HasStructure for EncryptedAttribute<G> {
    type Structure = ();

    fn structure(&self) -> Self::Structure {}
}

#[cfg(feature = "batch")]
#[cfg(feature = "batch")]
impl<G: Group> BatchEncryptable for Pseudonym<G> {
    fn preprocess_batch(items: &[Self]) -> Result<Vec<Self>, BatchError> {
        Ok(items.to_vec())
    }
}

#[cfg(feature = "batch")]
#[cfg(feature = "batch")]
impl<G: Group> BatchEncryptable for Attribute<G> {
    fn preprocess_batch(items: &[Self]) -> Result<Vec<Self>, BatchError> {
        Ok(items.to_vec())
    }
}
