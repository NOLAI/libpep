//! Pseudonyms, attributes and their encrypted versions, generic over the [`Group`].

use crate::data::simple::{ElGamalEncryptable, ElGamalEncrypted};
use crate::data::traits::{Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
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
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "", transparent)
)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref)]
pub struct Pseudonym<G: Group> {
    /// The group element.
    pub value: G::Element,
}

/// An attribute (in the background, this is a group element), which should not be identifiable
/// and can be encrypted and rekeyed, but not reshuffled.
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "", transparent)
)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref)]
pub struct Attribute<G: Group> {
    /// The group element.
    pub value: G::Element,
}

/// An encrypted pseudonym, which is an [`ElGamal`] encryption of a [`Pseudonym`].
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "", transparent)
)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref)]
pub struct EncryptedPseudonym<G: Group> {
    /// The ciphertext.
    pub value: ElGamal<G>,
}

/// An encrypted attribute, which is an [`ElGamal`] encryption of an [`Attribute`].
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "", transparent)
)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref)]
pub struct EncryptedAttribute<G: Group> {
    /// The ciphertext.
    pub value: ElGamal<G>,
}

/// The encryption, decryption and rerandomization of a plaintext/ciphertext pair that is a single
/// group element and a single ElGamal ciphertext, under the given key types.
macro_rules! impl_simple_pair {
    ($plain:ident / $enc:ident, $pk:ident / $sk:ident, $gpk:ident / $gsk:ident) => {
        impl<G: Group> ElGamalEncryptable for $plain<G> {
            fn value(&self) -> &G::Element {
                &self.value
            }
            fn from_point(value: G::Element) -> Self {
                Self { value }
            }
        }

        impl<G: Group> ElGamalEncrypted for $enc<G> {
            fn value(&self) -> &ElGamal<G> {
                &self.value
            }
            fn from_value(value: ElGamal<G>) -> Self {
                Self { value }
            }
        }

        impl<G: Group> Encryptable for $plain<G> {
            type Group = G;
            type EncryptedType = $enc<G>;
            type PublicKeyType = $pk<G>;
            #[cfg(feature = "offline")]
            type GlobalPublicKeyType = $gpk<G>;

            fn encrypt<R>(&self, public_key: &$pk<G>, rng: &mut R) -> $enc<G>
            where
                R: Rng + CryptoRng,
            {
                $enc::from_value(crate::elgamal::generic::encrypt(
                    &self.value,
                    public_key.value(),
                    rng,
                ))
            }

            #[cfg(feature = "offline")]
            fn encrypt_global<R>(&self, public_key: &$gpk<G>, rng: &mut R) -> $enc<G>
            where
                R: Rng + CryptoRng,
            {
                $enc::from_value(crate::elgamal::generic::encrypt(
                    &self.value,
                    public_key.value(),
                    rng,
                ))
            }
        }

        impl<G: Group> Encrypted for $enc<G> {
            type Group = G;
            type UnencryptedType = $plain<G>;
            type SecretKeyType = $sk<G>;
            #[cfg(all(feature = "offline", feature = "insecure"))]
            type GlobalSecretKeyType = $gsk<G>;

            #[cfg(feature = "elgamal3")]
            fn decrypt(&self, secret_key: &$sk<G>) -> Option<$plain<G>> {
                crate::elgamal::generic::decrypt(&self.value, secret_key.value())
                    .map($plain::from_point)
            }

            #[cfg(not(feature = "elgamal3"))]
            fn decrypt(&self, secret_key: &$sk<G>) -> $plain<G> {
                $plain::from_point(crate::elgamal::generic::decrypt(
                    &self.value,
                    secret_key.value(),
                ))
            }

            #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
            fn decrypt_global(&self, secret_key: &$gsk<G>) -> Option<$plain<G>> {
                crate::elgamal::generic::decrypt(&self.value, secret_key.value())
                    .map($plain::from_point)
            }

            #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
            fn decrypt_global(&self, secret_key: &$gsk<G>) -> $plain<G> {
                $plain::from_point(crate::elgamal::generic::decrypt(
                    &self.value,
                    secret_key.value(),
                ))
            }

            #[cfg(feature = "elgamal3")]
            fn rerandomize<R>(&self, rng: &mut R) -> Self
            where
                R: Rng + CryptoRng,
            {
                self.rerandomize_known(&RerandomizeFactor(G::random_scalar(rng)))
            }

            #[cfg(not(feature = "elgamal3"))]
            fn rerandomize<R>(&self, public_key: &$pk<G>, rng: &mut R) -> Self
            where
                R: Rng + CryptoRng,
            {
                self.rerandomize_known(public_key, &RerandomizeFactor(G::random_scalar(rng)))
            }

            #[cfg(feature = "elgamal3")]
            fn rerandomize_known(&self, factor: &RerandomizeFactor<G>) -> Self {
                Self::from_value(crate::elgamal::primitives::rerandomize(
                    &self.value,
                    &factor.0,
                ))
            }

            #[cfg(not(feature = "elgamal3"))]
            fn rerandomize_known(
                &self,
                public_key: &$pk<G>,
                factor: &RerandomizeFactor<G>,
            ) -> Self {
                Self::from_value(crate::elgamal::primitives::rerandomize(
                    &self.value,
                    public_key.value(),
                    &factor.0,
                ))
            }
        }

        #[cfg(feature = "batch")]
        impl<G: Group> crate::data::traits::HasStructure for $enc<G> {
            type Structure = ();

            fn structure(&self) -> Self::Structure {}
        }
    };
}

impl_simple_pair!(
    Pseudonym / EncryptedPseudonym,
    PseudonymSessionPublicKey / PseudonymSessionSecretKey,
    PseudonymGlobalPublicKey / PseudonymGlobalSecretKey
);
impl_simple_pair!(
    Attribute / EncryptedAttribute,
    AttributeSessionPublicKey / AttributeSessionSecretKey,
    AttributeGlobalPublicKey / AttributeGlobalSecretKey
);

impl<G: Group> Pseudonymizable for EncryptedPseudonym<G> {
    fn pseudonymize_raw(&self, info: &PseudonymizationInfo<G>) -> Self {
        Self::from_value(crate::elgamal::primitives::rsk(
            &self.value,
            &info.s.0,
            &info.k.0,
        ))
    }
}

impl<G: Group> Rekeyable for EncryptedPseudonym<G> {
    type RekeyInfo = PseudonymRekeyInfo<G>;

    fn rekey_raw(&self, info: &Self::RekeyInfo) -> Self {
        Self::from_value(crate::elgamal::primitives::rekey(&self.value, &info.k.0))
    }
}

impl<G: Group> Rekeyable for EncryptedAttribute<G> {
    type RekeyInfo = AttributeRekeyInfo<G>;

    fn rekey_raw(&self, info: &Self::RekeyInfo) -> Self {
        Self::from_value(crate::elgamal::primitives::rekey(&self.value, &info.k.0))
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
