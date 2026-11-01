//! Core data types for pseudonyms and attributes, their encrypted versions,
//! and session-key based encryption and decryption operations.
//!
//! The [`ElGamalEncryptable`] and [`ElGamalEncrypted`] traits of [`data::elgamal`](crate::data::elgamal)
//! give access to the single group element or ciphertext behind these types, and to its encodings.

pub use crate::data::elgamal::{ElGamalEncryptable, ElGamalEncrypted};
use crate::data::traits::{Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::arithmetic::Ristretto255;
use crate::elgamal::ElGamal;
use crate::factors::types::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, RerandomizeFactor,
    TranscryptionInfo,
};
use crate::keys::traits::{PublicKey, SecretKey};
use crate::keys::types::*;
use derive_more::Deref;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A pseudonym (in the background, this is a group element) that can be used to identify a user
/// within a specific context, which can be encrypted, rekeyed and reshuffled.
///
/// Pseudonyms in different domains are unlinkable because
/// [reshuffling](crate::elgamal::primitives::reshuffle) obliviously evaluates the Diffie-Hellman
/// weak PRF on them. A weak PRF is pseudorandom only for uniformly random inputs, so origin
/// pseudonyms must be uniformly random ([`random`](ElGamalEncryptable::random)) or lizard-encoded
/// ([`from_lizard`](ElGamalEncryptable::from_lizard)), and not imported or constructed with known
/// discrete-log relations; see the security note on [`ElGamalEncryptable`].
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "", transparent)
)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref)]
pub struct Pseudonym<G: Group = Ristretto255> {
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
pub struct Attribute<G: Group = Ristretto255> {
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
pub struct EncryptedPseudonym<G: Group = Ristretto255> {
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
pub struct EncryptedAttribute<G: Group = Ristretto255> {
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
                $enc::from_value(crate::elgamal::encrypt(
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
                $enc::from_value(crate::elgamal::encrypt(
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
                crate::elgamal::decrypt(&self.value, secret_key.value()).map($plain::from_point)
            }

            #[cfg(not(feature = "elgamal3"))]
            fn decrypt(&self, secret_key: &$sk<G>) -> $plain<G> {
                $plain::from_point(crate::elgamal::decrypt(&self.value, secret_key.value()))
            }

            #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
            fn decrypt_global(&self, secret_key: &$gsk<G>) -> Option<$plain<G>> {
                crate::elgamal::decrypt(&self.value, secret_key.value()).map($plain::from_point)
            }

            #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
            fn decrypt_global(&self, secret_key: &$gsk<G>) -> $plain<G> {
                $plain::from_point(crate::elgamal::decrypt(&self.value, secret_key.value()))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::client::{decrypt, encrypt};
    use crate::contexts::EncryptionContext;
    use crate::data::simple::{ElGamalEncryptable, ElGamalEncrypted};
    use crate::elgamal::arithmetic::Ristretto255;
    use crate::factors::RekeyingSecret;
    use crate::keys::*;

    type Pseudonym = crate::data::simple::Pseudonym<Ristretto255>;
    type Attribute = crate::data::simple::Attribute<Ristretto255>;
    type EncryptedPseudonym = crate::data::simple::EncryptedPseudonym<Ristretto255>;
    #[cfg(feature = "serde")]
    type EncryptedAttribute = crate::data::simple::EncryptedAttribute<Ristretto255>;

    #[test]
    fn pseudonym_encode_decode() {
        let mut rng = rand::rng();
        let original = Pseudonym::random(&mut rng);
        let encoded = original.to_bytes();
        let decoded = Pseudonym::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn attribute_encode_decode() {
        let mut rng = rand::rng();
        let original = Attribute::random(&mut rng);
        let encoded = original.to_bytes();
        let decoded = Attribute::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn pseudonym_from_lizard_roundtrip() {
        let data = b"test identifier!";
        let pseudonym = Pseudonym::from_lizard(data);
        let decoded = pseudonym
            .to_lizard()
            .expect("lizard encoding should succeed");
        assert_eq!(decoded, *data);
    }

    #[test]
    fn attribute_from_lizard_roundtrip() {
        let data = b"some attribute!!";
        let attribute = Attribute::from_lizard(data);
        let decoded = attribute
            .to_lizard()
            .expect("lizard encoding should succeed");
        assert_eq!(decoded, *data);
    }

    #[test]
    fn pseudonym_hex_roundtrip() {
        let mut rng = rand::rng();
        let original = Pseudonym::random(&mut rng);
        let hex = original.to_hex();
        let decoded = Pseudonym::from_hex(&hex).expect("hex decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn encrypt_decrypt_pseudonym() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_pseudonym_global_keys(&mut rng);
        let rekeying_secret = RekeyingSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, session_secret) =
            make_pseudonym_session_keys(&global_secret, &session, &rekeying_secret);

        let original = Pseudonym::random(&mut rng);
        let encrypted = encrypt(&original, &session_public, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &session_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &session_secret);

        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypt_decrypt_attribute() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_attribute_global_keys(&mut rng);
        let rekeying_secret = RekeyingSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, session_secret) =
            make_attribute_session_keys(&global_secret, &session, &rekeying_secret);

        let original = Attribute::random(&mut rng);
        let encrypted = encrypt(&original, &session_public, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &session_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &session_secret);

        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypted_pseudonym_base64_roundtrip() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_pseudonym_global_keys(&mut rng);
        let rekeying_secret = RekeyingSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, _) =
            make_pseudonym_session_keys(&global_secret, &session, &rekeying_secret);

        let pseudonym = Pseudonym::random(&mut rng);
        let encrypted = encrypt(&pseudonym, &session_public, &mut rng);
        let base64 = encrypted.to_base64();
        let decoded =
            EncryptedPseudonym::from_base64(&base64).expect("base64 decoding should succeed");

        assert_eq!(decoded, encrypted);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn encrypted_attribute_serde_json() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_attribute_global_keys(&mut rng);
        let rekeying_secret = RekeyingSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, _) =
            make_attribute_session_keys(&global_secret, &session, &rekeying_secret);

        let attribute = Attribute::random(&mut rng);
        let encrypted = encrypt(&attribute, &session_public, &mut rng);
        let json = serde_json::to_string(&encrypted).expect("serialization should succeed");
        let deserialized: EncryptedAttribute =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(deserialized, encrypted);
    }

    #[test]
    fn polymorphic_encrypt_decrypt() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_pseudonym_global_keys(&mut rng);
        let rekeying_secret = RekeyingSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, session_secret) =
            make_pseudonym_session_keys(&global_secret, &session, &rekeying_secret);

        let original = Pseudonym::random(&mut rng);
        let encrypted = encrypt(&original, &session_public, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &session_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &session_secret);

        assert_eq!(decrypted, original);
    }
}
