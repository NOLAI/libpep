//! Long (multi-block) data types for pseudonyms and attributes, generic over the [`Group`].
//!
//! Encoding and padding need the group's [`InvertibleEncoding`]; encryption and transcryption
//! work over any [`Group`].
//!
//! # Padding
//!
//! Long values use PKCS#7 padding (internal padding) in their last block, and can be brought
//! to a fixed number of blocks with external padding ([`pad_to`](LongPseudonym::pad_to)) for
//! batch unlinkability. See the [`padding`](crate::data::padding) module.

use crate::data::padding::external::{create_external_padding_block, is_external_padding_block};
use crate::data::padding::internal::unpad_block;
use crate::data::padding::PaddingError;
use crate::data::simple::generic::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use crate::data::simple::{ElGamalEncryptable, ElGamalEncrypted};
use crate::data::traits::{Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::elgamal::arithmetic::group::{Bytes, Group, InvertibleEncoding};
use crate::errors::ParseError;
use crate::factors::types::generic::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, RerandomizeFactor,
    TranscryptionInfo,
};
#[cfg(feature = "offline")]
use crate::keys::types::generic::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::types::generic::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use crate::keys::types::generic::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey,
};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A pseudonym of more than one block: a sequence of [`Pseudonym`]s that together hold a longer
/// identifier, PKCS#7-padded in the last block.
///
/// # Privacy Warning
///
/// **The number of blocks of a `LongPseudonym` is visible and may reveal the length of the
/// identifier.** Consider padding identifiers to a fixed size, or use [`pad_to`](Self::pad_to)
/// for batches.
///
/// Reshuffling applies to every block separately, so **pseudonyms that share a block are
/// linkable**: in
///
/// ```no_run
/// use libpep::data::long::LongPseudonym;
///
/// let long_pseudo = LongPseudonym::from_string_padded("some-long-identifier1@example.com");
/// ```
///
/// the second block is `"@example.com"` plus padding, and every other identifier ending in
/// `"@example.com"` shares it in every domain.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongPseudonym<G: Group>(pub Vec<Pseudonym<G>>);

/// An attribute of more than one block: a sequence of [`Attribute`]s that together hold a longer
/// value, PKCS#7-padded in the last block.
///
/// # Privacy Warning
///
/// **The number of blocks of a `LongAttribute` is visible and may reveal the length of the
/// value.** Consider padding values to a fixed size, or use [`pad_to`](Self::pad_to) for
/// batches.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongAttribute<G: Group>(pub Vec<Attribute<G>>);

/// An encrypted [`LongPseudonym`]: one [`EncryptedPseudonym`] per block.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongEncryptedPseudonym<G: Group>(pub Vec<EncryptedPseudonym<G>>);

/// An encrypted [`LongAttribute`]: one [`EncryptedAttribute`] per block.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongEncryptedAttribute<G: Group>(pub Vec<EncryptedAttribute<G>>);

/// The encodings, encryption, decryption and rerandomization of a long plaintext/ciphertext
/// pair, block by block, under the given key types.
macro_rules! impl_long_pair {
    ($plain:ident / $enc:ident, $block:ident / $enc_block:ident, $pk:ident / $sk:ident, $gpk:ident / $gsk:ident) => {
        impl<G: InvertibleEncoding> $plain<G> {
            /// Encode bytes of any length, PKCS#7-padded in the last block.
            ///
            /// # Privacy Warning
            ///
            /// The number of blocks follows the length of the data and may reveal it.
            pub fn from_bytes_padded(data: &[u8]) -> Self {
                Self(from_bytes_padded_impl::<$block<G>>(data))
            }

            /// Encode a string of any length, PKCS#7-padded in the last block.
            ///
            /// # Privacy Warning
            ///
            /// The number of blocks follows the length of the string and may reveal it.
            pub fn from_string_padded(text: &str) -> Self {
                Self::from_bytes_padded(text.as_bytes())
            }

            /// Decode to the original string.
            ///
            /// # Errors
            ///
            /// Returns an error if the value has no blocks, is not padded, or is not UTF-8.
            pub fn to_string_padded(&self) -> Result<String, PaddingError> {
                Ok(String::from_utf8(self.to_bytes_padded()?)?)
            }

            /// Decode to the original bytes, removing external and PKCS#7 padding.
            ///
            /// # Errors
            ///
            /// Returns an error if the value has no blocks or is not padded.
            pub fn to_bytes_padded(&self) -> Result<Vec<u8>, PaddingError> {
                to_bytes_padded_impl(&self.0)
            }

            /// The hexadecimal encoding of all blocks, for values that are not valid UTF-8
            /// (such as pseudonyms transcrypted to another domain).
            pub fn to_hex(&self) -> String {
                self.0.iter().map(|block| block.to_hex()).collect()
            }

            /// Pad with all-zero external padding blocks to `target_blocks` blocks, so that
            /// values in a batch share one structure. The padding is removed on decoding.
            ///
            /// # Errors
            ///
            /// Returns an error if the value already has more than `target_blocks` blocks.
            pub fn pad_to(&self, target_blocks: usize) -> Result<Self, PaddingError> {
                let current = self.0.len();
                if current > target_blocks {
                    return Err(PaddingError::TooManyBlocks {
                        current,
                        target: target_blocks,
                    });
                }
                let padding_block =
                    $block::from_lizard(&create_external_padding_block::<G::Block>());
                let mut blocks = self.0.clone();
                blocks.resize(target_blocks, padding_block);
                Ok(Self(blocks))
            }
        }

        impl<G: Group> $enc<G> {
            /// Encode as the base64 encodings of the blocks, joined with `|`.
            pub fn serialize(&self) -> String {
                self.0
                    .iter()
                    .map(|item| item.to_base64())
                    .collect::<Vec<_>>()
                    .join("|")
            }

            /// Decode the format of [`serialize`](Self::serialize); the empty string is the
            /// value without blocks.
            ///
            /// # Errors
            ///
            /// Returns an error if a part is not a base64-encoded ciphertext.
            pub fn deserialize(s: &str) -> Result<Self, ParseError> {
                if s.is_empty() {
                    return Ok(Self(vec![]));
                }
                s.split('|')
                    .map(|part| {
                        $enc_block::from_base64(part)
                            .ok_or_else(|| ParseError::InvalidCiphertext(part.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Self)
            }
        }

        #[cfg(feature = "serde")]
        impl<G: Group> Serialize for $enc<G> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.serialize())
            }
        }

        #[cfg(feature = "serde")]
        impl<'de, G: Group> Deserialize<'de> for $enc<G> {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::deserialize(&s).map_err(serde::de::Error::custom)
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
                $enc(
                    self.0
                        .iter()
                        .map(|block| block.encrypt(public_key, rng))
                        .collect(),
                )
            }

            #[cfg(feature = "offline")]
            fn encrypt_global<R>(&self, public_key: &$gpk<G>, rng: &mut R) -> $enc<G>
            where
                R: Rng + CryptoRng,
            {
                $enc(
                    self.0
                        .iter()
                        .map(|block| block.encrypt_global(public_key, rng))
                        .collect(),
                )
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
                self.0
                    .iter()
                    .map(|block| block.decrypt(secret_key))
                    .collect::<Option<Vec<_>>>()
                    .map($plain)
            }

            #[cfg(not(feature = "elgamal3"))]
            fn decrypt(&self, secret_key: &$sk<G>) -> $plain<G> {
                $plain(
                    self.0
                        .iter()
                        .map(|block| block.decrypt(secret_key))
                        .collect(),
                )
            }

            #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
            fn decrypt_global(&self, secret_key: &$gsk<G>) -> Option<$plain<G>> {
                self.0
                    .iter()
                    .map(|block| block.decrypt_global(secret_key))
                    .collect::<Option<Vec<_>>>()
                    .map($plain)
            }

            #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
            fn decrypt_global(&self, secret_key: &$gsk<G>) -> $plain<G> {
                $plain(
                    self.0
                        .iter()
                        .map(|block| block.decrypt_global(secret_key))
                        .collect(),
                )
            }

            /// Every block gets its own factor: with one factor the differences between the
            /// blocks would survive transcryption and link the value to its input.
            #[cfg(feature = "elgamal3")]
            fn rerandomize<R>(&self, rng: &mut R) -> Self
            where
                R: Rng + CryptoRng,
            {
                Self(self.0.iter().map(|block| block.rerandomize(rng)).collect())
            }

            /// Every block gets its own factor: with one factor the differences between the
            /// blocks would survive transcryption and link the value to its input.
            #[cfg(not(feature = "elgamal3"))]
            fn rerandomize<R>(&self, public_key: &$pk<G>, rng: &mut R) -> Self
            where
                R: Rng + CryptoRng,
            {
                Self(
                    self.0
                        .iter()
                        .map(|block| block.rerandomize(public_key, rng))
                        .collect(),
                )
            }

            #[cfg(feature = "elgamal3")]
            fn rerandomize_known(&self, factor: &RerandomizeFactor<G>) -> Self {
                Self(
                    self.0
                        .iter()
                        .map(|block| block.rerandomize_known(factor))
                        .collect(),
                )
            }

            #[cfg(not(feature = "elgamal3"))]
            fn rerandomize_known(
                &self,
                public_key: &$pk<G>,
                factor: &RerandomizeFactor<G>,
            ) -> Self {
                Self(
                    self.0
                        .iter()
                        .map(|block| block.rerandomize_known(public_key, factor))
                        .collect(),
                )
            }
        }

        #[cfg(feature = "batch")]
        impl<G: Group> crate::data::traits::HasStructure for $enc<G> {
            type Structure = usize;

            fn structure(&self) -> Self::Structure {
                self.0.len()
            }
        }
    };
}

impl_long_pair!(
    LongPseudonym / LongEncryptedPseudonym,
    Pseudonym / EncryptedPseudonym,
    PseudonymSessionPublicKey / PseudonymSessionSecretKey,
    PseudonymGlobalPublicKey / PseudonymGlobalSecretKey
);
impl_long_pair!(
    LongAttribute / LongEncryptedAttribute,
    Attribute / EncryptedAttribute,
    AttributeSessionPublicKey / AttributeSessionSecretKey,
    AttributeGlobalPublicKey / AttributeGlobalSecretKey
);

// Transcryption applies the same factors to every block, so the scalar inversions are done
// once per value rather than once per block.

impl<G: Group> Pseudonymizable for LongEncryptedPseudonym<G> {
    fn pseudonymize_raw(&self, info: &PseudonymizationInfo<G>) -> Self {
        let ski = info.s.0 * G::scalar_inverse(&info.k.0);
        Self(
            self.0
                .iter()
                .map(|block| {
                    #[cfg(feature = "elgamal3")]
                    let value = crate::elgamal::primitives::rsk_precomputed(
                        block.value(),
                        &info.s.0,
                        &info.k.0,
                        &ski,
                    );
                    #[cfg(not(feature = "elgamal3"))]
                    let value =
                        crate::elgamal::primitives::rsk_precomputed(block.value(), &info.s.0, &ski);
                    EncryptedPseudonym::from_value(value)
                })
                .collect(),
        )
    }
}

/// Rekey every block with the inverse computed once.
fn rekey_blocks<G: Group, E: ElGamalEncrypted<Group = G>>(blocks: &[E], k: &G::Scalar) -> Vec<E> {
    let k_inv = G::scalar_inverse(k);
    blocks
        .iter()
        .map(|block| {
            #[cfg(feature = "elgamal3")]
            let value = crate::elgamal::primitives::rekey_precomputed(block.value(), k, &k_inv);
            #[cfg(not(feature = "elgamal3"))]
            let value = crate::elgamal::primitives::rekey_precomputed(block.value(), &k_inv);
            E::from_value(value)
        })
        .collect()
}

impl<G: Group> Rekeyable for LongEncryptedPseudonym<G> {
    type RekeyInfo = PseudonymRekeyInfo<G>;

    fn rekey_raw(&self, info: &Self::RekeyInfo) -> Self {
        Self(rekey_blocks(&self.0, &info.k.0))
    }
}

impl<G: Group> Rekeyable for LongEncryptedAttribute<G> {
    type RekeyInfo = AttributeRekeyInfo<G>;

    fn rekey_raw(&self, info: &Self::RekeyInfo) -> Self {
        Self(rekey_blocks(&self.0, &info.k.0))
    }
}

impl<G: Group> Transcryptable for LongEncryptedPseudonym<G> {
    fn transcrypt_raw(&self, info: &TranscryptionInfo<G>) -> Self {
        self.pseudonymize_raw(&info.pseudonym)
    }
}

impl<G: Group> Transcryptable for LongEncryptedAttribute<G> {
    fn transcrypt_raw(&self, info: &TranscryptionInfo<G>) -> Self {
        self.rekey_raw(&info.attribute)
    }
}

/// Split `data` into blocks, PKCS#7-padding the last one; empty data is one block of padding.
fn from_bytes_padded_impl<T: ElGamalEncryptable>(data: &[u8]) -> Vec<T>
where
    T::Group: InvertibleEncoding,
{
    let block_length = <T::Group as InvertibleEncoding>::BLOCK_LENGTH;
    let full_blocks = data.len() / block_length;
    let remaining = data.len() % block_length;

    let mut result = Vec::with_capacity(full_blocks + 1);
    for chunk in data[..full_blocks * block_length].chunks(block_length) {
        let mut block = <T::Group as InvertibleEncoding>::Block::zeroed();
        block.as_mut().copy_from_slice(chunk);
        result.push(T::from_lizard(&block));
    }

    let mut last_block = <T::Group as InvertibleEncoding>::Block::zeroed();
    last_block.as_mut().fill((block_length - remaining) as u8);
    last_block.as_mut()[..remaining].copy_from_slice(&data[full_blocks * block_length..]);
    result.push(T::from_lizard(&last_block));

    result
}

/// Join the blocks, dropping trailing external (all-zero) padding blocks and the PKCS#7 padding
/// of the last data block.
fn to_bytes_padded_impl<T: ElGamalEncryptable>(items: &[T]) -> Result<Vec<u8>, PaddingError>
where
    T::Group: InvertibleEncoding,
{
    if items.is_empty() {
        return Err(PaddingError::Empty);
    }
    let blocks = items
        .iter()
        .map(|item| item.to_lizard().ok_or(PaddingError::NotEncoded))
        .collect::<Result<Vec<_>, _>>()?;

    // External padding is never the first block: an all-zero first block is data.
    let mut last = blocks.len() - 1;
    while last > 0
        && is_external_padding_block::<<T::Group as InvertibleEncoding>::Block>(
            blocks[last].as_ref(),
        )
    {
        last -= 1;
    }

    let mut result =
        Vec::with_capacity((last + 1) * <T::Group as InvertibleEncoding>::BLOCK_LENGTH);
    for block in &blocks[..last] {
        result.extend_from_slice(block.as_ref());
    }
    result.extend_from_slice(&unpad_block(blocks[last].as_ref())?);
    Ok(result)
}
