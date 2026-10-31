//! Long (multi-block) data types for pseudonyms and attributes.
//!
//! A long value is a sequence of blocks, one group element each (16 bytes of data per block on
//! ristretto255).
//!
//! # Padding
//!
//! Long values use PKCS#7 padding (internal padding) in their last block, and can be brought
//! to a fixed number of blocks with external padding ([`pad_to`](LongPseudonym::pad_to)) for
//! batch unlinkability. See the [`padding`](crate::data::padding) module.
//!
//! The types are generic over the [`Group`].

use crate::data::elgamal::{ElGamalEncryptable, ElGamalEncrypted};
pub use crate::data::errors::ParseError;
use crate::data::padding::external::{create_external_padding_block, is_external_padding_block};
use crate::data::padding::internal::unpad_block;
use crate::data::padding::PaddingError;
use crate::data::simple::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use crate::data::traits::{Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::elgamal::arithmetic::group::{Bytes, Group, InvertibleEncoding};
use crate::factors::types::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, RerandomizeFactor,
    TranscryptionInfo,
};
#[cfg(feature = "offline")]
use crate::keys::types::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::types::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use crate::keys::types::{
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
/// # Privacy warning
///
/// The number of blocks of a `LongPseudonym` is visible and may reveal the length of the
/// identifier. Consider padding identifiers to a fixed size, or use [`pad_to`](Self::pad_to)
/// for batches.
///
/// Reshuffling applies to every block separately, so pseudonyms that share a block are
/// linkable: in
///
/// ```
/// use libpep::data::long::LongPseudonym;
/// use libpep::elgamal::arithmetic::Ristretto255;
///
/// let long_pseudo = LongPseudonym::<Ristretto255>::from_string_padded("some-identifier1@example.com");
/// assert_eq!(long_pseudo.len(), 2);
/// ```
///
/// the second block is `"@example.com"` plus padding, and every other identifier ending in
/// `"@example.com"` shares it in every domain.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongPseudonym<G: Group>(pub Vec<Pseudonym<G>>);

/// An attribute of more than one block: a sequence of [`Attribute`]s that together hold a longer
/// value, PKCS#7-padded in the last block.
///
/// # Privacy warning
///
/// The number of blocks of a `LongAttribute` is visible and may reveal the length of the
/// value. Consider padding values to a fixed size, or use [`pad_to`](Self::pad_to) for
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
            /// # Privacy warning
            ///
            /// The number of blocks follows the length of the data and may reveal it.
            pub fn from_bytes_padded(data: &[u8]) -> Self {
                Self(from_bytes_padded_impl::<$block<G>>(data))
            }

            /// Encode a string of any length, PKCS#7-padded in the last block.
            ///
            /// # Privacy warning
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::client::encrypt;
    use crate::contexts::EncryptionContext;
    use crate::data::elgamal::ElGamalEncryptable;
    use crate::data::errors::ParseError;
    use crate::data::padding::PaddingError;
    use crate::elgamal::arithmetic::Ristretto255;
    use crate::elgamal::arithmetic::Ristretto255Sha512;
    use crate::factors::EncryptionSecret;
    use crate::keys::{
        make_attribute_global_keys, make_attribute_session_keys, make_pseudonym_global_keys,
        make_pseudonym_session_keys,
    };

    type Pseudonym = crate::data::simple::Pseudonym<Ristretto255>;
    type Attribute = crate::data::simple::Attribute<Ristretto255>;
    type EncryptedPseudonym = crate::data::simple::EncryptedPseudonym<Ristretto255>;
    type LongPseudonym = crate::data::long::LongPseudonym<Ristretto255>;
    type LongAttribute = crate::data::long::LongAttribute<Ristretto255>;
    type LongEncryptedPseudonym = crate::data::long::LongEncryptedPseudonym<Ristretto255>;
    type LongEncryptedAttribute = crate::data::long::LongEncryptedAttribute<Ristretto255>;

    #[test]
    fn long_attribute_from_bytes_padded_empty() {
        let data: &[u8] = &[];
        let result = LongAttribute::from_bytes_padded(data);
        // Empty data should still result in one block with full padding (PKCS#7)
        assert_eq!(result.len(), 1);
        // The block should be all padding bytes with value 16
        let block_bytes = result[0].to_lizard().unwrap();
        assert_eq!([16u8; 16], block_bytes);
    }

    #[test]
    fn long_attribute_from_bytes_padded_single_block() {
        let data = b"Hello, world!";
        let result = LongAttribute::from_bytes_padded(data);

        assert_eq!(1, result.len());

        // The padding should be 3 bytes of value 3
        let bytes = result[0].to_lizard().unwrap();
        assert_eq!(b"Hello, world!\x03\x03\x03", &bytes);
    }

    #[test]
    fn long_attribute_from_bytes_padded_exact_block() {
        let data = b"0123456789ABCDEF";
        let result = LongAttribute::from_bytes_padded(data);

        // Should have 2 blocks: the 16 bytes of data and one full block of padding
        assert_eq!(2, result.len());

        // The first block is the input itself.
        assert_eq!(b"0123456789ABCDEF", &result[0].to_lizard().unwrap());

        // Second block should be all padding bytes with value 16
        let expected_padding = [16u8; 16];
        assert_eq!(expected_padding, result[1].to_lizard().unwrap());
    }

    #[test]
    fn long_attribute_from_bytes_padded_multiple_blocks() {
        let data = b"This is a longer string that spans multiple blocks";
        let result = LongAttribute::from_bytes_padded(data);

        // Calculate expected number of blocks (51 bytes -> 4 blocks)
        let expected_blocks = (data.len() / 16) + 1;
        assert_eq!(expected_blocks, result.len());

        // Check the content of each full block
        for (i, block) in result.iter().enumerate().take(data.len() / 16) {
            let start = i * 16;
            let expected = data[start..start + 16].to_vec();
            assert_eq!(expected, block.to_lizard().unwrap()[..16]);
        }

        // Check the last block's padding
        let last_block = result.last().unwrap().to_lizard().unwrap();
        let remaining = data.len() % 16;
        let padding_byte = (16 - remaining) as u8;

        // Verify data portion
        assert_eq!(&data[data.len() - remaining..], &last_block[..remaining]);

        // Verify padding portion
        for byte in last_block.iter().skip(remaining) {
            assert_eq!(&padding_byte, byte);
        }
    }

    #[test]
    fn long_attribute_to_bytes_padded() {
        let original = b"This is some test data for padding";
        let attributes = LongAttribute::from_bytes_padded(original);
        let decoded = attributes.to_bytes_padded().unwrap();
        assert_eq!(original, decoded.as_slice());
    }

    #[test]
    fn long_attribute_to_bytes_padded_empty() {
        let attributes = LongAttribute::from(vec![]);
        let result = attributes.to_bytes_padded();

        assert_eq!(result.unwrap_err(), PaddingError::Empty);
    }

    #[test]
    fn long_attribute_to_bytes_padded_invalid_padding() {
        // Create an Attribute with invalid padding (padding byte = 0)
        let invalid_block = [0u8; 16];
        let attribute = Attribute::from_lizard(&invalid_block);
        let long_attr = LongAttribute::from(vec![attribute]);

        let result = long_attr.to_bytes_padded();
        assert_eq!(result.unwrap_err(), PaddingError::InvalidPadding);

        // Try with inconsistent padding
        let mut inconsistent_block = [5u8; 16];
        inconsistent_block[15] = 6;
        let attribute = Attribute::from_lizard(&inconsistent_block);
        let long_attr = LongAttribute::from(vec![attribute]);

        let result = long_attr.to_bytes_padded();
        assert!(result.is_err());
    }

    #[test]
    fn long_attribute_to_string_padded() {
        let original = "This is a UTF-8 string with special chars: ñáéíóú 你好";
        let attributes = LongAttribute::from_string_padded(original);
        let decoded = attributes.to_string_padded().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn long_attribute_to_string_padded_invalid_utf8() {
        // Create data points with non-UTF8 data
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let mut block = [0u8; 16];
        block[..3].copy_from_slice(&invalid_utf8);
        block[3..].fill(13); // Padding

        let attribute = Attribute::from_lizard(&block);
        let long_attr = LongAttribute::from(vec![attribute]);

        let result = long_attr.to_string_padded();
        assert!(result.is_err());
    }

    #[test]
    fn long_attribute_roundtrip_all_padding_sizes() {
        for padding_size in 1..=16 {
            let size = 32 - padding_size;
            let data = vec![b'X'; size];

            let attributes = LongAttribute::from_bytes_padded(&data);
            let decoded = attributes.to_bytes_padded().unwrap();

            assert_eq!(data, decoded);
        }
    }

    #[test]
    fn long_pseudonym_from_bytes_padded() {
        let data = b"Hello, world!";
        let result = LongPseudonym::from_bytes_padded(data);

        assert_eq!(1, result.len());

        let bytes = result[0].to_lizard().unwrap();
        assert_eq!(b"Hello, world!\x03\x03\x03", &bytes);
    }

    #[test]
    fn long_pseudonym_to_bytes_padded() {
        let original = b"This is some test data for padding";
        let pseudonyms = LongPseudonym::from_bytes_padded(original);
        let decoded = pseudonyms.to_bytes_padded().unwrap();
        assert_eq!(original, decoded.as_slice());
    }

    #[test]
    fn long_pseudonym_string_roundtrip() {
        let original = "Testing pseudonym string conversion";
        let pseudonyms = LongPseudonym::from_string_padded(original);
        let decoded = pseudonyms.to_string_padded().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn long_encrypted_pseudonym_serialize_deserialize() {
        let mut rng = rand::rng();
        let (session_public, _session_secret) = make_pseudonym_session_keys::<Ristretto255Sha512>(
            &make_pseudonym_global_keys::<Ristretto255, _>(&mut rng).1,
            &EncryptionContext::from("session-1"),
            &EncryptionSecret::from("enc-secret".as_bytes().to_vec()),
        );

        let pseudonyms = LongPseudonym::from_string_padded("test-data-for-serialization");
        let encrypted: Vec<EncryptedPseudonym> = pseudonyms
            .iter()
            .map(|p| encrypt(p, &session_public, &mut rng))
            .collect();
        let long_encrypted = LongEncryptedPseudonym::from(encrypted);

        let serialized = long_encrypted.serialize();
        assert!(serialized.contains('|'));

        let deserialized = LongEncryptedPseudonym::deserialize(&serialized).unwrap();
        assert_eq!(long_encrypted.len(), deserialized.len());

        for (original, restored) in long_encrypted.iter().zip(deserialized.iter()) {
            assert_eq!(original, restored);
        }
    }

    #[test]
    fn long_encrypted_attribute_serialize_deserialize() {
        let mut rng = rand::rng();
        let (session_public, _session_secret) = make_attribute_session_keys::<Ristretto255Sha512>(
            &make_attribute_global_keys::<Ristretto255, _>(&mut rng).1,
            &EncryptionContext::from("session-1"),
            &EncryptionSecret::from("enc-secret".as_bytes().to_vec()),
        );

        let attributes = LongAttribute::from_string_padded("attribute-test-data");
        let encrypted: Vec<_> = attributes
            .iter()
            .map(|a| encrypt(a, &session_public, &mut rng))
            .collect();
        let long_encrypted = LongEncryptedAttribute::from(encrypted);

        let serialized = long_encrypted.serialize();
        assert!(serialized.contains('|'));

        let deserialized = LongEncryptedAttribute::deserialize(&serialized).unwrap();
        assert_eq!(long_encrypted.len(), deserialized.len());

        for (original, restored) in long_encrypted.iter().zip(deserialized.iter()) {
            assert_eq!(original, restored);
        }
    }

    #[test]
    fn long_encrypted_empty_roundtrip() {
        let empty_pseudo = super::LongEncryptedPseudonym::<Ristretto255>(vec![]);
        let serialized = empty_pseudo.serialize();
        assert_eq!(serialized, "");

        let deserialized = LongEncryptedPseudonym::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.len(), 0);

        let empty_attr = super::LongEncryptedAttribute::<Ristretto255>(vec![]);
        let serialized = empty_attr.serialize();
        assert_eq!(serialized, "");

        let deserialized = LongEncryptedAttribute::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.len(), 0);
    }

    #[test]
    fn long_encrypted_deserialize_invalid_base64() {
        let result = LongEncryptedPseudonym::deserialize("invalid!!!|also-invalid!!!");
        assert_eq!(
            result.unwrap_err(),
            ParseError::InvalidCiphertext("invalid!!!".to_string())
        );

        let result = LongEncryptedAttribute::deserialize("invalid!!!|also-invalid!!!");
        assert_eq!(
            result.unwrap_err(),
            ParseError::InvalidCiphertext("invalid!!!".to_string())
        );
    }

    #[test]
    #[cfg(feature = "json")]
    fn long_encrypted_serde_json() {
        let mut rng = rand::rng();
        let (session_public, _session_secret) = make_pseudonym_session_keys::<Ristretto255Sha512>(
            &make_pseudonym_global_keys::<Ristretto255, _>(&mut rng).1,
            &EncryptionContext::from("session-1"),
            &EncryptionSecret::from("enc-secret".as_bytes().to_vec()),
        );

        let pseudonyms = LongPseudonym::from_string_padded("serde-test-data");
        let encrypted: Vec<EncryptedPseudonym> = pseudonyms
            .iter()
            .map(|p| encrypt(p, &session_public, &mut rng))
            .collect();
        let long_encrypted = LongEncryptedPseudonym::from(encrypted);

        let json = serde_json::to_string(&long_encrypted).expect("Failed to serialize to JSON");
        let deserialized: LongEncryptedPseudonym =
            serde_json::from_str(&json).expect("Failed to deserialize from JSON");

        assert_eq!(long_encrypted.len(), deserialized.len());
        for (original, restored) in long_encrypted.iter().zip(deserialized.iter()) {
            assert_eq!(original, restored);
        }
    }

    #[test]
    fn long_encrypted_pseudonym_single_item() {
        use crate::data::padding::Padded;

        let mut rng = rand::rng();
        let (session_public, _session_secret) = make_pseudonym_session_keys::<Ristretto255Sha512>(
            &make_pseudonym_global_keys::<Ristretto255, _>(&mut rng).1,
            &EncryptionContext::from("session-1"),
            &EncryptionSecret::from("enc-secret".as_bytes().to_vec()),
        );

        let pseudonym = Pseudonym::from_bytes_padded(b"single").unwrap();
        let encrypted = encrypt(&pseudonym, &session_public, &mut rng);
        let long_encrypted = LongEncryptedPseudonym::from(vec![encrypted]);

        // Serialize and deserialize
        let serialized = long_encrypted.serialize();
        assert!(!serialized.contains('|')); // Single item should not have delimiter

        let deserialized = LongEncryptedPseudonym::deserialize(&serialized).unwrap();
        assert_eq!(1, deserialized.len());
        assert_eq!(long_encrypted[0], deserialized[0]);
    }

    #[test]
    fn long_attribute_null_bytes_in_middle() {
        // Test string with null bytes in the middle
        let str_with_nulls = "hello\0world";
        let attr = LongAttribute::from_string_padded(str_with_nulls);
        let decoded = attr.to_string_padded().unwrap();
        assert_eq!(str_with_nulls, decoded);
    }

    #[test]
    fn long_attribute_null_bytes_at_end() {
        // Test string ending with null bytes
        let str_ending_nulls = "test\0\0";
        let attr = LongAttribute::from_string_padded(str_ending_nulls);
        let decoded = attr.to_string_padded().unwrap();
        assert_eq!(str_ending_nulls, decoded);
    }

    #[test]
    fn long_attribute_empty_string() {
        // Test empty string
        let empty = "";
        let attr = LongAttribute::from_string_padded(empty);
        let decoded = attr.to_string_padded().unwrap();
        assert_eq!(empty, decoded);
    }

    #[test]
    fn long_attribute_strings_ending_with_many_null_bytes() {
        // Test various counts of trailing null bytes
        for null_count in 1..=20 {
            let mut test_str = String::from("test");
            test_str.push_str(&"\0".repeat(null_count));

            let attr = LongAttribute::from_string_padded(&test_str);
            let decoded = attr.to_string_padded().unwrap();

            assert_eq!(test_str, decoded, "Failed for {} null bytes", null_count);
        }
    }

    #[test]
    fn long_attribute_only_null_bytes() {
        // Test strings that are only null bytes
        for null_count in 1..=20 {
            let test_str = "\0".repeat(null_count);

            let attr = LongAttribute::from_string_padded(&test_str);
            let decoded = attr.to_string_padded().unwrap();

            assert_eq!(
                test_str, decoded,
                "Failed for string of {} null bytes",
                null_count
            );
        }
    }

    #[test]
    fn long_attribute_edge_case_15_and_16_null_bytes() {
        // 15 null bytes fit in one block with 1 byte padding
        let str_15 = "\0".repeat(15);
        let attr_15 = LongAttribute::from_string_padded(&str_15);
        let decoded_15 = attr_15.to_string_padded().unwrap();
        assert_eq!(str_15, decoded_15);

        // 16 null bytes - requires 2 blocks (first full, second with 15 bytes data + 1 padding)
        let str_16 = "\0".repeat(16);
        let attr_16 = LongAttribute::from_string_padded(&str_16);
        let decoded_16 = attr_16.to_string_padded().unwrap();
        assert_eq!(str_16, decoded_16);

        // 17 null bytes
        let str_17 = "\0".repeat(17);
        let attr_17 = LongAttribute::from_string_padded(&str_17);
        let decoded_17 = attr_17.to_string_padded().unwrap();
        assert_eq!(str_17, decoded_17);
    }

    #[test]
    fn long_attribute_pad_to_with_null_bytes() {
        // Create a string with null bytes
        let str_with_nulls = "data\0\0end";
        let attr = LongAttribute::from_string_padded(str_with_nulls);

        // Pad to more blocks
        let padded = attr.pad_to(3).unwrap();

        // Should preserve the null bytes in the original string
        let decoded = padded.to_string_padded().unwrap();
        assert_eq!(str_with_nulls, decoded);
    }

    #[test]
    fn long_attribute_pad_to_only_null_bytes() {
        // Test strings that are only null bytes, then padded
        for null_count in 1..=10 {
            let test_str = "\0".repeat(null_count);

            let attr = LongAttribute::from_string_padded(&test_str);
            let padded = attr.pad_to(5).unwrap();

            let decoded = padded.to_string_padded().unwrap();
            assert_eq!(
                test_str, decoded,
                "Failed for padded string of {} null bytes",
                null_count
            );
        }
    }

    #[test]
    fn long_attribute_pad_to_empty_string() {
        // Test empty string with padding
        let empty = "";
        let attr = LongAttribute::from_string_padded(empty);
        let padded = attr.pad_to(2).unwrap();

        let decoded = padded.to_string_padded().unwrap();
        assert_eq!(empty, decoded);
    }

    #[test]
    fn long_pseudonym_null_bytes_roundtrip() {
        // Test pseudonym with null bytes
        let str_with_nulls = "user\0\0id";
        let pseudo = LongPseudonym::from_string_padded(str_with_nulls);
        let decoded = pseudo.to_string_padded().unwrap();
        assert_eq!(str_with_nulls, decoded);
    }

    #[test]
    fn long_pseudonym_pad_to_with_null_bytes() {
        // Test pseudonym with null bytes after padding
        let str_with_nulls = "id\0\0x";
        let pseudo = LongPseudonym::from_string_padded(str_with_nulls);
        let padded = pseudo.pad_to(3).unwrap();

        let decoded = padded.to_string_padded().unwrap();
        assert_eq!(str_with_nulls, decoded);
    }

    #[test]
    fn long_attribute_data_ending_with_full_0x10_block() {
        // Regression test for external padding detection:
        // Plaintext containing a full block of 0x10 bytes should roundtrip correctly.
        // After PKCS#7 encoding, this becomes [0x10×16][0x10×16] (data block + padding block).
        // The decoder must correctly identify the second block as legitimate PKCS#7 padding,
        // not external padding added by pad_to().
        let data = vec![0x10u8; 16];
        let attr = LongAttribute::from_bytes_padded(&data);
        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(
            data, decoded,
            "Data ending with full 0x10 block should roundtrip correctly"
        );
    }

    #[test]
    fn long_attribute_ascending_sequence_data() {
        // Regression test: data containing ascending sequence [0,1,2,...,15]
        // must encode and decode correctly even though it looks like a pattern.
        let data: Vec<u8> = (0..16).collect();
        let attr = LongAttribute::from_bytes_padded(&data);
        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(
            data, decoded,
            "Ascending sequence data should roundtrip correctly"
        );
    }

    #[test]
    fn long_attribute_pad_to_preserves_data() {
        // Test that pad_to correctly preserves data when adding external padding
        let attr = LongAttribute::from_string_padded("hello");
        let original_len = attr.len();

        let padded = attr.pad_to(original_len + 2).unwrap();
        assert_eq!(
            padded.len(),
            original_len + 2,
            "Padded length should match target"
        );

        let decoded = padded.to_string_padded().unwrap();
        assert_eq!(decoded, "hello", "pad_to should preserve original data");
    }

    #[test]
    fn long_pseudonym_pad_to_preserves_data() {
        // Test that pad_to correctly preserves data for pseudonyms
        let pseudo = LongPseudonym::from_string_padded("test-user-id");
        let original_len = pseudo.len();

        let padded = pseudo.pad_to(original_len + 3).unwrap();
        assert_eq!(
            padded.len(),
            original_len + 3,
            "Padded length should match target"
        );

        let decoded = padded.to_string_padded().unwrap();
        assert_eq!(
            decoded, "test-user-id",
            "pad_to should preserve original data"
        );
    }

    #[test]
    fn long_attribute_data_containing_magic_marker_multiblock() {
        // Edge case: Data that contains bytes [0xFF, 0xEE, 0xDD, 0xCC]
        // CAN be encoded regardless - external padding is all zeros now.
        let data = vec![
            0xFF, 0xEE, 0xDD, 0xCC, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0xAA, 0xBB, 0xCC,
        ];
        let attr = LongAttribute::from_bytes_padded(&data);
        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(
            data, decoded,
            "Multi-block data with any bytes should roundtrip correctly"
        );
    }

    #[test]
    fn long_attribute_single_block_with_magic_marker() {
        // Edge case: Data starting with [0xFF, 0xEE, 0xDD, 0xCC] works fine.
        // After PKCS#7, the last byte will be 0x08 (padding), not 0x00.
        // External padding is all zeros, so this won't be confused.
        let data = vec![0xFF, 0xEE, 0xDD, 0xCC, 0x99, 0x88, 0x77, 0x66];
        let attr = LongAttribute::from_bytes_padded(&data);

        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(
            data, decoded,
            "Single-block data with any bytes should roundtrip correctly"
        );
    }

    #[test]
    fn long_attribute_data_exactly_matching_external_padding_pattern() {
        // Edge case: Data that is all zeros.
        // After PKCS#7 encoding, the last byte will be a padding value (0x01-0x10), not 0x00.
        let data = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let attr = LongAttribute::from_bytes_padded(&data);

        // After PKCS#7: will be 1 block with last byte = 0x01
        // Not all zeros, so won't be confused with external padding
        assert_eq!(attr.len(), 1);

        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(data, decoded, "All-zero data should roundtrip correctly");
    }

    #[test]
    fn long_attribute_double_pad_to_works() {
        // With all-zero external padding, calling pad_to() multiple times works correctly.
        // The decoder scans backwards removing all zero blocks until it finds the data block.
        let attr = LongAttribute::from_string_padded("test");
        let padded_once = attr.pad_to(2).unwrap();
        let padded_twice = padded_once.pad_to(3).unwrap();

        // This should succeed - all zero blocks are removed, leaving just the data
        let result = padded_twice.to_string_padded();
        assert!(
            result.is_ok(),
            "Double pad_to should succeed with all-zero padding"
        );
        assert_eq!(result.unwrap(), "test");
    }

    #[test]
    fn verify_no_ambiguous_edge_cases() {
        // Verify that all data can be encoded without ambiguity.
        // External padding is all-zero blocks, and PKCS#7 ensures the last byte is never 0x00.

        // Test 1: Arbitrary data
        let data1 = vec![0xFF, 0xEE, 0xDD, 0xCC, 0x99, 0x88, 0x77, 0x66];
        let attr1 = LongAttribute::from_bytes_padded(&data1);
        let decoded1 = attr1.to_bytes_padded().unwrap();
        assert_eq!(data1, decoded1, "Arbitrary data should work");

        // Test 2: All-zero data (PKCS#7 adds non-zero padding)
        let data2 = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let attr2 = LongAttribute::from_bytes_padded(&data2);
        let decoded2 = attr2.to_bytes_padded().unwrap();
        assert_eq!(data2, decoded2, "All-zero data should work");

        // Test 3: Mixed zeros and non-zeros
        let data3 = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x11, 0x12,
            0x13, 0x14, 0x15, 0x16,
        ];
        let attr3 = LongAttribute::from_bytes_padded(&data3);
        let decoded3 = attr3.to_bytes_padded().unwrap();
        assert_eq!(data3, decoded3, "Mixed data should work");

        // Test 4: pad_to() works correctly
        let attr4 = LongAttribute::from_string_padded("hello");
        let padded = attr4.pad_to(3).unwrap();
        assert_eq!(
            padded.len(),
            3,
            "pad_to should create correct number of blocks"
        );
        let decoded4 = padded.to_string_padded().unwrap();
        assert_eq!("hello", decoded4, "pad_to should preserve original data");

        // Test 5: Various lengths with different byte patterns
        for len in 1..=32 {
            let mut data = vec![0x00; len]; // All zeros
            data[0] = 0xFF; // Make first byte non-zero

            let attr = LongAttribute::from_bytes_padded(&data);
            let decoded = attr.to_bytes_padded().unwrap();
            assert_eq!(data, decoded, "Data of length {} should work", len);
        }
    }
}
