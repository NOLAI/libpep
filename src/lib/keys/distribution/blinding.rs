//! Blinding factors and blinded global secret keys for distributed transcryptors.
//!
//! This module provides blinding factors used to blind global secret keys during system setup,
//! making it impossible to derive keys without cooperation of the transcryptors.

use crate::arithmetic::scalars::ScalarNonZero;
use crate::keys::*;
use derive_more::{Deref, From};
use rand_core::{CryptoRng, Rng};

/// A blinding factor used to blind a global secret key during system setup.
///
/// This type intentionally does **not** implement `Deref` to the inner
/// scalar: the wrapped value is secret and exposing it via the `*` operator
/// makes it easy to leak inadvertently (e.g. via `Debug` of a tuple).
/// Internal callers that need the scalar value should use
/// [`BlindingFactor::as_scalar`].
#[derive(Copy, Clone, From)]
pub struct BlindingFactor(pub(crate) ScalarNonZero);

impl std::fmt::Debug for BlindingFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not leak the secret scalar via Debug formatting (e.g. logs).
        f.write_str("BlindingFactor(…)")
    }
}

/// A blinded pseudonym global secret key, which is the pseudonym global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
///
/// Although blinded, the wrapped scalar is still cryptographically sensitive
/// material; `Debug` is implemented manually to avoid leaking it.
#[derive(Copy, Clone, Eq, PartialEq, From, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct BlindedPseudonymGlobalSecretKey(pub(crate) ScalarNonZero);

impl std::fmt::Debug for BlindedPseudonymGlobalSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlindedPseudonymGlobalSecretKey(…)")
    }
}

/// A blinded attribute global secret key, which is the attribute global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
///
/// Although blinded, the wrapped scalar is still cryptographically sensitive
/// material; `Debug` is implemented manually to avoid leaking it.
#[derive(Copy, Clone, Eq, PartialEq, From, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct BlindedAttributeGlobalSecretKey(pub(crate) ScalarNonZero);

impl std::fmt::Debug for BlindedAttributeGlobalSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlindedAttributeGlobalSecretKey(…)")
    }
}

/// A pair of blinded global secret keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Eq, PartialEq, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlindedGlobalKeys {
    pub pseudonym: BlindedPseudonymGlobalSecretKey,
    pub attribute: BlindedAttributeGlobalSecretKey,
}

impl std::fmt::Debug for BlindedGlobalKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlindedGlobalKeys")
            .field("pseudonym", &self.pseudonym)
            .field("attribute", &self.attribute)
            .finish()
    }
}

impl BlindingFactor {
    /// Crate-internal accessor for the inner secret scalar.
    ///
    /// Not part of the public API: external callers should never need the
    /// raw scalar, since exposing it defeats the purpose of blinding.
    #[inline]
    pub(crate) fn as_scalar(&self) -> &ScalarNonZero {
        &self.0
    }

    /// Create a random blinding factor.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let scalar = ScalarNonZero::random(rng);
            if scalar != ScalarNonZero::one() {
                return Self(scalar);
            }
        }
    }

    /// Encode as a byte array.
    ///
    /// This exposes the secret scalar bytes; callers must handle the result
    /// as secret material (e.g. only persist it via a secure channel).
    pub fn to_bytes(&self) -> [u8; 32] {
        use crate::arithmetic::scalars::ScalarTraits;
        self.0.to_bytes()
    }
    /// Encode as a hexadecimal string.
    ///
    /// As with [`Self::to_bytes`], the result is secret material.
    pub fn to_hex(&self) -> String {
        use crate::arithmetic::scalars::ScalarTraits;
        self.0.to_hex()
    }
    /// Decode from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        ScalarNonZero::from_bytes(bytes).map(Self)
    }
    /// Decode from a slice of bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        ScalarNonZero::from_slice(slice).map(Self)
    }
    /// Decode from a hexadecimal string.
    pub fn from_hex(s: &str) -> Option<Self> {
        ScalarNonZero::from_hex(s).map(Self)
    }
}

impl BlindedPseudonymGlobalSecretKey {
    /// Decode from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        ScalarNonZero::from_bytes(bytes).map(Self)
    }
    /// Decode from a slice of bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        ScalarNonZero::from_slice(slice).map(Self)
    }
    /// Decode from a hexadecimal string.
    pub fn from_hex(s: &str) -> Option<Self> {
        ScalarNonZero::from_hex(s).map(Self)
    }
}

impl BlindedAttributeGlobalSecretKey {
    /// Decode from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        ScalarNonZero::from_bytes(bytes).map(Self)
    }
    /// Decode from a slice of bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        ScalarNonZero::from_slice(slice).map(Self)
    }
    /// Decode from a hexadecimal string.
    pub fn from_hex(s: &str) -> Option<Self> {
        ScalarNonZero::from_hex(s).map(Self)
    }
}

/// Helper to compute the blinding multiplier from blinding factors.
fn compute_blinding_multiplier(blinding_factors: &[BlindingFactor]) -> Option<ScalarNonZero> {
    let k = blinding_factors
        .iter()
        .fold(ScalarNonZero::one(), |acc, x| acc * x.0.invert());
    if k == ScalarNonZero::one() {
        return None;
    }
    Some(k)
}

/// Trait for global secret key types that can be blinded.
pub trait BlindableGlobalSecretKey: Sized {
    type BlindedType: From<ScalarNonZero>;

    /// Get the inner scalar value.
    fn inner(&self) -> &ScalarNonZero;

    /// Blind this global secret key with the given blinding factors.
    fn blind(&self, blinding_factors: &[BlindingFactor]) -> Option<Self::BlindedType> {
        compute_blinding_multiplier(blinding_factors)
            .map(|k| Self::BlindedType::from(*self.inner() * k))
    }
}

impl BlindableGlobalSecretKey for PseudonymGlobalSecretKey {
    type BlindedType = BlindedPseudonymGlobalSecretKey;

    fn inner(&self) -> &ScalarNonZero {
        &self.0
    }
}

impl BlindableGlobalSecretKey for AttributeGlobalSecretKey {
    type BlindedType = BlindedAttributeGlobalSecretKey;

    fn inner(&self) -> &ScalarNonZero {
        &self.0
    }
}

/// Create a blinded global secret key from a global secret key and blinding factors.
/// Automatically works for both pseudonym and attribute keys based on the types.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
pub fn make_blinded_global_key<K>(
    global_secret_key: &K,
    blinding_factors: &[BlindingFactor],
) -> Option<K::BlindedType>
where
    K: BlindableGlobalSecretKey,
{
    global_secret_key.blind(blinding_factors)
}

/// Create a [`BlindedPseudonymGlobalSecretKey`] from a [`PseudonymGlobalSecretKey`] and a list of [`BlindingFactor`]s.
/// Used during system setup to blind the global secret key for pseudonyms.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
pub fn make_blinded_pseudonym_global_secret_key(
    global_secret_key: &PseudonymGlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedPseudonymGlobalSecretKey> {
    make_blinded_global_key(global_secret_key, blinding_factors)
}

/// Create a [`BlindedAttributeGlobalSecretKey`] from a [`AttributeGlobalSecretKey`] and a list of [`BlindingFactor`]s.
/// Used during system setup to blind the global secret key for attributes.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
pub fn make_blinded_attribute_global_secret_key(
    global_secret_key: &AttributeGlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedAttributeGlobalSecretKey> {
    make_blinded_global_key(global_secret_key, blinding_factors)
}

/// Create [`BlindedGlobalKeys`] (both pseudonym and attribute) from global secret keys and blinding factors.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1 for either key type.
pub fn make_blinded_global_keys(
    pseudonym_global_secret_key: &PseudonymGlobalSecretKey,
    attribute_global_secret_key: &AttributeGlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedGlobalKeys> {
    let pseudonym = make_blinded_global_key(pseudonym_global_secret_key, blinding_factors)?;
    let attribute = make_blinded_global_key(attribute_global_secret_key, blinding_factors)?;
    Some(BlindedGlobalKeys {
        pseudonym,
        attribute,
    })
}
