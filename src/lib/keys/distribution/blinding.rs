//! Blinding factors and blinded global secret keys for distributed transcryptors.
//!
//! During system setup the global secret keys are blinded with one blinding factor per
//! transcryptor, so that no key can be derived from the published blinded key without the
//! cooperation of every transcryptor.
//!
//! Blinding factors and blinded keys are protocol material, not keys: no data is encrypted
//! towards them and they have no associated public key, so they do not implement
//! [`SecretKey`].

use crate::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
use crate::keys::*;
use rand_core::{CryptoRng, Rng};

/// A blinding factor used to blind a global secret key during system setup.
#[derive(Copy, Clone, Debug)]
pub struct BlindingFactor(pub(crate) ScalarNonZero);

impl BlindingFactor {
    /// Create a random blinding factor.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let scalar = ScalarNonZero::random(rng);
            if scalar != ScalarNonZero::one() {
                return Self(scalar);
            }
        }
    }

    /// Construct from a raw scalar.
    pub fn from_scalar(scalar: ScalarNonZero) -> Self {
        Self(scalar)
    }

    /// The scalar value of this blinding factor.
    pub fn value(&self) -> &ScalarNonZero {
        &self.0
    }

    /// Encode as a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Encode as a hexadecimal string.
    pub fn to_hex(&self) -> String {
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

/// A global secret key blinded by the blinding factors of all transcryptors.
///
/// Blinding makes the value safe to publish: it hides the global secret key unless every
/// transcryptor cooperates. It is not usable as a decryption key on its own; combined with one
/// [session key share](super::shares::SessionKeyShare) per transcryptor it yields a session key.
pub trait BlindedGlobalSecretKey: Sized {
    /// The scalar value of this blinded key.
    fn value(&self) -> &ScalarNonZero;

    /// Construct from a raw scalar.
    fn from_scalar(scalar: ScalarNonZero) -> Self;

    /// Encode as a byte array.
    fn to_bytes(&self) -> [u8; 32] {
        self.value().to_bytes()
    }

    /// Encode as a hexadecimal string.
    fn to_hex(&self) -> String {
        self.value().to_hex()
    }

    /// Decode from a byte array.
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        ScalarNonZero::from_bytes(bytes).map(Self::from_scalar)
    }

    /// Decode from a slice of bytes.
    fn from_slice(slice: &[u8]) -> Option<Self> {
        ScalarNonZero::from_slice(slice).map(Self::from_scalar)
    }

    /// Decode from a hexadecimal string.
    fn from_hex(s: &str) -> Option<Self> {
        ScalarNonZero::from_hex(s).map(Self::from_scalar)
    }
}

/// A blinded pseudonym global secret key, which is the pseudonym global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct BlindedPseudonymGlobalSecretKey(pub(crate) ScalarNonZero);

/// A blinded attribute global secret key, which is the attribute global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct BlindedAttributeGlobalSecretKey(pub(crate) ScalarNonZero);

macro_rules! impl_blinded_global_secret_key {
    ($($t:ty),+ $(,)?) => {$(
        impl BlindedGlobalSecretKey for $t {
            fn value(&self) -> &ScalarNonZero {
                &self.0
            }
            fn from_scalar(scalar: ScalarNonZero) -> Self {
                Self(scalar)
            }
        }
    )+};
}

impl_blinded_global_secret_key!(
    BlindedPseudonymGlobalSecretKey,
    BlindedAttributeGlobalSecretKey
);

/// A pair of blinded global secret keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlindedGlobalSecretKeys {
    pub pseudonym: BlindedPseudonymGlobalSecretKey,
    pub attribute: BlindedAttributeGlobalSecretKey,
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

/// A global secret key that can be blinded with the blinding factors of the transcryptors.
pub trait BlindableGlobalSecretKey: SecretKey {
    /// The blinded form of this key.
    type BlindedType: BlindedGlobalSecretKey;

    /// Blind this global secret key with the given blinding factors.
    ///
    /// The blinded key is the secret key multiplied by the inverse of every blinding factor.
    /// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
    fn blind(&self, blinding_factors: &[BlindingFactor]) -> Option<Self::BlindedType> {
        compute_blinding_multiplier(blinding_factors)
            .map(|k| Self::BlindedType::from_scalar(*self.value() * k))
    }
}

impl BlindableGlobalSecretKey for PseudonymGlobalSecretKey {
    type BlindedType = BlindedPseudonymGlobalSecretKey;
}

impl BlindableGlobalSecretKey for AttributeGlobalSecretKey {
    type BlindedType = BlindedAttributeGlobalSecretKey;
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

/// Create [`BlindedGlobalSecretKeys`] (both pseudonym and attribute) from global secret keys and blinding factors.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1 for either key type.
pub fn make_blinded_global_keys(
    pseudonym_global_secret_key: &PseudonymGlobalSecretKey,
    attribute_global_secret_key: &AttributeGlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedGlobalSecretKeys> {
    let pseudonym = make_blinded_global_key(pseudonym_global_secret_key, blinding_factors)?;
    let attribute = make_blinded_global_key(attribute_global_secret_key, blinding_factors)?;
    Some(BlindedGlobalSecretKeys {
        pseudonym,
        attribute,
    })
}
