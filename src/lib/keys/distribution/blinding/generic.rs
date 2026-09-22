//! Blinding factors and blinded global secret keys generic over the [`Group`].

use crate::elgamal::arithmetic::group::Group;
use crate::keys::traits::{decode_hex, SecretKey};
use crate::keys::types::generic::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use rand_core::{CryptoRng, Rng};

/// A blinding factor used to blind a global secret key during system setup.
#[derive(Copy, Clone, Debug)]
pub struct BlindingFactor<G: Group>(pub(crate) G::Scalar);

impl<G: Group> BlindingFactor<G> {
    /// Create a random blinding factor.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let scalar = G::random_scalar(rng);
            if scalar != G::scalar_one() {
                return Self(scalar);
            }
        }
    }

    /// Construct from a raw scalar.
    pub fn from_scalar(scalar: G::Scalar) -> Self {
        Self(scalar)
    }

    /// The scalar value of this blinding factor.
    pub fn value(&self) -> &G::Scalar {
        &self.0
    }

    /// Encode as a byte array.
    pub fn to_bytes(&self) -> G::ScalarBytes {
        G::serialize_scalar(&self.0)
    }

    /// Encode as a hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from a byte array.
    pub fn from_bytes(bytes: &G::ScalarBytes) -> Option<Self> {
        Self::from_slice(bytes.as_ref())
    }

    /// Decode from a slice of bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        G::deserialize_scalar(slice).map(Self)
    }

    /// Decode from a hexadecimal string.
    pub fn from_hex(s: &str) -> Option<Self> {
        decode_hex::<G::ScalarBytes>(s).and_then(|b| Self::from_slice(b.as_ref()))
    }
}

/// A global secret key blinded by the blinding factors of all transcryptors.
///
/// Blinding makes the value safe to publish: it hides the global secret key unless every
/// transcryptor cooperates. It is not usable as a decryption key on its own; combined with one
/// [session key share](super::super::shares::SessionKeyShare) per transcryptor it yields a session key.
pub trait BlindedGlobalSecretKey: Sized {
    /// The group the key is a scalar of.
    type Group: Group;

    /// The scalar value of this blinded key.
    fn value(&self) -> &<Self::Group as Group>::Scalar;

    /// Construct from a raw scalar.
    fn from_scalar(scalar: <Self::Group as Group>::Scalar) -> Self;

    /// Encode as a byte array.
    fn to_bytes(&self) -> <Self::Group as Group>::ScalarBytes {
        Self::Group::serialize_scalar(self.value())
    }

    /// Encode as a hexadecimal string.
    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from a byte array.
    fn from_bytes(bytes: &<Self::Group as Group>::ScalarBytes) -> Option<Self> {
        Self::from_slice(bytes.as_ref())
    }

    /// Decode from a slice of bytes.
    fn from_slice(slice: &[u8]) -> Option<Self> {
        Self::Group::deserialize_scalar(slice).map(Self::from_scalar)
    }

    /// Decode from a hexadecimal string.
    fn from_hex(s: &str) -> Option<Self> {
        decode_hex::<<Self::Group as Group>::ScalarBytes>(s)
            .and_then(|b| Self::from_slice(b.as_ref()))
    }
}

/// A blinded pseudonym global secret key, which is the pseudonym global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct BlindedPseudonymGlobalSecretKey<G: Group>(pub(crate) G::Scalar);

/// A blinded attribute global secret key, which is the attribute global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct BlindedAttributeGlobalSecretKey<G: Group>(pub(crate) G::Scalar);

macro_rules! impl_blinded_global_secret_key {
    ($($t:ident),+ $(,)?) => {$(
        impl<G: Group> BlindedGlobalSecretKey for $t<G> {
            type Group = G;

            fn value(&self) -> &G::Scalar {
                &self.0
            }
            fn from_scalar(scalar: G::Scalar) -> Self {
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
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct BlindedGlobalSecretKeys<G: Group> {
    pub pseudonym: BlindedPseudonymGlobalSecretKey<G>,
    pub attribute: BlindedAttributeGlobalSecretKey<G>,
}

/// Helper to compute the blinding multiplier from blinding factors.
fn compute_blinding_multiplier<G: Group>(
    blinding_factors: &[BlindingFactor<G>],
) -> Option<G::Scalar> {
    let k = blinding_factors
        .iter()
        .fold(G::scalar_one(), |acc, x| acc * G::scalar_inverse(&x.0));
    if k == G::scalar_one() {
        return None;
    }
    Some(k)
}

/// A global secret key that can be blinded with the blinding factors of the transcryptors.
pub trait BlindableGlobalSecretKey: SecretKey {
    /// The blinded form of this key.
    type BlindedType: BlindedGlobalSecretKey<Group = Self::Group>;

    /// Blind this global secret key with the given blinding factors.
    ///
    /// The blinded key is the secret key multiplied by the inverse of every blinding factor.
    /// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
    fn blind(&self, blinding_factors: &[BlindingFactor<Self::Group>]) -> Option<Self::BlindedType> {
        compute_blinding_multiplier(blinding_factors)
            .map(|k| Self::BlindedType::from_scalar(*self.value() * k))
    }
}

impl<G: Group> BlindableGlobalSecretKey for PseudonymGlobalSecretKey<G> {
    type BlindedType = BlindedPseudonymGlobalSecretKey<G>;
}

impl<G: Group> BlindableGlobalSecretKey for AttributeGlobalSecretKey<G> {
    type BlindedType = BlindedAttributeGlobalSecretKey<G>;
}

/// Create a blinded global secret key from a global secret key and blinding factors.
/// Automatically works for both pseudonym and attribute keys based on the types.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
pub fn make_blinded_global_key<K>(
    global_secret_key: &K,
    blinding_factors: &[BlindingFactor<K::Group>],
) -> Option<K::BlindedType>
where
    K: BlindableGlobalSecretKey,
{
    global_secret_key.blind(blinding_factors)
}

/// Create a [`BlindedPseudonymGlobalSecretKey`] from a [`PseudonymGlobalSecretKey`] and a list of [`BlindingFactor`]s.
/// Used during system setup to blind the global secret key for pseudonyms.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
pub fn make_blinded_pseudonym_global_secret_key<G: Group>(
    global_secret_key: &PseudonymGlobalSecretKey<G>,
    blinding_factors: &[BlindingFactor<G>],
) -> Option<BlindedPseudonymGlobalSecretKey<G>> {
    make_blinded_global_key(global_secret_key, blinding_factors)
}

/// Create a [`BlindedAttributeGlobalSecretKey`] from a [`AttributeGlobalSecretKey`] and a list of [`BlindingFactor`]s.
/// Used during system setup to blind the global secret key for attributes.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
pub fn make_blinded_attribute_global_secret_key<G: Group>(
    global_secret_key: &AttributeGlobalSecretKey<G>,
    blinding_factors: &[BlindingFactor<G>],
) -> Option<BlindedAttributeGlobalSecretKey<G>> {
    make_blinded_global_key(global_secret_key, blinding_factors)
}

/// Create [`BlindedGlobalSecretKeys`] (both pseudonym and attribute) from global secret keys and blinding factors.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1 for either key type.
pub fn make_blinded_global_keys<G: Group>(
    pseudonym_global_secret_key: &PseudonymGlobalSecretKey<G>,
    attribute_global_secret_key: &AttributeGlobalSecretKey<G>,
    blinding_factors: &[BlindingFactor<G>],
) -> Option<BlindedGlobalSecretKeys<G>> {
    let pseudonym = make_blinded_global_key(pseudonym_global_secret_key, blinding_factors)?;
    let attribute = make_blinded_global_key(attribute_global_secret_key, blinding_factors)?;
    Some(BlindedGlobalSecretKeys {
        pseudonym,
        attribute,
    })
}
