//! System setup for distributed trust: blinding factors and blinded global secret keys.

use crate::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
use crate::core::keys::*;
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::de::{Error, Visitor};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use std::fmt::Formatter;

/// A blinding factor used to blind a global secret key during system setup.
#[derive(Copy, Clone, Debug, From, Deref)]
pub struct BlindingFactor(pub(crate) ScalarNonZero);

/// A blinded pseudonym global secret key, which is the pseudonym global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct BlindedPseudonymGlobalSecretKey(pub(crate) ScalarNonZero);

/// A blinded attribute global secret key, which is the attribute global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct BlindedAttributeGlobalSecretKey(pub(crate) ScalarNonZero);

/// A pair of blinded global secret keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlindedGlobalKeys {
    pub pseudonym: BlindedPseudonymGlobalSecretKey,
    pub attribute: BlindedAttributeGlobalSecretKey,
}

/// Macro to add encoding/decoding methods to scalar wrapper types.
macro_rules! impl_scalar_encoding {
    ($type:ident) => {
        impl $type {
            /// Encode as a byte array.
            pub fn to_bytes(&self) -> [u8; 32] {
                self.0.to_bytes()
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
            /// Encode as a hexadecimal string.
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }
        }
    };
}

impl_scalar_encoding!(BlindingFactor);
impl_scalar_encoding!(BlindedPseudonymGlobalSecretKey);
impl_scalar_encoding!(BlindedAttributeGlobalSecretKey);

impl BlindingFactor {
    /// Create a random blinding factor.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let scalar = ScalarNonZero::random(rng);
        assert_ne!(scalar, ScalarNonZero::one());
        Self(scalar)
    }
}

/// Macro to implement Serialize and Deserialize for scalar wrapper types as hex strings.
#[cfg(feature = "serde")]
macro_rules! impl_hex_serde_for_scalar_wrapper {
    ($type:ident) => {
        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.to_hex().as_str())
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct TypeVisitor;
                impl Visitor<'_> for TypeVisitor {
                    type Value = $type;
                    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                        write!(
                            formatter,
                            "a hex encoded string representing a {}",
                            stringify!($type)
                        )
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        ScalarNonZero::from_hex(v)
                            .map($type)
                            .ok_or(E::custom(format!("invalid hex encoded string: {v}")))
                    }
                }

                deserializer.deserialize_str(TypeVisitor)
            }
        }
    };
}

#[cfg(feature = "serde")]
impl_hex_serde_for_scalar_wrapper!(BlindedPseudonymGlobalSecretKey);
#[cfg(feature = "serde")]
impl_hex_serde_for_scalar_wrapper!(BlindedAttributeGlobalSecretKey);

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

/// Create a [`BlindedPseudonymGlobalSecretKey`] from a [`PseudonymGlobalSecretKey`] and a list of [`BlindingFactor`]s.
/// Used during system setup to blind the global secret key for pseudonyms.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
pub fn make_blinded_pseudonym_global_secret_key(
    global_secret_key: &PseudonymGlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedPseudonymGlobalSecretKey> {
    compute_blinding_multiplier(blinding_factors)
        .map(|k| BlindedPseudonymGlobalSecretKey(global_secret_key.0 * k))
}

/// Create a [`BlindedAttributeGlobalSecretKey`] from a [`AttributeGlobalSecretKey`] and a list of [`BlindingFactor`]s.
/// Used during system setup to blind the global secret key for attributes.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
pub fn make_blinded_attribute_global_secret_key(
    global_secret_key: &AttributeGlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedAttributeGlobalSecretKey> {
    compute_blinding_multiplier(blinding_factors)
        .map(|k| BlindedAttributeGlobalSecretKey(global_secret_key.0 * k))
}

/// Create [`BlindedGlobalKeys`] (both pseudonym and attribute) from global secret keys and blinding factors.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1 for either key type.
pub fn make_blinded_global_keys(
    pseudonym_global_secret_key: &PseudonymGlobalSecretKey,
    attribute_global_secret_key: &AttributeGlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedGlobalKeys> {
    let pseudonym =
        make_blinded_pseudonym_global_secret_key(pseudonym_global_secret_key, blinding_factors)?;
    let attribute =
        make_blinded_attribute_global_secret_key(attribute_global_secret_key, blinding_factors)?;
    Some(BlindedGlobalKeys {
        pseudonym,
        attribute,
    })
}

/// Generic function to setup a distributed system with global keys, blinded global secret key and blinding factors.
fn _make_distributed_global_keys<R, PK, SK, BGSK, F>(
    n: usize,
    rng: &mut R,
    make_keys: F,
    make_blinded: fn(&SK, &[BlindingFactor]) -> Option<BGSK>,
) -> (PK, BGSK, Vec<BlindingFactor>)
where
    R: RngCore + CryptoRng,
    F: Fn(&mut R) -> (PK, SK),
{
    let (pk, sk) = make_keys(rng);
    let blinding_factors: Vec<BlindingFactor> =
        (0..n).map(|_| BlindingFactor::random(rng)).collect();
    // Unwrap is safe: only fails if product of random blinding factors equals 1 (cryptographically negligible)
    #[allow(clippy::unwrap_used)]
    let bsk = make_blinded(&sk, &blinding_factors).unwrap();
    (pk, bsk, blinding_factors)
}

/// Setup a distributed system with pseudonym global keys, a blinded global secret key and a list of
/// blinding factors for pseudonyms.
/// The blinding factors should securely be transferred to the transcryptors ([`PEPSystem`](crate::distributed::server::transcryptor::PEPSystem)s), the global public key
/// and blinded global secret key can be publicly shared with anyone and are required by [`PEPClient`](crate::distributed::client::client::PEPClient)s.
pub fn make_distributed_pseudonym_global_keys<R: RngCore + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (
    PseudonymGlobalPublicKey,
    BlindedPseudonymGlobalSecretKey,
    Vec<BlindingFactor>,
) {
    _make_distributed_global_keys(
        n,
        rng,
        make_pseudonym_global_keys,
        make_blinded_pseudonym_global_secret_key,
    )
}

/// Setup a distributed system with attribute global keys, a blinded global secret key and a list of
/// blinding factors for attributes.
/// The blinding factors should securely be transferred to the transcryptors ([`PEPSystem`](crate::distributed::server::transcryptor::PEPSystem)s), the global public key
/// and blinded global secret key can be publicly shared with anyone and are required by [`PEPClient`](crate::distributed::client::client::PEPClient)s.
pub fn make_distributed_attribute_global_keys<R: RngCore + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (
    AttributeGlobalPublicKey,
    BlindedAttributeGlobalSecretKey,
    Vec<BlindingFactor>,
) {
    _make_distributed_global_keys(
        n,
        rng,
        make_attribute_global_keys,
        make_blinded_attribute_global_secret_key,
    )
}

/// Setup a distributed system with both pseudonym and attribute global keys, blinded global secret keys,
/// and a list of blinding factors. This is a convenience method that combines
/// [`make_distributed_pseudonym_global_keys`] and [`make_distributed_attribute_global_keys`].
///
/// The blinding factors should securely be transferred to the transcryptors ([`PEPSystem`](crate::distributed::server::transcryptor::PEPSystem)s),
/// the global public keys and blinded global secret keys can be publicly shared with anyone and are
/// required by [`PEPClient`](crate::distributed::client::client::PEPClient)s.
pub fn make_distributed_global_keys<R: RngCore + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (GlobalPublicKeys, BlindedGlobalKeys, Vec<BlindingFactor>) {
    let (pseudonym_pk, pseudonym_sk) = make_pseudonym_global_keys(rng);
    let (attribute_pk, attribute_sk) = make_attribute_global_keys(rng);

    let blinding_factors: Vec<BlindingFactor> =
        (0..n).map(|_| BlindingFactor::random(rng)).collect();

    // Unwrap is safe: only fails if product of random blinding factors equals 1 (cryptographically negligible)
    #[allow(clippy::unwrap_used)]
    let blinded_global_keys =
        make_blinded_global_keys(&pseudonym_sk, &attribute_sk, &blinding_factors).unwrap();

    (
        GlobalPublicKeys {
            pseudonym: pseudonym_pk,
            attribute: attribute_pk,
        },
        blinded_global_keys,
        blinding_factors,
    )
}
