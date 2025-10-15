//! Key blinding, session key share generation and session key retrieval for distributed trust.

use crate::high_level::keys::*;
use crate::internal::arithmetic::*;
use derive_more::From;
use rand_core::{CryptoRng, RngCore};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;

/// A blinding factor used to blind a global secret key during system setup.
#[derive(Copy, Clone, Debug)]
pub struct BlindingFactor(pub(crate) ScalarNonZero);

/// A blinded pseudonym global secret key, which is the pseudonym global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct BlindedPseudonymGlobalSecretKey(pub(crate) ScalarNonZero);

/// A blinded attribute global secret key, which is the attribute global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct BlindedAttributeGlobalSecretKey(pub(crate) ScalarNonZero);

/// A pair of blinded global secret keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Serialize, Deserialize)]
pub struct BlindedGlobalKeys {
    pub pseudonym: BlindedPseudonymGlobalSecretKey,
    pub attribute: BlindedAttributeGlobalSecretKey,
}

/// A pseudonym session key share, which is a part of a pseudonym session key provided by one transcryptor.
/// By combining all pseudonym session key shares and the [`BlindedPseudonymGlobalSecretKey`], a pseudonym session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PseudonymSessionKeyShare(pub(crate) ScalarNonZero);

/// An attribute session key share, which is a part of an attribute session key provided by one transcryptor.
/// By combining all attribute session key shares and the [`BlindedAttributeGlobalSecretKey`], an attribute session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct AttributeSessionKeyShare(pub(crate) ScalarNonZero);

/// A pair of session key shares containing both pseudonym and attribute shares.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Serialize, Deserialize)]
pub struct SessionKeyShares {
    pub pseudonym: PseudonymSessionKeyShare,
    pub attribute: AttributeSessionKeyShare,
}

/// A trait for scalars that are safe to encode and decode since they do not need to remain absolutely secret.
pub trait SafeScalar {
    /// Create from a scalar.
    fn from(x: ScalarNonZero) -> Self;
    /// Get the scalar value.
    fn value(&self) -> &ScalarNonZero;
    /// Encode as a byte array.
    /// See [`ScalarNonZero::encode`] for more information.
    fn encode(&self) -> [u8; 32] {
        self.value().encode()
    }
    /// Decode from a byte array.
    /// Returns `None` if the array is not 32 bytes long.
    /// See [`ScalarNonZero::decode`] for more information.
    fn decode(bytes: &[u8; 32]) -> Option<Self>
    where
        Self: Sized,
    {
        ScalarNonZero::decode(bytes).map(Self::from)
    }
    /// Decode from a slice of bytes.
    /// Returns `None` if the slice is not 32 bytes long.
    /// See [`ScalarNonZero::decode_from_slice`] for more information.
    fn decode_from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        ScalarNonZero::decode_from_slice(slice).map(Self::from)
    }
    /// Decode from a hexadecimal string of 64 characters.
    /// Returns `None` if the string is not 64 characters long.
    /// See [`ScalarNonZero::decode_from_hex`] for more information.
    fn decode_from_hex(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        ScalarNonZero::decode_from_hex(s).map(Self::from)
    }
    /// Encode as a hexadecimal string of 64 characters.
    /// See [`ScalarNonZero::encode_as_hex`] for more information.
    fn encode_as_hex(&self) -> String {
        self.value().encode_as_hex()
    }
}
impl SafeScalar for BlindingFactor {
    fn from(x: ScalarNonZero) -> Self {
        BlindingFactor(x)
    }

    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}
impl SafeScalar for BlindedPseudonymGlobalSecretKey {
    fn from(x: ScalarNonZero) -> Self {
        BlindedPseudonymGlobalSecretKey(x)
    }

    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}
impl SafeScalar for BlindedAttributeGlobalSecretKey {
    fn from(x: ScalarNonZero) -> Self {
        BlindedAttributeGlobalSecretKey(x)
    }

    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

impl SafeScalar for PseudonymSessionKeyShare {
    fn from(x: ScalarNonZero) -> Self {
        PseudonymSessionKeyShare(x)
    }

    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

impl SafeScalar for AttributeSessionKeyShare {
    fn from(x: ScalarNonZero) -> Self {
        AttributeSessionKeyShare(x)
    }

    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}
impl BlindingFactor {
    /// Create a random blinding factor.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let scalar = ScalarNonZero::random(rng);
        assert_ne!(scalar, ScalarNonZero::one());
        Self(scalar)
    }
}

/// Macro to implement Serialize and Deserialize for SafeScalar types
macro_rules! impl_serde_for_safe_scalar {
    ($type:ident) => {
        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.encode_as_hex().as_str())
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
                        ScalarNonZero::decode_from_hex(v)
                            .map($type)
                            .ok_or(E::custom(format!("invalid hex encoded string: {v}")))
                    }
                }

                deserializer.deserialize_str(TypeVisitor)
            }
        }
    };
}

impl_serde_for_safe_scalar!(BlindedPseudonymGlobalSecretKey);
impl_serde_for_safe_scalar!(BlindedAttributeGlobalSecretKey);
impl_serde_for_safe_scalar!(PseudonymSessionKeyShare);
impl_serde_for_safe_scalar!(AttributeSessionKeyShare);

/// Generic function to create a blinded global secret key from a global secret key and blinding factors.
fn _make_blinded_global_secret_key<GSK, BGSK>(
    global_secret_key: &GSK,
    blinding_factors: &[BlindingFactor],
) -> Option<BGSK>
where
    GSK: SecretKey,
    BGSK: SafeScalar,
{
    let k = blinding_factors
        .iter()
        .fold(ScalarNonZero::one(), |acc, x| acc * x.0.invert());
    if k == ScalarNonZero::one() {
        return None;
    }
    Some(BGSK::from(*global_secret_key.value() * k))
}

/// Create a [`BlindedPseudonymGlobalSecretKey`] from a [`PseudonymGlobalSecretKey`] and a list of [`BlindingFactor`]s.
/// Used during system setup to blind the global secret key for pseudonyms.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
pub fn make_blinded_pseudonym_global_secret_key(
    global_secret_key: &PseudonymGlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedPseudonymGlobalSecretKey> {
    _make_blinded_global_secret_key(global_secret_key, blinding_factors)
}

/// Create a [`BlindedAttributeGlobalSecretKey`] from a [`AttributeGlobalSecretKey`] and a list of [`BlindingFactor`]s.
/// Used during system setup to blind the global secret key for attributes.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
pub fn make_blinded_attribute_global_secret_key(
    global_secret_key: &AttributeGlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedAttributeGlobalSecretKey> {
    _make_blinded_global_secret_key(global_secret_key, blinding_factors)
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

/// Generic function to create a session key share from a rekey factor and a blinding factor.
fn _make_session_key_share<SKS>(
    rekey_factor: &ScalarNonZero,
    blinding_factor: &BlindingFactor,
) -> SKS
where
    SKS: SafeScalar,
{
    SKS::from(rekey_factor * blinding_factor.0)
}

/// Create a [`PseudonymSessionKeyShare`] from a [`ScalarNonZero`] pseudonym rekey factor and a [`BlindingFactor`].
pub fn make_pseudonym_session_key_share(
    rekey_factor: &ScalarNonZero,
    blinding_factor: &BlindingFactor,
) -> PseudonymSessionKeyShare {
    _make_session_key_share(rekey_factor, blinding_factor)
}

/// Create an [`AttributeSessionKeyShare`] from a [`ScalarNonZero`] attribute rekey factor and a [`BlindingFactor`].
pub fn make_attribute_session_key_share(
    rekey_factor: &ScalarNonZero,
    blinding_factor: &BlindingFactor,
) -> AttributeSessionKeyShare {
    _make_session_key_share(rekey_factor, blinding_factor)
}

/// Create [`SessionKeyShares`] (both pseudonym and attribute) from rekey factors and a blinding factor.
pub fn make_session_key_shares(
    pseudonym_rekey_factor: &ScalarNonZero,
    attribute_rekey_factor: &ScalarNonZero,
    blinding_factor: &BlindingFactor,
) -> SessionKeyShares {
    SessionKeyShares {
        pseudonym: make_pseudonym_session_key_share(pseudonym_rekey_factor, blinding_factor),
        attribute: make_attribute_session_key_share(attribute_rekey_factor, blinding_factor),
    }
}

/// Generic function to reconstruct a session key from a blinded global secret key and session key shares.
fn _make_session_key<BGSK, SKS, PK, SK>(
    blinded_global_secret_key: BGSK,
    session_key_shares: &[SKS],
) -> (PK, SK)
where
    BGSK: SafeScalar,
    SKS: SafeScalar,
    PK: From<GroupElement>,
    SK: SecretKey + From<ScalarNonZero>,
{
    let secret = SK::from(
        session_key_shares
            .iter()
            .fold(*blinded_global_secret_key.value(), |acc, x| acc * x.value()),
    );
    let public = PK::from(*secret.value() * G);
    (public, secret)
}

/// Reconstruct a pseudonym session key from a [`BlindedPseudonymGlobalSecretKey`] and a list of [`PseudonymSessionKeyShare`]s.
pub fn make_pseudonym_session_key(
    blinded_global_secret_key: BlindedPseudonymGlobalSecretKey,
    session_key_shares: &[PseudonymSessionKeyShare],
) -> (PseudonymSessionPublicKey, PseudonymSessionSecretKey) {
    _make_session_key(blinded_global_secret_key, session_key_shares)
}

/// Reconstruct an attribute session key from a [`BlindedAttributeGlobalSecretKey`] and a list of [`AttributeSessionKeyShare`]s.
pub fn make_attribute_session_key(
    blinded_global_secret_key: BlindedAttributeGlobalSecretKey,
    session_key_shares: &[AttributeSessionKeyShare],
) -> (AttributeSessionPublicKey, AttributeSessionSecretKey) {
    _make_session_key(blinded_global_secret_key, session_key_shares)
}

/// Reconstruct session keys (both pseudonym and attribute) from blinded global secret keys and session key shares.
pub fn make_session_keys_distributed(
    blinded_global_keys: BlindedGlobalKeys,
    session_key_shares: &[SessionKeyShares],
) -> SessionKeys {
    let pseudonym_shares: Vec<PseudonymSessionKeyShare> =
        session_key_shares.iter().map(|s| s.pseudonym).collect();
    let attribute_shares: Vec<AttributeSessionKeyShare> =
        session_key_shares.iter().map(|s| s.attribute).collect();

    let (pseudonym_public, pseudonym_secret) =
        make_pseudonym_session_key(blinded_global_keys.pseudonym, &pseudonym_shares);
    let (attribute_public, attribute_secret) =
        make_attribute_session_key(blinded_global_keys.attribute, &attribute_shares);

    SessionKeys {
        pseudonym: PseudonymSessionKeys {
            public: pseudonym_public,
            secret: pseudonym_secret,
        },
        attribute: AttributeSessionKeys {
            public: attribute_public,
            secret: attribute_secret,
        },
    }
}

/// Generic function to update a session key with new session key shares.
fn _update_session_key<SK, SKS, PK>(
    session_secret_key: SK,
    old_session_key_share: SKS,
    new_session_key_share: SKS,
) -> (PK, SK)
where
    SK: SecretKey + From<ScalarNonZero>,
    SKS: SafeScalar,
    PK: From<GroupElement>,
{
    let secret = SK::from(
        *session_secret_key.value()
            * old_session_key_share.value().invert()
            * new_session_key_share.value(),
    );
    let public = PK::from(*secret.value() * G);
    (public, secret)
}

/// Update a pseudonym session key share from one session to the other
pub fn update_pseudonym_session_key(
    session_secret_key: PseudonymSessionSecretKey,
    old_session_key_share: PseudonymSessionKeyShare,
    new_session_key_share: PseudonymSessionKeyShare,
) -> (PseudonymSessionPublicKey, PseudonymSessionSecretKey) {
    _update_session_key(
        session_secret_key,
        old_session_key_share,
        new_session_key_share,
    )
}

/// Update an attribute session key share from one session to the other
pub fn update_attribute_session_key(
    session_secret_key: AttributeSessionSecretKey,
    old_session_key_share: AttributeSessionKeyShare,
    new_session_key_share: AttributeSessionKeyShare,
) -> (AttributeSessionPublicKey, AttributeSessionSecretKey) {
    _update_session_key(
        session_secret_key,
        old_session_key_share,
        new_session_key_share,
    )
}

/// Update session keys (both pseudonym and attribute) from old session key shares to new ones.
pub fn update_session_keys(
    current_keys: SessionKeys,
    old_shares: SessionKeyShares,
    new_shares: SessionKeyShares,
) -> SessionKeys {
    let (pseudonym_public, pseudonym_secret) = update_pseudonym_session_key(
        current_keys.pseudonym.secret,
        old_shares.pseudonym,
        new_shares.pseudonym,
    );
    let (attribute_public, attribute_secret) = update_attribute_session_key(
        current_keys.attribute.secret,
        old_shares.attribute,
        new_shares.attribute,
    );

    SessionKeys {
        pseudonym: PseudonymSessionKeys {
            public: pseudonym_public,
            secret: pseudonym_secret,
        },
        attribute: AttributeSessionKeys {
            public: attribute_public,
            secret: attribute_secret,
        },
    }
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
    let bsk = make_blinded(&sk, &blinding_factors).unwrap();
    (pk, bsk, blinding_factors)
}

/// Setup a distributed system with pseudonym global keys, a blinded global secret key and a list of
/// blinding factors for pseudonyms.
/// The blinding factors should securely be transferred to the transcryptors ([`PEPSystem`](crate::distributed::systems::PEPSystem)s), the global public key
/// and blinded global secret key can be publicly shared with anyone and are required by [`PEPClient`](crate::distributed::systems::PEPClient)s.
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
/// The blinding factors should securely be transferred to the transcryptors ([`PEPSystem`](crate::distributed::systems::PEPSystem)s), the global public key
/// and blinded global secret key can be publicly shared with anyone and are required by [`PEPClient`](crate::distributed::systems::PEPClient)s.
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
/// The blinding factors should securely be transferred to the transcryptors ([`PEPSystem`](crate::distributed::systems::PEPSystem)s),
/// the global public keys and blinded global secret keys can be publicly shared with anyone and are
/// required by [`PEPClient`](crate::distributed::systems::PEPClient)s.
pub fn make_distributed_global_keys<R: RngCore + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (GlobalPublicKeys, BlindedGlobalKeys, Vec<BlindingFactor>) {
    let (pseudonym_pk, pseudonym_sk) = make_pseudonym_global_keys(rng);
    let (attribute_pk, attribute_sk) = make_attribute_global_keys(rng);

    let blinding_factors: Vec<BlindingFactor> =
        (0..n).map(|_| BlindingFactor::random(rng)).collect();

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
