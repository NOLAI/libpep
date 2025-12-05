//! Session key shares and generation for distributed trust servers (transcryptors).

use crate::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
use crate::core::transcryption::contexts::{
    AttributeRekeyFactor, PseudonymRekeyFactor, RekeyFactor,
};
use crate::distributed::server::setup::BlindingFactor;
use derive_more::{Deref, From};
#[cfg(feature = "serde")]
use serde::de::{Error, Visitor};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use std::fmt::Formatter;

/// A pseudonym session key share, which is a part of a pseudonym session key provided by one transcryptor.
/// By combining all pseudonym session key shares and the [`BlindedPseudonymGlobalSecretKey`](crate::distributed::server::setup::BlindedPseudonymGlobalSecretKey), a pseudonym session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct PseudonymSessionKeyShare(pub(crate) ScalarNonZero);

/// An attribute session key share, which is a part of an attribute session key provided by one transcryptor.
/// By combining all attribute session key shares and the [`BlindedAttributeGlobalSecretKey`](crate::distributed::server::setup::BlindedAttributeGlobalSecretKey), an attribute session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct AttributeSessionKeyShare(pub(crate) ScalarNonZero);

/// A pair of session key shares containing both pseudonym and attribute shares.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionKeyShares {
    pub pseudonym: PseudonymSessionKeyShare,
    pub attribute: AttributeSessionKeyShare,
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

impl_scalar_encoding!(PseudonymSessionKeyShare);
impl_scalar_encoding!(AttributeSessionKeyShare);

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
impl_hex_serde_for_scalar_wrapper!(PseudonymSessionKeyShare);
#[cfg(feature = "serde")]
impl_hex_serde_for_scalar_wrapper!(AttributeSessionKeyShare);

/// Create a [`PseudonymSessionKeyShare`] from a [`PseudonymRekeyFactor`] and a [`BlindingFactor`].
pub fn make_pseudonym_session_key_share(
    rekey_factor: &PseudonymRekeyFactor,
    blinding_factor: &BlindingFactor,
) -> PseudonymSessionKeyShare {
    PseudonymSessionKeyShare(rekey_factor.scalar() * **blinding_factor)
}

/// Create an [`AttributeSessionKeyShare`] from an [`AttributeRekeyFactor`] and a [`BlindingFactor`].
pub fn make_attribute_session_key_share(
    rekey_factor: &AttributeRekeyFactor,
    blinding_factor: &BlindingFactor,
) -> AttributeSessionKeyShare {
    AttributeSessionKeyShare(rekey_factor.scalar() * **blinding_factor)
}

/// Create [`SessionKeyShares`] (both pseudonym and attribute) from rekey factors and a blinding factor.
pub fn make_session_key_shares(
    pseudonym_rekey_factor: &PseudonymRekeyFactor,
    attribute_rekey_factor: &AttributeRekeyFactor,
    blinding_factor: &BlindingFactor,
) -> SessionKeyShares {
    SessionKeyShares {
        pseudonym: make_pseudonym_session_key_share(pseudonym_rekey_factor, blinding_factor),
        attribute: make_attribute_session_key_share(attribute_rekey_factor, blinding_factor),
    }
}
