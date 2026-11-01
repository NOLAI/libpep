//! [`PseudonymizationDomain`]s and [`EncryptionContext`]s: the identifiers that data is
//! pseudonymized and encrypted for, and the [`TranscryptorId`] that names a transcryptor.
//!
//! A transcryptor derives its secret reshuffle factor from a pseudonymization domain and its
//! secret rekey factor from an encryption context, so every user, which has its own domain and
//! context, gets pseudonyms and a session key that no other user can relate to its own.

/// Identifier of a transcryptor.
pub type TranscryptorId = String;

/// The pseudonymization domain: the domain in which a user knows data subjects by their
/// pseudonyms (typically one per user, role or user group). Pseudonyms of the same data subject
/// in different domains cannot be linked without the transcryptors, and the reshuffle factor is
/// specific to the domain.
///
/// With the `global-pseudonyms` feature, the domain can be `Global`, for pseudonyms that are the
/// same in every domain. With the `legacy` feature, a specific domain also carries an
/// `audience_type`.
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum PseudonymizationDomain {
    /// The global domain, with reshuffle factor 1.
    #[cfg(feature = "global-pseudonyms")]
    Global,
    /// A specific domain with a payload and an audience type (legacy mode).
    #[cfg(feature = "legacy")]
    Specific {
        /// The domain identifier.
        payload: String,
        /// The audience type of the legacy PEP repository.
        audience_type: u32,
    },
    /// A specific domain, identified by its payload.
    #[cfg(not(feature = "legacy"))]
    Specific(String),
}

/// The encryption context: the context in which a ciphertext is encrypted (typically a user's
/// session). Session keys and the rekey factor are specific to the context.
///
/// With the `offline` feature, the context can be `Global`, for ciphertexts encrypted towards
/// the global keys. With the `legacy` feature, a specific context also carries an
/// `audience_type`.
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum EncryptionContext {
    /// The global context, with rekey factor 1.
    #[cfg(feature = "offline")]
    Global,
    /// A specific context with a payload and an audience type (legacy mode).
    #[cfg(feature = "legacy")]
    Specific {
        /// The context identifier.
        payload: String,
        /// The audience type of the legacy PEP repository.
        audience_type: u32,
    },
    /// A specific context, identified by its payload.
    #[cfg(not(feature = "legacy"))]
    Specific(String),
}

macro_rules! impl_identifier {
    ($t:ident, $global_feature:literal) => {
        impl From<&str> for $t {
            /// A specific identifier from its payload (with the `legacy` feature: audience type 0).
            fn from(payload: &str) -> Self {
                String::from(payload).into()
            }
        }

        impl From<String> for $t {
            /// A specific identifier from its payload (with the `legacy` feature: audience type 0).
            fn from(payload: String) -> Self {
                #[cfg(feature = "legacy")]
                {
                    Self::Specific {
                        payload,
                        audience_type: 0,
                    }
                }
                #[cfg(not(feature = "legacy"))]
                {
                    Self::Specific(payload)
                }
            }
        }

        impl $t {
            /// The global identifier.
            #[cfg(feature = $global_feature)]
            pub fn global() -> Self {
                Self::Global
            }

            /// A specific identifier with an audience type (legacy mode).
            #[cfg(feature = "legacy")]
            pub fn from_audience(payload: &str, audience_type: u32) -> Self {
                Self::Specific {
                    payload: payload.to_string(),
                    audience_type,
                }
            }
        }
    };
}

impl_identifier!(PseudonymizationDomain, "global-pseudonyms");
impl_identifier!(EncryptionContext, "offline");
