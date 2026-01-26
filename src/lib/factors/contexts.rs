//! Specification of [PseudonymizationDomain]s and [EncryptionContext]s and transcryption between them.
//! Based on simple string representations, this module provides the necessary types to describe
//! transcryption between different domains and sessions.

/// Pseudonymization domains are used to describe the domain in which pseudonyms exist (typically,
/// a user's role or usergroup).
///
/// With the `global-pseudonyms` feature enabled, domains can be `Global` (for pseudonyms that work across all domains).
/// With the `legacy` feature enabled, specific domains include an `audience_type` field.
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum PseudonymizationDomain {
    #[cfg(feature = "global-pseudonyms")]
    /// Global domain for pseudonyms
    Global,
    #[cfg(feature = "legacy")]
    /// Specific domain with payload and audience type (legacy mode)
    Specific { payload: String, audience_type: u32 },
    #[cfg(not(feature = "legacy"))]
    /// Specific domain with payload only
    Specific(String),
}

/// Encryption contexts are used to describe the context in which ciphertexts exist (typically, a
/// user's session).
///
/// With the `offline` feature enabled, contexts can be `Global` (for offline encryption).
/// With the `legacy` feature enabled, specific contexts include an `audience_type` field.
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum EncryptionContext {
    #[cfg(feature = "offline")]
    /// Global context for offline encryption
    Global,
    #[cfg(feature = "legacy")]
    /// Specific context with payload and audience type (legacy mode)
    Specific { payload: String, audience_type: u32 },
    #[cfg(not(feature = "legacy"))]
    /// Specific context with payload only
    Specific(String),
}

impl PseudonymizationDomain {
    /// Create a specific domain from a string payload
    #[cfg(feature = "legacy")]
    pub fn from(payload: &str) -> Self {
        PseudonymizationDomain::Specific {
            payload: payload.to_string(),
            audience_type: 0,
        }
    }

    /// Create a specific domain from a string payload
    #[cfg(not(feature = "legacy"))]
    pub fn from(payload: &str) -> Self {
        PseudonymizationDomain::Specific(payload.to_string())
    }

    /// Create a global domain (available only with global-pseudonyms feature)
    #[cfg(feature = "global-pseudonyms")]
    pub fn global() -> Self {
        PseudonymizationDomain::Global
    }

    /// Create a specific domain with audience type (legacy mode)
    #[cfg(feature = "legacy")]
    pub fn from_audience(payload: &str, audience_type: u32) -> Self {
        PseudonymizationDomain::Specific {
            payload: payload.to_string(),
            audience_type,
        }
    }
}

impl EncryptionContext {
    /// Create a specific context from a string payload
    #[cfg(feature = "legacy")]
    pub fn from(payload: &str) -> Self {
        EncryptionContext::Specific {
            payload: payload.to_string(),
            audience_type: 0,
        }
    }

    /// Create a specific context from a string payload
    #[cfg(not(feature = "legacy"))]
    pub fn from(payload: &str) -> Self {
        EncryptionContext::Specific(payload.to_string())
    }

    /// Create a global context (available only with offline feature)
    #[cfg(feature = "offline")]
    pub fn global() -> Self {
        EncryptionContext::Global
    }

    /// Create a specific context with audience type (legacy mode)
    #[cfg(feature = "legacy")]
    pub fn from_audience(payload: &str, audience_type: u32) -> Self {
        EncryptionContext::Specific {
            payload: payload.to_string(),
            audience_type,
        }
    }
}
