//! The protocol [`Context`]: the mode and ciphersuite identifier that every hash in the protocol
//! is domain-separated with, as in [RFC 9497], Section 3.1, and
//! [draft-doesburg-cfrg-coprf], Section "Context and Ciphersuite".
//!
//! Parties that exchange data agree on one context. Everything that hashes, i.e. factor
//! [derivation](crate::factors::derivation) and the
//! [`hash_to_group` encoding](crate::encodings::hash_to_group), takes a `&Context`, so two
//! deployments with different identifiers derive unrelated factors and pseudonyms from the same
//! secrets and inputs.
//!
//! This is unrelated to the [`contexts`](crate::contexts) module, whose
//! [`EncryptionContext`](crate::contexts::EncryptionContext) names a session *within* a
//! deployment.
//!
//! [RFC 9497]: https://www.rfc-editor.org/rfc/rfc9497
//! [draft-doesburg-cfrg-coprf]: https://datatracker.ietf.org/doc/draft-doesburg-cfrg-coprf/

use std::fmt;

/// The protocol mode, the second component of the context string.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Mode {
    /// Plain (non-verifiable) transcryption, `modeCoPRF = 0x00`.
    #[default]
    CoPRF = 0x00,
    /// Verifiable transcryption, `modeVcoPRF = 0x01`.
    VcoPRF = 0x01,
}

/// The identifier of the ristretto255-SHA512 ciphersuite, the default context identifier.
pub const RISTRETTO255_SHA512: &str = "ristretto255-SHA512";

/// Mode and ciphersuite identifier, from which the context string
/// `"coPRFV1-" || I2OSP(mode, 1) || "-" || identifier` is built.
///
/// The default context is [`Mode::CoPRF`] with identifier [`RISTRETTO255_SHA512`].
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Context {
    pub mode: Mode,
    pub identifier: Vec<u8>,
}

impl Context {
    /// A context with the given mode and identifier.
    pub fn new(mode: Mode, identifier: impl Into<Vec<u8>>) -> Self {
        Self {
            mode,
            identifier: identifier.into(),
        }
    }

    /// A context in [`Mode::CoPRF`] with the given identifier.
    pub fn from_identifier(identifier: impl Into<Vec<u8>>) -> Self {
        Self::new(Mode::CoPRF, identifier)
    }

    /// The context string `"coPRFV1-" || I2OSP(mode, 1) || "-" || identifier`.
    #[must_use]
    pub fn context_string(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(10 + self.identifier.len());
        s.extend_from_slice(b"coPRFV1-");
        s.push(self.mode as u8);
        s.push(b'-');
        s.extend_from_slice(&self.identifier);
        s
    }

    /// A domain separation tag: `label || contextString`.
    #[must_use]
    pub fn dst(&self, label: &[u8]) -> Vec<u8> {
        let mut dst = label.to_vec();
        dst.extend_from_slice(&self.context_string());
        dst
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::from_identifier(RISTRETTO255_SHA512)
    }
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "coPRFV1-{:02x}-{}",
            self.mode as u8,
            String::from_utf8_lossy(&self.identifier)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_context_string() {
        assert_eq!(
            Context::default().context_string(),
            b"coPRFV1-\x00-ristretto255-SHA512"
        );
        assert_eq!(
            Context::new(Mode::VcoPRF, "x").context_string(),
            b"coPRFV1-\x01-x"
        );
    }

    #[test]
    fn dst_prefixes_label() {
        assert_eq!(
            Context::default().dst(b"HashToGroup-"),
            b"HashToGroup-coPRFV1-\x00-ristretto255-SHA512"
        );
    }
}
