//! The protocol [`Context`]: the mode and ciphersuite identifier that the protocol's hashes are
//! domain-separated with, as in [RFC 9497], Section 3.1, and [draft-doesburg-cfrg-coprf],
//! Section "Context and Ciphersuite".
//!
//! The context is a property of the ciphersuite, not a per-call parameter. It is fixed for a
//! build: [`ciphersuite()`] is the context of the ciphersuite this crate implements, and the
//! protocol's hashes use it internally.
//!
//! # Where the context does and does not separate
//!
//! Domain separation by context matters where a hash takes **no secret**, so that the hash input
//! alone determines the output and another protocol hashing the same input on the same group
//! would get the same element. That is the case for [`hash_to_group`](crate::encodings::hash_to_group),
//! which is why it takes an explicit `&Context`: the `"coPRFV1-"` prefix is what separates a
//! pseudonym from an RFC 9497 OPRF evaluation of the same identifier on ristretto255.
//!
//! Factor [derivation](crate::factors::derivation) is the opposite case. It hashes the
//! length-prefixed transcryptor secret together with the label and the length-prefixed domain or
//! session identifier, so two deployments already derive unrelated factors because their secrets
//! differ. The context adds only the domain separation tag, so factor derivation does not take a
//! context: it uses [`ciphersuite()`].
//!
//! This is unrelated to the [`contexts`](crate::contexts) module, whose
//! [`EncryptionContext`](crate::contexts::EncryptionContext) and
//! [`PseudonymizationDomain`](crate::contexts::PseudonymizationDomain) name a session and a domain
//! *within* a deployment. Those, not the protocol context, are how a deployment separates its own
//! sessions and domains.
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

/// The context of the ciphersuite this crate implements: [`Mode::CoPRF`] with identifier
/// [`RISTRETTO255_SHA512`].
///
/// This is what the protocol's internal hashes, in particular factor
/// [derivation](crate::factors::derivation), are domain-separated with. It is fixed for a build
/// because the ciphersuite is: a deployment separates its own sessions and domains with an
/// [`EncryptionContext`](crate::contexts::EncryptionContext) and a
/// [`PseudonymizationDomain`](crate::contexts::PseudonymizationDomain), not by varying this.
#[must_use]
pub fn ciphersuite() -> Context {
    Context::from_identifier(RISTRETTO255_SHA512)
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
    fn ciphersuite_is_the_default_context() {
        assert_eq!(ciphersuite(), Context::default());
        assert_eq!(ciphersuite().mode, Mode::CoPRF);
        assert_eq!(ciphersuite().identifier, RISTRETTO255_SHA512.as_bytes());
    }

    #[test]
    fn dst_prefixes_label() {
        assert_eq!(
            Context::default().dst(b"HashToGroup-"),
            b"HashToGroup-coPRFV1-\x00-ristretto255-SHA512"
        );
    }
}
