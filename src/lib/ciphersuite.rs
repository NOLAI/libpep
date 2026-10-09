//! The [`Ciphersuite`]: the identifier that the protocol's hashes are domain-separated with, as
//! in [RFC 9497], Section 3.1, and [draft-doesburg-cfrg-coprf], Section "Context and
//! Ciphersuite".
//!
//! The ciphersuite is not a per-call parameter. It is fixed for a build:
//! [`Ciphersuite::current`] is the one this crate implements, and the protocol's hashes use it
//! internally.
//!
//! # Where the ciphersuite does and does not separate
//!
//! Domain separation by ciphersuite matters where a hash takes **no secret**, so that the hash
//! input alone determines the output and another protocol hashing the same input on the same
//! group would get the same element. That is the case for
//! [`hash_to_group`](crate::encodings::hash_to_group), which is why it takes an explicit
//! `&Ciphersuite`: the `"coPRFV1-"` prefix is what separates a pseudonym from an RFC 9497 OPRF
//! evaluation of the same identifier on ristretto255.
//!
//! Factor [derivation](crate::factors::derivation) is the opposite case. It hashes the
//! length-prefixed transcryptor secret together with the label and the length-prefixed domain or
//! session identifier, so two deployments already derive unrelated factors because their secrets
//! differ. The ciphersuite adds only the domain separation tag, so factor derivation does not take
//! one: it uses [`Ciphersuite::current`].
//!
//! # Why there is no mode
//!
//! RFC 9497 puts a mode byte in its context string, separating its OPRF, VOPRF and POPRF
//! variants. This protocol has no such split. Verifiable transcryption derives the *same* factors
//! as plain transcryption and adds commitments and proofs on top: the draft's factor commitments
//! are `DeriveFactor(...) * G`, the ordinary factor times the generator. A mode byte would make a
//! verifiable transcryptor derive different keys than a plain one for the same session, so the two
//! could not interoperate. What separates the protocol's hashes from each other is the label of
//! each tag (`"DeriveFactor-"`, `"HashToGroup-"`, `"HashToScalar-"`, and the proof transcript's own
//! labels), not a mode.
//!
//! # Not to be confused with the contexts module
//!
//! A [`Ciphersuite`] names the hash domain the whole protocol runs in. The
//! [`EncryptionContext`](crate::contexts::EncryptionContext) and
//! [`PseudonymizationDomain`](crate::contexts::PseudonymizationDomain) of the
//! [`contexts`](crate::contexts) module name a session and a domain *within* a deployment, and
//! those are how a deployment separates its own data.
//!
//! [RFC 9497]: https://www.rfc-editor.org/rfc/rfc9497
//! [draft-doesburg-cfrg-coprf]: https://datatracker.ietf.org/doc/draft-doesburg-cfrg-coprf/

use std::fmt;

/// The identifier of the ristretto255-SHA512 ciphersuite, the one this crate implements.
pub const RISTRETTO255_SHA512: &str = "ristretto255-SHA512";

/// A ciphersuite identifier, from which the context string `"coPRFV1-" || identifier` is built.
///
/// [`Ciphersuite::current`] is the ciphersuite this crate implements.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ciphersuite(pub Vec<u8>);

impl Ciphersuite {
    /// A ciphersuite with the given identifier.
    pub fn new(identifier: impl Into<Vec<u8>>) -> Self {
        Self(identifier.into())
    }

    /// The ciphersuite this crate implements, identifier [`RISTRETTO255_SHA512`].
    ///
    /// This is what the protocol's internal hashes, in particular factor
    /// [derivation](crate::factors::derivation), are domain-separated with. It is fixed for a
    /// build: a deployment separates its own sessions and domains with an
    /// [`EncryptionContext`](crate::contexts::EncryptionContext) and a
    /// [`PseudonymizationDomain`](crate::contexts::PseudonymizationDomain), not by varying this.
    #[must_use]
    pub fn current() -> Self {
        Self::new(RISTRETTO255_SHA512)
    }

    /// The ciphersuite identifier.
    #[must_use]
    pub fn identifier(&self) -> &[u8] {
        &self.0
    }

    /// The context string `"coPRFV1-" || identifier`.
    ///
    /// The name is the spec's: RFC 9497 and the draft both call this value `contextString`, so it
    /// stays recognisable to anyone reading either document next to this code. It is unrelated to
    /// the [`contexts`](crate::contexts) module.
    #[must_use]
    pub fn context_string(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(8 + self.0.len());
        s.extend_from_slice(b"coPRFV1-");
        s.extend_from_slice(&self.0);
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

impl Default for Ciphersuite {
    fn default() -> Self {
        Self::current()
    }
}

impl fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "coPRFV1-{}", String::from_utf8_lossy(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_context_string() {
        assert_eq!(
            Ciphersuite::default().context_string(),
            b"coPRFV1-ristretto255-SHA512"
        );
        assert_eq!(Ciphersuite::new("x").context_string(), b"coPRFV1-x");
    }

    #[test]
    fn context_string_is_prefixed_against_rfc9497() {
        // RFC 9497 builds "OPRFV1-" || mode || "-" || identifier, so an OPRF on the same group
        // never shares a domain separation tag with this protocol.
        let s = Ciphersuite::default().context_string();
        assert!(s.starts_with(b"coPRFV1-"));
        assert!(!s.starts_with(b"OPRFV1-"));
    }

    #[test]
    fn current_is_the_default() {
        assert_eq!(Ciphersuite::current(), Ciphersuite::default());
        assert_eq!(
            Ciphersuite::current().identifier(),
            RISTRETTO255_SHA512.as_bytes()
        );
    }

    #[test]
    fn dst_prefixes_label() {
        assert_eq!(
            Ciphersuite::default().dst(b"HashToGroup-"),
            b"HashToGroup-coPRFV1-ristretto255-SHA512"
        );
    }

    #[test]
    fn display_matches_the_context_string() {
        assert_eq!(
            Ciphersuite::default().to_string().as_bytes(),
            Ciphersuite::default().context_string()
        );
    }
}
