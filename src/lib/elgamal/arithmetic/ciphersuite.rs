//! The [`Ciphersuite`]: the group-and-hash pair the protocol's hashes are domain-separated with,
//! as in [RFC 9497], Section 3.1, and [draft-doesburg-cfrg-coprf], Section "Context and
//! Ciphersuite".
//!
//! A ciphersuite identifier names a group *and* a hash: `ristretto255-SHA512` is ristretto255
//! with SHA-512, `P256-SHA256` is P-256 with SHA-256. Each [`Group`](super::Group) implementation
//! fixes both — its `hash_to_group` and `hash_to_scalar` are written against one hash — so the
//! identifier belongs to the group and is reached through it as
//! [`Group::CIPHERSUITE`](super::Group::CIPHERSUITE). There is no way to pair one group's
//! identifier with another group's operations.
//!
//! The identifier is taken verbatim from the draft's ciphersuite table rather than composed from
//! group and hash fragments: the table spells the P-256 suite `P256-SHA256` while the group
//! itself is called P-256, so a composed string would be wrong.
//!
//! # Where the ciphersuite does and does not separate
//!
//! Domain separation by ciphersuite matters where a hash takes **no secret**, so that the hash
//! input alone determines the output and another protocol hashing the same input on the same
//! group would get the same element. That is the case for
//! [`hash_to_group`](super::hashing::hash_to_group): the [`PREFIX`] is what separates a
//! pseudonym from an RFC 9497 OPRF evaluation of the same identifier on ristretto255. It reads
//! `"coPRFV1-"`, for the convertible OPRF abstraction of Lehmann's ScrambleDB that this protocol
//! builds on, versioned independently of the crate; see [`PREFIX`] for both halves of that name.
//!
//! Factor [derivation](crate::factors::derivation) is the opposite case. It hashes the
//! length-prefixed transcryptor secret together with the label and the length-prefixed domain or
//! session identifier, so two deployments already derive unrelated factors because their secrets
//! differ. The ciphersuite adds only the domain separation tag.
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

/// The prefix of every context string, distinguishing this protocol from RFC 9497's `"OPRFV1-"`
/// on the same group.
///
/// `coPRF` is a *convertible* oblivious pseudorandom function. Convertibility is what separates
/// it from the plain OPRF of RFC 9497: a transcryptor converts an output from one domain to
/// another without learning either the input or the output. The abstraction is due to Lehmann's
/// ScrambleDB work, which named it; this protocol builds on it rather than introducing it.
///
/// `V1` versions the domain separation scheme, **not the crate**: the two are independent, and
/// a release that changes neither the hashing
/// construction nor the tag layout leaves this at `V1`. Should that construction ever change
/// incompatibly, the prefix becomes `coPRFV2-`, so deployments on either side of the change
/// derive unrelated values instead of silently disagreeing about the same ones.
///
/// The shape deliberately parallels `"OPRFV1-"`: a sibling construction, with separated domains
/// on the same group.
pub const PREFIX: &str = "coPRFV1-";

/// A ciphersuite: the group-and-hash pair whose identifier the protocol's domain separation tags
/// are built from, as `"coPRFV1-" || identifier`.
///
/// Reached through [`Group::CIPHERSUITE`](super::Group::CIPHERSUITE); see the
/// [module documentation](self).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Ciphersuite {
    identifier: &'static str,
    context_string: &'static str,
}

impl Ciphersuite {
    /// The ciphersuite with the given identifier and the context string it implies.
    ///
    /// Public only for the [`ciphersuite!`](crate::ciphersuite) macro, which a [`Group`](super::Group)
    /// implementation outside this crate expands; it builds `context_string` as
    /// `"coPRFV1-" || identifier` at compile time, so the two cannot disagree.
    #[doc(hidden)]
    #[must_use]
    pub const fn new(identifier: &'static str, context_string: &'static str) -> Self {
        Self {
            identifier,
            context_string,
        }
    }

    /// The ciphersuite identifier, e.g. `ristretto255-SHA512`.
    #[must_use]
    pub const fn identifier(&self) -> &'static str {
        self.identifier
    }

    /// The context string `"coPRFV1-" || identifier`.
    ///
    /// The name is the spec's: RFC 9497 and the draft both call this value `contextString`, so it
    /// stays recognisable to anyone reading either document next to this code. It is unrelated to
    /// the [`contexts`](crate::contexts) module.
    #[must_use]
    pub const fn context_string(&self) -> &'static [u8] {
        self.context_string.as_bytes()
    }

    /// A domain separation tag: `label || contextString`.
    #[must_use]
    pub fn dst(&self, label: &[u8]) -> Vec<u8> {
        let context_string = self.context_string();
        let mut dst = Vec::with_capacity(label.len() + context_string.len());
        dst.extend_from_slice(label);
        dst.extend_from_slice(context_string);
        dst
    }
}

impl fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.context_string)
    }
}

/// Define a [`Ciphersuite`] constant from its identifier, concatenating the context string at
/// compile time so that the identifier appears once.
///
/// ```
/// # use libpep::ciphersuite;
/// # use libpep::elgamal::arithmetic::Ciphersuite;
/// const SUITE: Ciphersuite = ciphersuite!("ristretto255-SHA512");
/// assert_eq!(SUITE.context_string(), b"coPRFV1-ristretto255-SHA512");
/// ```
#[macro_export]
macro_rules! ciphersuite {
    ($identifier:literal) => {
        $crate::elgamal::arithmetic::Ciphersuite::new($identifier, concat!("coPRFV1-", $identifier))
    };
}

#[cfg(test)]
mod tests {
    use super::super::Ristretto255;
    use super::*;
    use crate::elgamal::arithmetic::Group;

    #[test]
    fn ristretto255_context_string() {
        // Pinned exactly: the context string is inside every DeriveFactor tag, so a change here
        // changes every derived factor and every hashed pseudonym.
        assert_eq!(
            Ristretto255::CIPHERSUITE.context_string(),
            b"coPRFV1-ristretto255-SHA512"
        );
        assert_eq!(
            Ristretto255::CIPHERSUITE.identifier(),
            "ristretto255-SHA512"
        );
    }

    #[test]
    fn context_string_is_prefixed_against_rfc9497() {
        // RFC 9497 builds "OPRFV1-" || mode || "-" || identifier, so an OPRF on the same group
        // never shares a domain separation tag with this protocol.
        let s = Ristretto255::CIPHERSUITE.context_string();
        assert!(s.starts_with(PREFIX.as_bytes()));
        assert!(!s.starts_with(b"OPRFV1-"));
    }

    #[test]
    fn macro_agrees_with_the_prefix() {
        const SUITE: Ciphersuite = ciphersuite!("x-Y");
        assert_eq!(SUITE.identifier(), "x-Y");
        assert_eq!(SUITE.context_string(), b"coPRFV1-x-Y");
    }

    #[test]
    fn dst_prefixes_label() {
        assert_eq!(
            Ristretto255::CIPHERSUITE.dst(b"HashToGroup-"),
            b"HashToGroup-coPRFV1-ristretto255-SHA512"
        );
    }

    #[test]
    fn display_matches_the_context_string() {
        assert_eq!(
            Ristretto255::CIPHERSUITE.to_string().as_bytes(),
            Ristretto255::CIPHERSUITE.context_string()
        );
    }
}
