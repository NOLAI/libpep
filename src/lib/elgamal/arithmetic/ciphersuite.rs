//! The [`Ciphersuite`]: the group-and-hash pair the protocol's hashes are domain-separated with.
//!
//! A ciphersuite identifier names a group and a hash: `ristretto255-SHA512` is ristretto255
//! with SHA-512, `P256-SHA256` is P-256 with SHA-256. Each [`Group`](super::Group) implementation
//! fixes both (its `hash_to_group` and `hash_to_scalar` are written against one hash), so the
//! identifier belongs to the group and is reached through it as
//! [`Group::CIPHERSUITE`](super::Group::CIPHERSUITE). One group's identifier cannot be paired
//! with another group's operations.
//!
//! The identifier is taken verbatim from the ciphersuite table instead of being composed from
//! group and hash fragments: the table spells the P-256 suite `P256-SHA256` while the group
//! itself is called P-256, so a composed string would be wrong.
//!
//! # Domain separation
//!
//! Separation by ciphersuite matters for hashes that take no secret, where the input alone
//! determines the output and another protocol hashing the same input on the same group would get
//! the same element. [`hash_to_group`](super::hashing::hash_to_group) is such a hash: the
//! [`PREFIX`] keeps a pseudonym apart from other protocols' hashes of the same identifier on
//! ristretto255. The prefix reads `"nPEPV1-"` and is versioned independently of the crate; see
//! [`PREFIX`].
//!
//! Factor [derivation](crate::factors::derivation) hashes the length-prefixed transcryptor secret
//! together with the label and the length-prefixed domain or session identifier, so two
//! deployments derive unrelated factors because their secrets differ. The ciphersuite only
//! contributes the domain separation tag. The protocol's hashes are separated from each other by
//! the label of each tag (`"DeriveFactor-"`, `"HashToGroup-"`, `"HashToScalar-"`, and the proof
//! transcript's own labels).
//!
//! # Relation to the contexts module
//!
//! A [`Ciphersuite`] names the hash domain the whole protocol runs in. The
//! [`EncryptionContext`](crate::contexts::EncryptionContext) and
//! [`PseudonymizationDomain`](crate::contexts::PseudonymizationDomain) of the
//! [`contexts`](crate::contexts) module name a session and a domain within a deployment, and a
//! deployment uses those to separate its own data.

use std::fmt;

/// The prefix of every context string.
///
/// `nPEP` stands for n-PEP. `V1` versions the domain separation scheme, not the crate. A release
/// that changes neither the hashing construction nor the tag layout leaves it at `V1`. If that
/// construction ever changes incompatibly, the prefix becomes `nPEPV2-`, so deployments on either
/// side of the change derive unrelated values instead of silently disagreeing about the same ones.
pub const PREFIX: &str = "nPEPV1-";

/// A ciphersuite: the group-and-hash pair whose identifier the protocol's domain separation tags
/// are built from, as `"nPEPV1-" || identifier`.
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
    /// `"nPEPV1-" || identifier` at compile time, so the two cannot disagree.
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

    /// The context string `"nPEPV1-" || identifier`.
    ///
    /// Related protocols call this value `contextString`, and the name is kept so it is
    /// recognisable. It is unrelated to the [`contexts`](crate::contexts) module.
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

/// Define a [`Ciphersuite`] constant from its identifier. The context string is concatenated at
/// compile time, so the identifier is written once.
///
/// ```
/// # use libpep::ciphersuite;
/// # use libpep::elgamal::arithmetic::Ciphersuite;
/// const SUITE: Ciphersuite = ciphersuite!("ristretto255-SHA512");
/// assert_eq!(SUITE.context_string(), b"nPEPV1-ristretto255-SHA512");
/// ```
#[macro_export]
macro_rules! ciphersuite {
    ($identifier:literal) => {
        $crate::elgamal::arithmetic::Ciphersuite::new($identifier, concat!("nPEPV1-", $identifier))
    };
}

#[cfg(test)]
mod tests {
    use super::super::Ristretto255;
    use super::*;
    use crate::elgamal::arithmetic::Group;

    #[test]
    fn ristretto255_context_string() {
        // The context string is inside every DeriveFactor tag, so a change here
        // changes every derived factor and every hashed pseudonym.
        assert_eq!(
            Ristretto255::CIPHERSUITE.context_string(),
            b"nPEPV1-ristretto255-SHA512"
        );
        assert_eq!(
            Ristretto255::CIPHERSUITE.identifier(),
            "ristretto255-SHA512"
        );
    }

    #[test]
    fn macro_agrees_with_the_prefix() {
        const SUITE: Ciphersuite = ciphersuite!("x-Y");
        assert_eq!(SUITE.identifier(), "x-Y");
        assert_eq!(SUITE.context_string(), b"nPEPV1-x-Y");
    }

    #[test]
    fn dst_prefixes_label() {
        assert_eq!(
            Ristretto255::CIPHERSUITE.dst(b"HashToGroup-"),
            b"HashToGroup-nPEPV1-ristretto255-SHA512"
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
