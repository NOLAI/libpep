//! The [`Ciphersuite`]: a [`Group`] together with the hash its protocol runs on, and the
//! [`hashing`] to the group and to scalars that runs under it.
//!
//! A [`Group`] is pure group arithmetic. Everything that hashes (encoding an identifier as a
//! group element, deriving factors, the Fiat-Shamir challenges of the proofs) needs more: a hash
//! function, the maps from hash output to elements and scalars, and an identifier that keeps the
//! domain separation tags of one ciphersuite apart from another. A [`Ciphersuite`] bundles these,
//! and reaches its group as `C::Group`. The split between the two traits is described in the
//! [crate docs](crate#groups-and-ciphersuites).
//!
//! A ciphersuite is named by a [`CiphersuiteId`], such as `ristretto255-SHA512` for ristretto255
//! with SHA-512 (the marker [`Ristretto255Sha512`]). The identifier is
//! written out in full for each ciphersuite and not composed from the names of the group and the
//! hash, because those do not always combine into the usual identifier: P-256 with SHA-256 is
//! `P256-SHA256`.
//!
//! # Domain separation
//!
//! Separation by ciphersuite matters for hashes that take no secret: the input alone determines
//! the output, so another protocol hashing the same input on the same group would get the same
//! element. [`hash_to_group`](hashing::hash_to_group) is such a hash, and the [`PREFIX`]
//! (`"nPEPV1-"`, versioned independently of the crate) keeps a pseudonym apart from those.
//!
//! Factor [derivation](crate::factors::derivation) hashes the transcryptor secret, so two
//! deployments derive unrelated factors because their secrets differ. The ciphersuite only
//! contributes the domain separation tag. The protocol's hashes are separated from each other by
//! the label of each tag (`"DeriveFactor-"`, `"HashToGroup-"`, `"HashToScalar-"`, and the proof
//! transcript's own labels).
//!
//! A [`CiphersuiteId`] is not an [`EncryptionContext`](crate::contexts::EncryptionContext) or a
//! [`PseudonymizationDomain`](crate::contexts::PseudonymizationDomain): it names the hash domain
//! of the whole protocol, while those name a session and a domain within a deployment.

pub mod hashing;
pub mod ristretto255;

pub use ristretto255::Ristretto255Sha512;

use crate::group::Group;
use sha2::digest::common::BlockSizeUser;
use sha2::Digest;
use std::fmt;

/// The prefix of every context string.
///
/// `nPEP` stands for n-PEP. `V1` versions the domain separation scheme, not the crate. A release
/// that changes neither the hashing construction nor the tag layout leaves it at `V1`. If that
/// construction ever changes incompatibly, the prefix becomes `nPEPV2-`, so deployments on either
/// side of the change derive unrelated values instead of silently disagreeing about the same ones.
pub const PREFIX: &str = "nPEPV1-";

/// The element type of the group of ciphersuite `C`.
#[cfg(any(feature = "verifiable", feature = "verifiable-derivation"))]
pub(crate) type ElementOf<C> = <<C as Ciphersuite>::Group as Group>::Element;
/// The non-zero scalar type of the group of ciphersuite `C`.
#[cfg(any(feature = "verifiable", feature = "verifiable-derivation"))]
pub(crate) type ScalarOf<C> = <<C as Ciphersuite>::Group as Group>::Scalar;
/// The possibly-zero scalar type of the group of ciphersuite `C`.
#[cfg(any(feature = "verifiable", feature = "verifiable-derivation"))]
pub(crate) type ScalarCanBeZeroOf<C> = <<C as Ciphersuite>::Group as Group>::ScalarCanBeZero;

/// A ciphersuite: a [`Group`] together with the hash and the maps from hash output to elements
/// and scalars that the protocol's hashes are built from.
///
/// A ciphersuite is a marker type: it carries no data. Implement it for a new unit struct, naming
/// its group and hash, and give it an identifier with the [`ciphersuite!`](macro@crate::ciphersuite)
/// macro. [`Ristretto255Sha512`] is the ciphersuite of ristretto255
/// with SHA-512.
pub trait Ciphersuite:
    Copy + Clone + std::fmt::Debug + Default + Eq + Send + Sync + 'static
{
    /// The group this ciphersuite computes in.
    type Group: Group;

    /// The hash this ciphersuite is named after: `SHA-512` for `ristretto255-SHA512`.
    ///
    /// It is declared next to [`ID`](Self::ID) so that the identifier and the hash cannot drift
    /// apart. It is not necessarily the hash inside [`hash_to_group`](Self::hash_to_group) and
    /// [`hash_to_scalar`](Self::hash_to_scalar), which may use the expander RFC 9380 prescribes
    /// for the group.
    type Hash: Digest + BlockSizeUser;

    /// The identifier of this ciphersuite, whose context string the protocol's domain separation
    /// tags are built from.
    ///
    /// Build it with the [`ciphersuite!`](macro@crate::ciphersuite) macro from the identifier, for
    /// example `"ristretto255-SHA512"`.
    const ID: CiphersuiteId;

    /// `HashToGroup(msg, dst)`: a deterministic map of an arbitrary byte string to a group
    /// element, indifferentiable from a random oracle; RFC 9380 hash-to-curve with domain
    /// separation tag `dst`.
    fn hash_to_group(msg: &[u8], dst: &[u8]) -> <Self::Group as Group>::Element;

    /// `HashToScalar(msg, dst)`: a deterministic map of an arbitrary byte string to a scalar,
    /// indifferentiable from a random oracle. Returns `None` if the scalar is zero.
    fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Option<<Self::Group as Group>::Scalar>;
}

/// The identifier of a [`Ciphersuite`], from which the protocol's domain separation tags are
/// built, as `"nPEPV1-" || identifier`.
///
/// Reached through [`Ciphersuite::ID`]; see the [module documentation](self).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct CiphersuiteId {
    identifier: &'static str,
    context_string: &'static str,
}

impl CiphersuiteId {
    /// The identifier with the given name and the context string it implies.
    ///
    /// Public only for the [`ciphersuite!`](macro@crate::ciphersuite) macro, which a [`Ciphersuite`]
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
    /// This value is called `contextString` in the descriptions of the tags. It is unrelated to
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

impl fmt::Display for CiphersuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.context_string)
    }
}

/// Define a [`CiphersuiteId`] constant from its identifier. The context string is concatenated at
/// compile time, so the identifier is written once.
///
/// ```
/// # use libpep::ciphersuite;
/// # use libpep::ciphersuite::CiphersuiteId;
/// const SUITE: CiphersuiteId = ciphersuite!("ristretto255-SHA512");
/// assert_eq!(SUITE.context_string(), b"nPEPV1-ristretto255-SHA512");
/// ```
#[macro_export]
macro_rules! ciphersuite {
    ($identifier:literal) => {
        $crate::ciphersuite::CiphersuiteId::new($identifier, concat!("nPEPV1-", $identifier))
    };
}

#[cfg(test)]
mod tests {
    use super::Ristretto255Sha512;
    use super::*;

    #[test]
    fn ristretto255_context_string() {
        // The context string is inside every DeriveFactor tag, so a change here
        // changes every derived factor and every hashed pseudonym.
        assert_eq!(
            Ristretto255Sha512::ID.context_string(),
            b"nPEPV1-ristretto255-SHA512"
        );
        assert_eq!(Ristretto255Sha512::ID.identifier(), "ristretto255-SHA512");
    }

    #[test]
    fn macro_agrees_with_the_prefix() {
        const SUITE: CiphersuiteId = ciphersuite!("x-Y");
        assert_eq!(SUITE.identifier(), "x-Y");
        assert_eq!(SUITE.context_string(), b"nPEPV1-x-Y");
    }

    #[test]
    fn dst_prefixes_label() {
        assert_eq!(
            Ristretto255Sha512::ID.dst(b"HashToGroup-"),
            b"HashToGroup-nPEPV1-ristretto255-SHA512"
        );
    }

    #[test]
    fn display_matches_the_context_string() {
        assert_eq!(
            Ristretto255Sha512::ID.to_string().as_bytes(),
            Ristretto255Sha512::ID.context_string()
        );
    }
}
