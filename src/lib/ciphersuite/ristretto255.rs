//! The ciphersuite `ristretto255-SHA512`: the [`Ristretto255`] group with SHA-512, and its
//! raw-tag hash functions.
//!
//! [`hash_to_group_with_dst`] is the `hash_to_ristretto255` map (RFC 9380, Appendix B) and
//! [`hash_to_scalar_with_dst`] is `HashToScalar`, both with SHA-512 and both taking the complete
//! domain separation tag, as the RFC 9497 test vectors do. The protocol-level encoding,
//! [`hash_to_group`](super::hashing::hash_to_group), derives the tag from a ciphersuite's
//! [`CiphersuiteId`] instead.

use super::hashing::expand_message_xmd;
use super::{Ciphersuite, CiphersuiteId};
use crate::group::group_elements::GroupElement;
use crate::group::scalars::{ScalarCanBeZero, ScalarNonZero};
use crate::group::{Group, Ristretto255};
use sha2::Sha512;

///
/// Hashing to the group is `hash_to_ristretto255` (RFC 9380, Appendix B) and hashing to a scalar
/// reduces 64 bytes of `expand_message_xmd` output modulo the group order, both with SHA-512.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Ristretto255Sha512;

impl Ciphersuite for Ristretto255Sha512 {
    type Group = Ristretto255;
    type Hash = sha2::Sha512;

    const ID: CiphersuiteId = crate::ciphersuite!("ristretto255-SHA512");

    fn hash_to_group(msg: &[u8], dst: &[u8]) -> GroupElement {
        hash_to_group_with_dst(msg, dst)
    }

    fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Option<ScalarNonZero> {
        let uniform = expand_64(msg, dst);
        Ristretto255::scalar_from_uniform_bytes(&uniform)
    }
}

/// Expand `msg` under `dst` to 64 bytes with SHA-512, the uniform input both the group and the
/// scalar hash of the ristretto255-SHA512 ciphersuite are built from.
///
/// SHA-512 is fixed here because this is a ristretto255 primitive: it backs the raw-tag functions
/// below and the trait methods of `Ristretto255Sha512`, which the RFC 9380 and RFC 9497 test
/// vectors define with SHA-512. Code that is generic over a [`Ciphersuite`] reaches its hash
/// through [`Ciphersuite::Hash`] instead.
pub(crate) fn expand_64(msg: &[u8], dst: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&expand_message_xmd::<Sha512>(msg, dst, 64));
    out
}

/// `hash_to_ristretto255` (RFC 9380, Appendix B) with `expand_message_xmd` and SHA-512, as
/// `HashToGroup` of the ristretto255-SHA512 ciphersuite: expand `msg` under `dst`
/// to 64 bytes and apply the ristretto255 one-way map.
///
/// `dst` is the complete domain separation tag, e.g. `"HashToGroup-" || contextString`. To hash
/// under a ciphersuite's tag instead of a raw one, use [`hash_to_group`](crate::ciphersuite::hashing::hash_to_group).
#[must_use]
pub fn hash_to_group_with_dst(msg: &[u8], dst: &[u8]) -> GroupElement {
    GroupElement::from_hash(&expand_64(msg, dst))
}

/// `HashToScalar` of the ristretto255-SHA512 ciphersuite: expand `msg` under `dst`
/// to 64 bytes, interpret them as a little-endian integer and reduce it modulo the group order.
///
/// `dst` is the complete domain separation tag, e.g. `"HashToScalar-" || contextString`. The
/// result can be zero (with negligible probability); callers that need a non-zero scalar check.
///
/// Named for symmetry with [`hash_to_group_with_dst`]: both take a raw tag.
#[must_use]
pub fn hash_to_scalar_with_dst(msg: &[u8], dst: &[u8]) -> ScalarCanBeZero {
    ScalarCanBeZero::from_hash(&expand_64(msg, dst))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::group::scalars::ScalarTraits;

    /// The context string of the RFC 9497 `ristretto255-SHA512` test vectors.
    const OPRF_CONTEXT: &[u8] = b"OPRFV1-\x00-ristretto255-SHA512";

    /// RFC 9497, Appendix A.1.1: `DeriveKeyPair` is one `HashToScalar` call.
    #[test]
    fn hash_to_scalar_matches_oprf() {
        let seed = [0xa3u8; 32];
        let info = b"test key";
        let mut input = seed.to_vec();
        input.extend_from_slice(&(info.len() as u16).to_be_bytes());
        input.extend_from_slice(info);
        input.push(0); // counter
        let dst = [b"DeriveKeyPair".as_slice(), OPRF_CONTEXT].concat();
        let sk = Ristretto255Sha512::hash_to_scalar(&input, &dst).unwrap();
        assert_eq!(
            sk.to_hex(),
            "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e"
        );
    }

    /// RFC 9497, Appendix A.1.1: `BlindedElement = blind * HashToGroup(input)`.
    #[test]
    fn hash_to_group_matches_oprf() {
        let dst = [b"HashToGroup-".as_slice(), OPRF_CONTEXT].concat();
        let blind = ScalarNonZero::from_hex(
            "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
        )
        .unwrap();
        let blinded = blind * Ristretto255Sha512::hash_to_group(&[0x00], &dst);
        assert_eq!(
            blinded.to_hex(),
            "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c"
        );
        let blinded = blind * Ristretto255Sha512::hash_to_group(&[0x5a; 17], &dst);
        assert_eq!(
            blinded.to_hex(),
            "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418"
        );
    }

    /// RFC 9497, Appendix A.1.1 (ristretto255-SHA512, OPRF mode): the blinded element is
    /// `Blind * HashToGroup(Input)`.
    #[test]
    fn hash_to_group_matches_oprf_blinded_elements() {
        let dst = b"HashToGroup-OPRFV1-\x00-ristretto255-SHA512";
        let blind = ScalarNonZero::from_hex(
            "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
        )
        .unwrap();
        let cases = [
            (
                hex::decode("00").unwrap(),
                "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c",
            ),
            (
                hex::decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a").unwrap(),
                "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418",
            ),
        ];
        for (input, blinded) in cases {
            assert_eq!(
                (blind * hash_to_group_with_dst(&input, dst)).to_hex(),
                blinded
            );
        }
    }

    /// RFC 9497, Appendix A.1: the server key is `DeriveKeyPair(Seed, KeyInfo)`, one
    /// `HashToScalar` call with counter 0 in both modes.
    #[test]
    fn hash_to_scalar_matches_oprf_derive_key_pair() {
        let seed = [0xa3u8; 32];
        let info = b"test key";
        let mut derive_input = seed.to_vec();
        derive_input.extend_from_slice(&(info.len() as u16).to_be_bytes());
        derive_input.extend_from_slice(info);
        derive_input.push(0);
        let cases: [(&[u8], &str); 2] = [
            (
                b"DeriveKeyPairOPRFV1-\x00-ristretto255-SHA512",
                "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e",
            ),
            (
                b"DeriveKeyPairOPRFV1-\x01-ristretto255-SHA512",
                "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909",
            ),
        ];
        for (dst, expected) in cases {
            assert_eq!(
                hash_to_scalar_with_dst(&derive_input, dst).to_hex(),
                expected
            );
        }
    }

    #[test]
    fn domain_separation() {
        assert_ne!(
            hash_to_group_with_dst(b"x", b"a"),
            hash_to_group_with_dst(b"x", b"b")
        );
        assert_ne!(
            hash_to_scalar_with_dst(b"x", b"a"),
            hash_to_scalar_with_dst(b"x", b"b")
        );
        assert_eq!(
            hash_to_group_with_dst(b"x", b"a"),
            hash_to_group_with_dst(b"x", b"a")
        );
    }
}
