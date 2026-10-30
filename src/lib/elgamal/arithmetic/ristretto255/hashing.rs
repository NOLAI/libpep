//! Hashing to the ristretto255 group and its scalars with raw domain separation tags: the
//! `hash_to_ristretto255` map (RFC 9380, Appendix B) and `HashToScalar`, both with SHA-512.
//!
//! These take the complete domain separation tag, which is what the test vectors exercise. The
//! protocol-level encoding, [`hash_to_group`](crate::elgamal::arithmetic::hashing::hash_to_group),
//! derives the tag from a group's [`Ciphersuite`](crate::elgamal::arithmetic::Ciphersuite)
//! instead.

use super::group_elements::GroupElement;
use super::scalars::ScalarCanBeZero;
use crate::elgamal::arithmetic::hashing::expand_message_xmd;
use sha2::Sha512;

/// Expand `msg` under `dst` to 64 bytes with SHA-512, the uniform input both the group and the
/// scalar hash of the ristretto255-SHA512 ciphersuite are built from.
///
/// SHA-512 is pinned here because this is a ristretto255 primitive, not a generic one: it backs
/// the raw-tag functions below and `Ristretto255`'s own trait methods, which the RFC 9380 and
/// published ristretto255-SHA512 test vectors exercise with SHA-512 by definition. Code that is generic over a
/// [`Group`] must reach the ciphersuite's hash through [`Group::Hash`] instead.
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
/// under a ciphersuite's tag instead of a raw one, use [`hash_to_group`](crate::elgamal::arithmetic::hashing::hash_to_group).
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
    use crate::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};

    /// OPRF test vector A.1.1 (ristretto255-SHA512, OPRF mode): the blinded element is
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

    /// OPRF test vector A.1: the server key is `DeriveKeyPair(Seed, KeyInfo)`, one
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
