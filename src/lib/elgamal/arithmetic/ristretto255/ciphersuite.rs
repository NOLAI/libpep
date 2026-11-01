//! The ciphersuite `ristretto255-SHA512`.

use super::group_elements::GroupElement;
use super::scalars::ScalarNonZero;
use super::Ristretto255;
use crate::elgamal::arithmetic::ciphersuite::{Ciphersuite, CiphersuiteId};
use crate::elgamal::arithmetic::group::Group;

/// The ciphersuite `ristretto255-SHA512`: the [`Ristretto255`] group with SHA-512.
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
        super::hashing::hash_to_group_with_dst(msg, dst)
    }

    fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Option<ScalarNonZero> {
        let uniform = super::hashing::expand_64(msg, dst);
        Ristretto255::scalar_from_uniform_bytes(&uniform)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::elgamal::arithmetic::scalars::ScalarTraits;

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
}
