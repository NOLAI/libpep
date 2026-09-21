//! Hashing to the group and to scalars, following [RFC 9380] and the ristretto255-SHA512
//! ciphersuite of [RFC 9497].
//!
//! [`expand_message_xmd`] is the expander of RFC 9380, Section 5.3.1. [`hash_to_group`] is
//! `hash_to_ristretto255` (RFC 9380, Appendix B) with SHA-512; [`hash_to_scalar`] is the
//! `HashToScalar` of RFC 9497, Section 4.1. Both take the complete domain separation tag; the
//! protocol-level tags are assembled from a [`Context`](crate::protocol::Context).
//!
//! [`GroupElement::from_hash`] and [`ScalarCanBeZero::from_hash`] remain the low-level
//! primitives that map 64 uniform bytes to the group and to the scalar field.
//!
//! [RFC 9380]: https://www.rfc-editor.org/rfc/rfc9380
//! [RFC 9497]: https://www.rfc-editor.org/rfc/rfc9497

use super::group_elements::GroupElement;
use super::scalars::ScalarCanBeZero;
use sha2::digest::common::BlockSizeUser;
use sha2::{Digest, Sha512};

/// The longest domain separation tag that is used as is; longer tags are hashed first
/// (RFC 9380, Section 5.3.3).
const MAX_DST_LENGTH: usize = 255;

/// `expand_message_xmd` from RFC 9380, Section 5.3.1, for a Merkle-Damgård hash `H`.
///
/// Expands `msg` under the domain separation tag `dst` to `len_in_bytes` uniformly
/// pseudorandom bytes. A tag longer than 255 bytes is replaced by
/// `H("H2C-OVERSIZE-DST-" || dst)` as prescribed by Section 5.3.3.
///
/// # Panics
///
/// Panics if `len_in_bytes` exceeds 65535 or needs more than 255 hash blocks, the limits of
/// the expander.
#[must_use]
pub fn expand_message_xmd<H: Digest + BlockSizeUser>(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> Vec<u8> {
    let b_in_bytes = <H as Digest>::output_size();
    let s_in_bytes = H::block_size();
    let ell = len_in_bytes.div_ceil(b_in_bytes);
    assert!(
        ell <= 255 && len_in_bytes <= 65535,
        "expand_message_xmd: output length out of range"
    );

    let dst_prime = {
        let mut dst_prime = if dst.len() > MAX_DST_LENGTH {
            let mut h = H::new();
            h.update(b"H2C-OVERSIZE-DST-");
            h.update(dst);
            h.finalize().to_vec()
        } else {
            dst.to_vec()
        };
        // The tag is at most 255 bytes here, so its length fits in one byte.
        dst_prime.push(dst_prime.len() as u8);
        dst_prime
    };

    let mut h = H::new();
    h.update(vec![0u8; s_in_bytes]);
    h.update(msg);
    h.update((len_in_bytes as u16).to_be_bytes());
    h.update([0u8]);
    h.update(&dst_prime);
    let b_0 = h.finalize();

    let mut h = H::new();
    h.update(&b_0);
    h.update([1u8]);
    h.update(&dst_prime);
    let mut b_prev = h.finalize();

    let mut uniform_bytes = Vec::with_capacity(ell * b_in_bytes);
    uniform_bytes.extend_from_slice(&b_prev);
    for i in 2..=ell {
        let mut h = H::new();
        let xored: Vec<u8> = b_0.iter().zip(b_prev.iter()).map(|(a, b)| a ^ b).collect();
        h.update(xored);
        h.update([i as u8]);
        h.update(&dst_prime);
        b_prev = h.finalize();
        uniform_bytes.extend_from_slice(&b_prev);
    }
    uniform_bytes.truncate(len_in_bytes);
    uniform_bytes
}

/// Expand `msg` under `dst` to 64 bytes with SHA-512.
fn expand_64(msg: &[u8], dst: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&expand_message_xmd::<Sha512>(msg, dst, 64));
    out
}

/// `hash_to_ristretto255` (RFC 9380, Appendix B) with `expand_message_xmd` and SHA-512, as
/// `HashToGroup` of the ristretto255-SHA512 ciphersuite of RFC 9497: expand `msg` under `dst`
/// to 64 bytes and apply the ristretto255 one-way map.
///
/// `dst` is the complete domain separation tag, e.g. `"HashToGroup-" || contextString`.
#[must_use]
pub fn hash_to_group(msg: &[u8], dst: &[u8]) -> GroupElement {
    GroupElement::from_hash(&expand_64(msg, dst))
}

/// `HashToScalar` of the ristretto255-SHA512 ciphersuite of RFC 9497: expand `msg` under `dst`
/// to 64 bytes, interpret them as a little-endian integer and reduce it modulo the group order.
///
/// `dst` is the complete domain separation tag, e.g. `"HashToScalar-" || contextString`. The
/// result can be zero (with negligible probability); callers that need a non-zero scalar check.
#[must_use]
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> ScalarCanBeZero {
    ScalarCanBeZero::from_hash(&expand_64(msg, dst))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
    use sha2::Sha256;

    fn q128() -> Vec<u8> {
        let mut v = b"q128_".to_vec();
        v.extend(std::iter::repeat_n(b'q', 128));
        v
    }

    fn a512() -> Vec<u8> {
        let mut v = b"a512_".to_vec();
        v.extend(std::iter::repeat_n(b'a', 512));
        v
    }

    /// RFC 9380, Appendix K.1: expand_message_xmd(SHA-256).
    #[test]
    fn expand_message_xmd_sha256_vectors() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let cases: [(&[u8], &str); 4] = [
            (
                b"",
                "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
            ),
            (
                b"abc",
                "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
            ),
            (
                b"abcdef0123456789",
                "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
            ),
            (
                &q128(),
                "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9",
            ),
        ];
        for (msg, expected) in cases {
            assert_eq!(
                hex::encode(expand_message_xmd::<Sha256>(msg, dst, 0x20)),
                expected
            );
        }
    }

    /// RFC 9380, Appendix K.3: expand_message_xmd(SHA-512).
    #[test]
    fn expand_message_xmd_sha512_vectors() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA512-256";
        let short: [(&[u8], &str); 5] = [
            (
                b"",
                "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba",
            ),
            (
                b"abc",
                "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc",
            ),
            (
                b"abcdef0123456789",
                "087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58",
            ),
            (
                &q128(),
                "7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3",
            ),
            (
                &a512(),
                "57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4",
            ),
        ];
        for (msg, expected) in short {
            assert_eq!(
                hex::encode(expand_message_xmd::<Sha512>(msg, dst, 0x20)),
                expected
            );
        }
        let long: [(&[u8], &str); 5] = [
            (
                b"",
                "41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7eb00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961",
            ),
            (
                b"abc",
                "7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b488431851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1",
            ),
            (
                b"abcdef0123456789",
                "3f721f208e6199fe903545abc26c837ce59ac6fa45733f1baaf0222f8b7acb0424814fcb5eecf6c1d38f06e9d0a6ccfbf85ae612ab8735dfdf9ce84c372a77c8f9e1c1e952c3a61b7567dd0693016af51d2745822663d0c2367e3f4f0bed827feecc2aaf98c949b5ed0d35c3f1023d64ad1407924288d366ea159f46287e61ac",
            ),
            (
                &q128(),
                "b799b045a58c8d2b4334cf54b78260b45eec544f9f2fb5bd12fb603eaee70db7317bf807c406e26373922b7b8920fa29142703dd52bdf280084fb7ef69da78afdf80b3586395b433dc66cde048a258e476a561e9deba7060af40adf30c64249ca7ddea79806ee5beb9a1422949471d267b21bc88e688e4014087a0b592b695ed",
            ),
            (
                &a512(),
                "05b0bfef265dcee87654372777b7c44177e2ae4c13a27f103340d9cd11c86cb2426ffcad5bd964080c2aee97f03be1ca18e30a1f14e27bc11ebbd650f305269cc9fb1db08bf90bfc79b42a952b46daf810359e7bc36452684784a64952c343c52e5124cd1f71d474d5197fefc571a92929c9084ffe1112cf5eea5192ebff330b",
            ),
        ];
        for (msg, expected) in long {
            assert_eq!(
                hex::encode(expand_message_xmd::<Sha512>(msg, dst, 0x80)),
                expected
            );
        }
    }

    /// An oversized tag is hashed first; the result must differ from using a truncation and be
    /// stable.
    #[test]
    fn oversized_dst_is_hashed() {
        let dst = vec![b'x'; 300];
        let a = expand_message_xmd::<Sha512>(b"msg", &dst, 64);
        let b = expand_message_xmd::<Sha512>(b"msg", &dst, 64);
        assert_eq!(a, b);
        assert_ne!(a, expand_message_xmd::<Sha512>(b"msg", &dst[..255], 64));
    }

    /// RFC 9497, Appendix A.1.1 (ristretto255-SHA512, OPRF mode): the blinded element is
    /// `Blind * HashToGroup(Input)`.
    #[test]
    fn hash_to_group_matches_rfc9497_blinded_elements() {
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
            assert_eq!((blind * hash_to_group(&input, dst)).to_hex(), blinded);
        }
    }

    /// RFC 9497, Appendix A.1: the server key is `DeriveKeyPair(Seed, KeyInfo)`, one
    /// `HashToScalar` call with counter 0 in both modes.
    #[test]
    fn hash_to_scalar_matches_rfc9497_derive_key_pair() {
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
            assert_eq!(hash_to_scalar(&derive_input, dst).to_hex(), expected);
        }
    }

    #[test]
    fn domain_separation() {
        assert_ne!(hash_to_group(b"x", b"a"), hash_to_group(b"x", b"b"));
        assert_ne!(hash_to_scalar(b"x", b"a"), hash_to_scalar(b"x", b"b"));
        assert_eq!(hash_to_group(b"x", b"a"), hash_to_group(b"x", b"a"));
    }
}
