//! Hashing to the group and to scalars under a [`Ciphersuite`], following [RFC 9380].
//!
//! [`expand_message_xmd`] is the expander of RFC 9380, Section 5.3.1. It hashes a message to any
//! number of bytes under a domain separation tag, and the groups map those bytes to elements and
//! scalars. It is checked against the RFC's test vectors.
//!
//! [`hash_to_group_generic`] is the protocol-level encoding. It builds the tag from the
//! ciphersuite's [`CiphersuiteId`](super::CiphersuiteId) as `"HashToGroup-" || contextString`,
//! the shape of `HashToGroup` for ristretto255 in [RFC 9497], Section 4.1, with the library's own
//! context string. The raw-tag functions for
//! ristretto255, [`hash_to_group_with_dst`] and [`hash_to_scalar_with_dst`], are in
//! [`ristretto255`](super::ristretto255) and re-exported here.
//!
//! [RFC 9380]: https://www.rfc-editor.org/rfc/rfc9380
//! [RFC 9497]: https://www.rfc-editor.org/rfc/rfc9497

use super::ristretto255::Ristretto255Sha512;
use super::Ciphersuite;
use crate::group::group_elements::GroupElement;
use crate::group::scalars::ScalarNonZero;
use crate::group::Group;
use sha2::digest::common::BlockSizeUser;
use sha2::Digest;

pub use super::ristretto255::{hash_to_group_with_dst, hash_to_scalar_with_dst};

/// The longest domain separation tag that is used as is; longer tags are hashed first
/// (RFC 9380, Section 5.3.3).
const MAX_DST_LENGTH: usize = 255;

/// Hash `parts` with the ciphersuite's hash and reduce the digest to a non-zero scalar, with zero
/// mapped to one.
///
/// This is the Fiat-Shamir challenge of the proofs in `elgamal::zkps` and the
/// hash of the Carter-Wegman derivation (`factors::verifiable`). On ristretto255-SHA512
/// it is the SHA-512 digest reduced modulo the group order. A digest of any other length is
/// zero-padded or truncated to the 64 bytes the reduction takes.
pub fn hash_to_nonzero_scalar_generic<C: Ciphersuite>(
    parts: &[&[u8]],
) -> <C::Group as Group>::Scalar {
    let mut hasher = C::Hash::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 64];
    let n = digest.len().min(64);
    bytes[..n].copy_from_slice(&digest[..n]);
    C::Group::scalar_from_uniform_bytes(&bytes).unwrap_or_else(C::Group::scalar_one)
}

/// [`hash_to_nonzero_scalar_generic`] for ristretto255 with SHA-512.
pub fn hash_to_nonzero_scalar(parts: &[&[u8]]) -> ScalarNonZero {
    hash_to_nonzero_scalar_generic::<Ristretto255Sha512>(parts)
}

/// `expand_message_xmd` from RFC 9380, Section 5.3.1: hash `msg` to any requested number of
/// bytes, under a label.
///
/// `H` returns a fixed number of bytes; this returns `len_in_bytes` of them by chaining `H` over
/// a counter. The tag `dst` is mixed into every block, so the same message under two tags gives
/// unrelated outputs. Its length is appended to it, so a message cannot be mistaken for a tag.
///
/// `xmd` names the variant for Merkle-Damgård hashes, which have an internal block size (SHA-512,
/// for example). `expand_message_xof` is built on an extendable-output function such as SHAKE
/// and gives different output.
///
/// A tag longer than 255 bytes cannot carry a one-byte length, so it is replaced by
/// `H("H2C-OVERSIZE-DST-" || dst)` (Section 5.3.3).
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

/// Encode an input as a group element: `HashToGroup(x)` under the domain separation tag
/// `"HashToGroup-" || contextString` of `C`'s ciphersuite identifier.
///
/// This is the only encoding available on every ciphersuite. It is not invertible: the origin
/// party recognizes a pseudonym as belonging to `x` only by recomputing it. For an invertible
/// encoding on ristretto255, see
/// [`GroupElement::from_lizard`](crate::group::group_elements::GroupElement::from_lizard).
///
/// No secret enters this hash, unlike factor derivation, so another protocol hashing the same
/// input on the same group would get the same element. The `"nPEPV1-"` prefix of the
/// ciphersuite's identifier keeps a pseudonym apart from those hashes.
///
/// # Input length
///
/// `x` goes straight to `HashToGroup`, without a prior hash. A pre-hash adds no collision
/// resistance, since a collision in `HashToGroup(H(x))` is a collision in `H` or in
/// `HashToGroup`, and it makes the pseudonyms differ from those of an implementation that
/// computes `HashToGroup(x)`. The one exception bounds the input length: an `x` of 2^16 bytes or
/// more is reduced with [`C::Hash`](Ciphersuite::Hash) first.
///
/// # Encoding requirement
///
/// Reshuffling is linear: the pseudonym of `M` in domain `d` is `s_d * M`, so for any `M_1` and
/// `M_2 = a * M_1` the pseudonyms satisfy the same relation in every domain. Cross-domain
/// unlinkability holds under DDH only for elements whose mutual discrete-log relations are
/// unknown to everyone, so an encoding MUST make it infeasible to produce two encoded inputs
/// with a known discrete-log relation. Encoding an identifier `x` as `x * G`, or as any scalar
/// multiple of a fixed element, violates this and is forbidden. This function satisfies the
/// requirement through the random oracle property of hashing to the group.
/// [`GroupElement::from_lizard`](crate::group::group_elements::GroupElement::from_lizard) satisfies it
/// heuristically and without proof: it is not a random oracle, but a related encoding would have
/// to invert the map to an input that also passes its check bits. A uniformly random element
/// from [`GroupElement::random`](crate::group::group_elements::GroupElement::random) satisfies it, since
/// nobody knows its discrete logarithm.
#[must_use]
pub fn hash_to_group_generic<C: Ciphersuite>(x: &[u8]) -> <C::Group as Group>::Element {
    /// The bound on a hashed identifier: at most `2^16 - 1` bytes.
    const MAX_HASH_INPUT: usize = u16::MAX as usize;

    let dst = C::ID.dst(b"HashToGroup-");
    if x.len() > MAX_HASH_INPUT {
        C::hash_to_group(&C::Hash::digest(x), &dst)
    } else {
        C::hash_to_group(x, &dst)
    }
}

/// [`hash_to_group_generic`] for ristretto255 with SHA-512.
#[must_use]
pub fn hash_to_group(x: &[u8]) -> GroupElement {
    hash_to_group_generic::<Ristretto255Sha512>(x)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ciphersuite::Ristretto255Sha512;
    use sha2::{Sha256, Sha512};

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

    #[test]
    fn hash_to_group_is_deterministic_and_input_specific() {
        assert_eq!(hash_to_group(b"alice"), hash_to_group(b"alice"));
        assert_ne!(hash_to_group(b"alice"), hash_to_group(b"bob"));
    }

    /// The tag carries the ciphersuite identifier, so a ciphersuite whose identifier differed would
    /// hash the same input to a different element. This pins the tag the identifier produces
    /// rather than comparing two ciphersuites.
    #[test]
    fn hash_to_group_is_separated_by_the_ciphersuite_identifier() {
        let suite = Ristretto255Sha512::ID;
        assert_eq!(
            hash_to_group(b"alice"),
            hash_to_group_with_dst(b"alice", &suite.dst(b"HashToGroup-"))
        );
        assert_ne!(
            hash_to_group(b"alice"),
            hash_to_group_with_dst(b"alice", b"HashToGroup-nPEPV1-another-suite")
        );
    }

    #[test]
    fn hash_to_group_uses_the_ciphersuite_dst() {
        assert_eq!(
            hash_to_group(b"alice"),
            hash_to_group_with_dst(b"alice", b"HashToGroup-nPEPV1-ristretto255-SHA512")
        );
    }

    #[test]
    fn hash_to_group_does_not_prehash_ordinary_inputs() {
        // The encoding is HashToGroup(x), not HashToGroup(H(x)). Reducing the input first would
        // add no collision resistance and would silently diverge from any implementation written
        // against the primitive, so pin that it does not happen.
        let dst = Ristretto255Sha512::ID.dst(b"HashToGroup-");
        for x in [b"".as_slice(), b"a", b"patient-42", &[0xffu8; 1000]] {
            assert_eq!(
                hash_to_group(x),
                hash_to_group_with_dst(x, &dst),
                "hash_to_group must pass the input through unchanged"
            );
            assert_ne!(
                hash_to_group(x),
                hash_to_group_with_dst(&Sha512::digest(x), &dst),
                "hash_to_group must not pre-hash an input within the bound"
            );
        }
    }

    #[test]
    fn hash_to_group_prehashes_long_inputs() {
        let dst = Ristretto255Sha512::ID.dst(b"HashToGroup-");
        let max_input = u16::MAX as usize;
        let long = vec![7u8; max_input + 1];
        assert_eq!(
            hash_to_group(&long),
            hash_to_group_with_dst(&Sha512::digest(&long), &dst)
        );
        let max = vec![7u8; max_input];
        assert_eq!(hash_to_group(&max), hash_to_group_with_dst(&max, &dst));
    }

    #[test]
    fn hashed_elements_are_not_lizard_encodings() {
        assert!(hash_to_group(b"alice").to_lizard().is_none());
    }
}
