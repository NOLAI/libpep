//! The `ristretto255-SHA512` ciphersuite: the [`Group`] instance over
//! [`GroupElement`] and [`ScalarNonZero`], with the lizard encoding as its
//! [`InvertibleEncoding`].

use super::group::{Group, InvertibleEncoding};
use super::group_elements::{GroupElement, G};
use super::scalars::{ScalarCanBeZero, ScalarNonZero, ScalarTraits};
use rand_core::{CryptoRng, Rng};
use sha2::{Digest, Sha512};

/// The ristretto255 group with SHA-512, ciphersuite `ristretto255-SHA512` of RFC 9497.
///
/// Elements are 32 bytes, scalars 32 bytes. Hashing to the group is `hash_to_ristretto255`
/// (RFC 9380, Appendix B) and hashing to a scalar reduces 64 bytes of `expand_message_xmd`
/// output modulo the group order, both with SHA-512.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Ristretto255;

/// The order of ristretto255 (and of the prime-order subgroup of Curve25519),
/// `2^252 + 27742317777372353535851937790883648493`, big-endian.
const ORDER: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
];

impl Group for Ristretto255 {
    type Scalar = ScalarNonZero;
    type Element = GroupElement;
    type ElementBytes = [u8; 32];
    type ScalarBytes = [u8; 32];

    const NE: usize = 32;
    const NS: usize = 32;

    fn order() -> &'static [u8] {
        &ORDER
    }

    fn identity() -> GroupElement {
        GroupElement::identity()
    }

    fn generator() -> GroupElement {
        G
    }

    fn hash_to_group(msg: &[u8], dst: &[u8]) -> GroupElement {
        let uniform = expand_message_xmd::<64>(msg, dst);
        GroupElement::from_hash(&uniform)
    }

    fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Option<ScalarNonZero> {
        let uniform = expand_message_xmd::<64>(msg, dst);
        Self::scalar_from_uniform_bytes(&uniform)
    }

    fn element_from_uniform_bytes(bytes: &[u8; 64]) -> GroupElement {
        GroupElement::from_hash(bytes)
    }

    fn scalar_from_uniform_bytes(bytes: &[u8; 64]) -> Option<ScalarNonZero> {
        ScalarCanBeZero::from_hash(bytes).try_into().ok()
    }

    fn random_scalar<R: Rng + CryptoRng>(rng: &mut R) -> ScalarNonZero {
        ScalarNonZero::random(rng)
    }

    fn random_element<R: Rng + CryptoRng>(rng: &mut R) -> GroupElement {
        GroupElement::random(rng)
    }

    fn scalar_one() -> ScalarNonZero {
        ScalarNonZero::one()
    }

    fn scalar_inverse(scalar: &ScalarNonZero) -> ScalarNonZero {
        scalar.invert()
    }

    fn serialize_element(element: &GroupElement) -> [u8; 32] {
        element.to_bytes()
    }

    fn deserialize_element(bytes: &[u8]) -> Option<GroupElement> {
        GroupElement::from_slice(bytes)
    }

    fn serialize_scalar(scalar: &ScalarNonZero) -> [u8; 32] {
        scalar.to_bytes()
    }

    fn deserialize_scalar(bytes: &[u8]) -> Option<ScalarNonZero> {
        ScalarNonZero::from_slice(bytes)
    }

    fn scalar_mult_gen(scalar: &ScalarNonZero) -> GroupElement {
        scalar * G
    }
}

impl InvertibleEncoding for Ristretto255 {
    type Block = [u8; 16];

    const BLOCK_LENGTH: usize = 16;

    fn encode_lizard(block: &[u8; 16]) -> GroupElement {
        GroupElement::from_lizard(block)
    }

    fn decode_lizard(element: &GroupElement) -> Option<[u8; 16]> {
        element.to_lizard()
    }
}

/// `expand_message_xmd` of RFC 9380, Section 5.3.1, with SHA-512, producing `LEN` bytes.
///
/// Panics if `dst` is longer than 255 bytes, as the RFC requires callers to guarantee.
fn expand_message_xmd<const LEN: usize>(msg: &[u8], dst: &[u8]) -> [u8; LEN] {
    const B_IN_BYTES: usize = 64;
    const S_IN_BYTES: usize = 128;
    assert!(
        dst.len() <= 255,
        "domain separation tag longer than 255 bytes"
    );
    assert!(
        LEN <= 255 * B_IN_BYTES,
        "expand_message_xmd output too long"
    );
    let ell = LEN.div_ceil(B_IN_BYTES);
    // Unwrap is safe: LEN <= 255 * 64 < 2^16, dst.len() <= 255, ell <= 255.
    #[allow(clippy::unwrap_used)]
    let (dst_len, len_hi, len_lo, _) = (
        u8::try_from(dst.len()).unwrap(),
        u8::try_from(LEN >> 8).unwrap(),
        u8::try_from(LEN & 0xff).unwrap(),
        u8::try_from(ell).unwrap(),
    );

    let mut hasher = Sha512::new();
    hasher.update([0u8; S_IN_BYTES]);
    hasher.update(msg);
    hasher.update([len_hi, len_lo, 0]);
    hasher.update(dst);
    hasher.update([dst_len]);
    let b_0: [u8; B_IN_BYTES] = hasher.finalize().into();

    let mut out = [0u8; LEN];
    let mut b_prev = [0u8; B_IN_BYTES];
    for i in 1..=ell {
        let mut hasher = Sha512::new();
        if i == 1 {
            hasher.update(b_0);
        } else {
            let mut xored = b_0;
            for (x, p) in xored.iter_mut().zip(b_prev.iter()) {
                *x ^= p;
            }
            hasher.update(xored);
        }
        // Unwrap is safe: i <= ell <= 255.
        #[allow(clippy::unwrap_used)]
        hasher.update([u8::try_from(i).unwrap()]);
        hasher.update(dst);
        hasher.update([dst_len]);
        b_prev = hasher.finalize().into();
        let start = (i - 1) * B_IN_BYTES;
        let end = LEN.min(start + B_IN_BYTES);
        out[start..end].copy_from_slice(&b_prev[..end - start]);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// RFC 9380, Appendix K.3: expand_message_xmd(SHA-512).
    #[test]
    fn expand_message_xmd_sha512_vectors() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA512-256";
        assert_eq!(
            hex::encode(expand_message_xmd::<32>(b"", dst)),
            "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba"
        );
        assert_eq!(
            hex::encode(expand_message_xmd::<32>(b"abc", dst)),
            "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc"
        );
        assert_eq!(
            hex::encode(expand_message_xmd::<128>(b"", dst)),
            "41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7eb00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961"
        );
    }

    /// The context string of the RFC 9497 `ristretto255-SHA512` OPRF test vectors.
    const RFC9497_CONTEXT: &[u8] = b"OPRFV1-\x00-ristretto255-SHA512";

    /// RFC 9497, Appendix A.1.1: `DeriveKeyPair` is one `HashToScalar` call.
    #[test]
    fn hash_to_scalar_matches_rfc9497() {
        let seed = [0xa3u8; 32];
        let info = b"test key";
        let mut input = seed.to_vec();
        input.extend_from_slice(&(info.len() as u16).to_be_bytes());
        input.extend_from_slice(info);
        input.push(0); // counter
        let dst = [b"DeriveKeyPair".as_slice(), RFC9497_CONTEXT].concat();
        let sk = Ristretto255::hash_to_scalar(&input, &dst).unwrap();
        assert_eq!(
            sk.to_hex(),
            "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e"
        );
    }

    /// RFC 9497, Appendix A.1.1.1: `BlindedElement = blind * HashToGroup(input)`.
    #[test]
    fn hash_to_group_matches_rfc9497() {
        let dst = [b"HashToGroup-".as_slice(), RFC9497_CONTEXT].concat();
        let blind = ScalarNonZero::from_hex(
            "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
        )
        .unwrap();
        let blinded = blind * Ristretto255::hash_to_group(&[0x00], &dst);
        assert_eq!(
            blinded.to_hex(),
            "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c"
        );
        let blinded = blind * Ristretto255::hash_to_group(&[0x5a; 17], &dst);
        assert_eq!(
            blinded.to_hex(),
            "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418"
        );
    }

    #[test]
    fn serialization_roundtrip_and_identity_rejection() {
        let mut rng = rand::rng();
        let e = Ristretto255::random_element(&mut rng);
        assert_eq!(
            Ristretto255::deserialize_element(&Ristretto255::serialize_element(&e)),
            Some(e)
        );
        assert_eq!(
            Ristretto255::deserialize_element(&Ristretto255::serialize_element(
                &Ristretto255::identity()
            )),
            None
        );
        let s = Ristretto255::random_scalar(&mut rng);
        assert_eq!(
            Ristretto255::deserialize_scalar(&Ristretto255::serialize_scalar(&s)),
            Some(s)
        );
        assert_eq!(Ristretto255::deserialize_scalar(&[0u8; 32]), None);
        assert_eq!(Ristretto255::scalar_mult_gen(&s), s * G);
        assert_eq!(
            s * Ristretto255::scalar_inverse(&s),
            Ristretto255::scalar_one()
        );
    }

    #[test]
    fn lizard_encoding_roundtrip() {
        let block = *b"sixteen bytes!!!";
        let e = Ristretto255::encode_lizard(&block);
        assert_eq!(Ristretto255::decode_lizard(&e), Some(block));
    }

    #[test]
    fn order_is_the_basepoint_order() {
        // The order reduces to zero modulo itself, and the order minus one does not.
        use curve25519_dalek::scalar::Scalar;
        let mut le = ORDER;
        le.reverse();
        assert_eq!(Scalar::from_bytes_mod_order(le), Scalar::ZERO);
        le[0] -= 1;
        assert_ne!(Scalar::from_bytes_mod_order(le), Scalar::ZERO);
        assert_eq!(Ristretto255::order().len(), Ristretto255::NS);
    }
}
