//! Encodings of identifiers and payloads as group elements, the "Element Encodings" of
//! draft-doesburg-cfrg-coprf.
//!
//! Inputs enter the protocol as group elements. Which encoding a deployment uses for identifiers
//! and for payload data is agreed out of band; it is not part of the ciphersuite.
//!
//! # Required property
//!
//! Reshuffling is linear: the pseudonym of `M` in domain `d` is `s_d * M`, so for any `M_1` and
//! `M_2 = a * M_1` the pseudonyms of the two satisfy the same relation in every domain.
//! Cross-domain unlinkability holds under DDH only for elements whose mutual discrete-log
//! relations are unknown to every party. An encoding of inputs into group elements MUST therefore
//! be such that no party can produce two encoded inputs with a known discrete-log relation other
//! than by solving a discrete logarithm. **Encoding an identifier `x` as `x * G` (or as any
//! scalar multiple of a fixed element) violates this and is forbidden.**
//!
//! The encodings here satisfy the property: [`hash_to_group`] by the random oracle property of
//! hashing to the group, the invertible encodings because finding an input whose encoding is a
//! given multiple of another encoding requires computing a discrete logarithm. Uniformly random
//! elements ([`GroupElement::random`]) satisfy it trivially and can be used as origin pseudonyms
//! where no identifier needs to be encoded.
//!
//! # Choosing an encoding
//!
//! - [`hash_to_group`] is not invertible: the origin party recognizes a pseudonym as belonging
//!   to `x` only by recomputing it. Available on every ciphersuite.
//! - [`encode_lizard`] maps 16 bytes to an element and back. Origin pseudonyms encoded this way
//!   can be decoded when transcrypted back to the origin domain. Attributes must use an
//!   invertible encoding, since the receiver decodes them. ristretto255 only.
//! - [`encode_oaep`] embeds an input in the x-coordinate of a Weierstrass curve point, as the
//!   Dutch BSNk scheme does on brainpoolP320r1. Not available on ristretto255.
//!
//! A reshuffled element is never decodable, which is why reshuffling is never applied to
//! attributes.

use crate::elgamal::arithmetic::group_elements::GroupElement;
use crate::elgamal::arithmetic::hashing;
use crate::protocol::Context;
use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::{Digest, Sha256, Sha512};

/// Inputs longer than this are hashed with SHA-512 before hashing to the group.
const MAX_HASH_INPUT: usize = u16::MAX as usize;

/// `EncodeHash(x) = HashToGroup(x)` with domain separation tag
/// `"HashToGroup-" || contextString` (see [`hashing::hash_to_group`]).
///
/// An input longer than 2^16 - 1 bytes is hashed with SHA-512 first, as the draft prescribes.
#[must_use]
pub fn hash_to_group(x: &[u8], context: &Context) -> GroupElement {
    let dst = context.dst(b"HashToGroup-");
    if x.len() > MAX_HASH_INPUT {
        hashing::hash_to_group(&Sha512::digest(x), &dst)
    } else {
        hashing::hash_to_group(x, &dst)
    }
}

/// The lizard encoding of a 16-byte string as a ristretto255 element.
///
/// `SHA-256(data)` with bytes 8 to 23 replaced by `data` is masked to a field element and mapped
/// with the ristretto255 Elligator map. Every 16-byte string encodes; the hash bytes let
/// [`decode_lizard`] recognize an encoded element among the up to eight Elligator preimages.
#[must_use]
pub fn encode_lizard(data: &[u8; 16]) -> GroupElement {
    GroupElement(RistrettoPoint::lizard_encode::<Sha256>(data))
}

/// Invert [`encode_lizard`].
///
/// Returns `None` if the element is not a lizard encoding, which is the case with overwhelming
/// probability for an element that was not produced by [`encode_lizard`], such as a reshuffled
/// one. The `Sha256` type parameter of the underlying map is the same as in [`encode_lizard`].
#[must_use]
pub fn decode_lizard(element: &GroupElement) -> Option<[u8; 16]> {
    element.0.lizard_decode::<Sha256>()
}

/// The OAEP-style x-coordinate embedding of Weierstrass curves.
///
/// Not available on ristretto255: this encoding needs a Weierstrass curve and is specified by the
/// draft's editor's note to follow the BSNk PP technical specification (padding format, search
/// for the y-coordinate, and handling of the point's sign) once a brainpoolP320r1 ciphersuite
/// exists. It is a stub until the group abstraction adds such curves.
///
/// # Panics
///
/// Always.
pub fn encode_oaep(data: &[u8]) -> GroupElement {
    let _ = data;
    unimplemented!("the oaep encoding needs a Weierstrass curve ciphersuite")
}

/// Invert [`encode_oaep`]. See there: a stub until a Weierstrass curve ciphersuite exists.
///
/// # Panics
///
/// Always.
pub fn decode_oaep(element: &GroupElement) -> Option<Vec<u8>> {
    let _ = element;
    unimplemented!("the oaep encoding needs a Weierstrass curve ciphersuite")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::protocol::Mode;
    use rand_core::Rng;

    #[test]
    fn hash_to_group_is_deterministic_and_context_specific() {
        let ctx = Context::default();
        assert_eq!(hash_to_group(b"alice", &ctx), hash_to_group(b"alice", &ctx));
        assert_ne!(hash_to_group(b"alice", &ctx), hash_to_group(b"bob", &ctx));
        assert_ne!(
            hash_to_group(b"alice", &ctx),
            hash_to_group(b"alice", &Context::from_identifier("other"))
        );
        assert_ne!(
            hash_to_group(b"alice", &ctx),
            hash_to_group(b"alice", &Context::new(Mode::VcoPRF, "ristretto255-SHA512"))
        );
    }

    #[test]
    fn hash_to_group_uses_the_context_dst() {
        let ctx = Context::default();
        assert_eq!(
            hash_to_group(b"alice", &ctx),
            hashing::hash_to_group(b"alice", b"HashToGroup-coPRFV1-\x00-ristretto255-SHA512")
        );
    }

    #[test]
    fn long_inputs_are_prehashed() {
        let ctx = Context::default();
        let long = vec![7u8; MAX_HASH_INPUT + 1];
        assert_eq!(
            hash_to_group(&long, &ctx),
            hashing::hash_to_group(&Sha512::digest(&long), &ctx.dst(b"HashToGroup-"))
        );
        let max = vec![7u8; MAX_HASH_INPUT];
        assert_eq!(
            hash_to_group(&max, &ctx),
            hashing::hash_to_group(&max, &ctx.dst(b"HashToGroup-"))
        );
    }

    #[test]
    fn lizard_edge_cases() {
        let edge_cases = [
            "00000000000000000000000000000000",
            "00ffffffffffffffffffffffffffffff",
            "f3ffffffffffffffffffffffffffff7f",
            "ffffffffffffffffffffffffffffffff",
            "01ffffffffffffffffffffffffffffff",
            "edffffffffffffffffffffffffffff7f",
            "01000000000000000000000000000000",
            "ecffffffffffffffffffffffffffff7f",
        ];
        for encoding in edge_cases {
            let case = hex::decode(encoding).expect("hex decoding should succeed");
            let bytes = <&[u8; 16]>::try_from(case.as_slice()).expect("should be 16 bytes");
            let element = encode_lizard(bytes);
            let decoded = decode_lizard(&element).expect("lizard decoding should succeed");
            assert_eq!(decoded, *bytes);
        }
    }

    #[test]
    fn lizard_random_roundtrip() {
        let mut rng = rand::rng();
        let mut random_bytes = [0u8; 16];
        rng.fill_bytes(&mut random_bytes);
        let element = encode_lizard(&random_bytes);
        assert_eq!(decode_lizard(&element), Some(random_bytes));
    }

    #[test]
    fn lizard_fails_after_scalar_multiplication() {
        let mut rng = rand::rng();
        let mut random_bytes = [0u8; 16];
        rng.fill_bytes(&mut random_bytes);
        let element = encode_lizard(&random_bytes);
        let s = ScalarNonZero::random(&mut rng);
        // After scalar multiplication, the element is no longer in lizard form (extremely likely)
        assert!(decode_lizard(&(s * element)).is_none());
    }

    #[test]
    fn hashed_elements_are_not_lizard_encodings() {
        assert!(decode_lizard(&hash_to_group(b"alice", &Context::default())).is_none());
    }

    #[test]
    #[should_panic(expected = "Weierstrass")]
    fn oaep_is_not_available() {
        let _ = encode_oaep(b"x");
    }
}
