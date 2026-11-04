//! The `Group` instance of ristretto255.

use super::elements::{GroupElement, G};
use super::scalars::{ScalarCanBeZero, ScalarNonZero, ScalarTraits};
use crate::group::{Group, InvertibleEncoding};
use rand_core::{CryptoRng, Rng};

/// The ristretto255 group.
///
/// Elements are 32 bytes, scalars 32 bytes. The hashing that protocols build on it is in the
/// ciphersuite [`Ristretto255Sha512`](crate::ciphersuite::Ristretto255Sha512).
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
    type ScalarCanBeZero = ScalarCanBeZero;
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

    fn serialize_scalar_can_be_zero(scalar: &ScalarCanBeZero) -> [u8; 32] {
        scalar.to_bytes()
    }

    fn deserialize_scalar_can_be_zero(bytes: &[u8]) -> Option<ScalarCanBeZero> {
        ScalarCanBeZero::from_slice(bytes)
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
