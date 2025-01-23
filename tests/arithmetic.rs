use libpep::internal::arithmetic::{GroupElement, ScalarCanBeZero, ScalarNonZero, ScalarTraits};
use rand::Rng;
use rand_core::OsRng;

#[test]
fn encode_decode_scalar_non_zero() {
    let mut rng = OsRng;
    let s = ScalarNonZero::random(&mut rng);
    let encoded = s.encode();
    let decoded = ScalarNonZero::decode(&encoded);
    assert!(decoded.is_some());
    assert_eq!(decoded.unwrap(), s);
}

#[test]
fn encode_decode_scalar_can_be_zero() {
    let mut rng = OsRng;
    let s = ScalarCanBeZero::random(&mut rng);
    let encoded = s.encode();
    let decoded = ScalarCanBeZero::decode(&encoded);
    assert!(decoded.is_some());
    assert_eq!(decoded.unwrap(), s);
}

#[test]
fn encode_decode_group_element() {
    let mut rng = OsRng;
    let x = GroupElement::random(&mut rng);
    let encoded = x.encode();
    let decoded = GroupElement::decode(&encoded);
    assert!(decoded.is_some());
    assert_eq!(decoded.unwrap(), x);
}

#[test]
fn serialize_deserialize_group_element() {
    let mut rng = OsRng;
    let x = GroupElement::random(&mut rng);
    let serialized = serde_json::to_string(&x);
    assert!(serialized.is_ok());
    let deserialized = serde_json::from_str(&serialized.unwrap());
    assert!(deserialized.is_ok());
    assert_eq!(
        x,
        deserialized.unwrap(),
        "Deserialized element does not match the original"
    );
}

#[test]
fn encode_decode_group_element_32_bytes() {
    let bytes = b"test data dsfdsdfsd wefwefew dfd";
    let element = GroupElement::decode(bytes);
    assert!(element.is_some());
    let decoded = element.unwrap().encode();
    assert_eq!(decoded, *bytes);
}

#[test]
fn add_group_elements() {
    let mut rng = OsRng;
    let x = GroupElement::random(&mut rng);
    let y = GroupElement::random(&mut rng);
    let _z = x + y;
}

#[test]
fn add_scalars() {
    let mut rng = OsRng;
    let x = ScalarCanBeZero::random(&mut rng);
    let y = ScalarCanBeZero::random(&mut rng);
    let _z = x + y;
}

#[test]
fn mul_scalar_group_element() {
    let mut rng = OsRng;
    let x = GroupElement::random(&mut rng);
    let s = ScalarNonZero::random(&mut rng);
    let _z = s * x;
}
#[test]
fn test_lizard() {
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
    for encoding in edge_cases.iter() {
        let case = hex::decode(encoding).unwrap();
        let bytes = <&[u8; 16]>::try_from(case.as_slice()).unwrap();
        let element = GroupElement::decode_lizard(bytes);
        let encoded = element.encode_lizard().unwrap();
        assert_eq!(encoded, *bytes);
    }
}

#[test]
fn test_lizard2() {
    let mut rng = OsRng;

    let random_bytes: [u8; 16] = rng.gen();
    let element = GroupElement::decode_lizard(&random_bytes);
    let encoded = element.encode_lizard().unwrap();
    assert_eq!(encoded, random_bytes);

    let s = ScalarNonZero::random(&mut rng);

    let element2 = s * element;
    let encoded2 = element2.encode_lizard();
    assert!(encoded2.is_none()); // This should fail because it is not a valid lizard encoding anymore
}
