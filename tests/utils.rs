use rand_core::OsRng;
use libpep::arithmetic::{GroupElement};
use libpep::elgamal::{ElGamal, encrypt};

#[test]
fn encode_decode_string() {
    let mut rng = OsRng;
    let x = GroupElement::random(&mut rng);
    let y = GroupElement::random(&mut rng);
    let msg = encrypt(&x, &y, &mut rng);

    let encoded = msg.encode_to_string();
    let decoded = ElGamal::decode_from_string(&encoded).unwrap();
    assert_eq!(msg, decoded);
}
