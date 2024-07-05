use hex::decode;
use libpep::arithmetic::GroupElement;
use libpep::elgamal::{encrypt, ElGamal};
use rand_core::OsRng;
use libpep::lib_wasm::{decode_hex, encode_hex};

#[test]
fn encode_decode_elgamal() {
    let mut rng = OsRng;
    let x = GroupElement::random(&mut rng);
    let y = GroupElement::random(&mut rng);
    let msg = encrypt(&x, &y, &mut rng);

    let encoded = msg.to_string();
    print!("encoded: {}\n", encoded);
    let decoded = ElGamal::from_string(&encoded).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn encode_decode_group_element() {
    let mut rng = OsRng;
    let x = GroupElement::random(&mut rng);
    let encoded = x.to_hex();
    print!("encoded: {}\n", encoded);
    let decoded = GroupElement::from_hex(&encoded).unwrap();
    assert_eq!(x, decoded);
}


#[test]
fn test_encode_decode() {
    let pseudonym = "0c2332ca68d945ada4585cef87444c42b8cbd561de2449a2d3c335351c765444";
    let encoded = encode_hex(pseudonym);
    let decoded = decode_hex(&encoded);
    assert_eq!(pseudonym, decoded);
}
