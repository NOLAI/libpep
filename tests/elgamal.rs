use rand_core::OsRng;
use libpep::arithmetic::{G, GroupElement, ScalarNonZero};
use libpep::elgamal::{decrypt, ElGamal, encrypt};

#[test]
fn encryption_decryption() {
    let mut rng = OsRng;
    let y = ScalarNonZero::random(&mut rng);
    let gy = y * G;
    let m = GroupElement::random(&mut rng);
    let encrypted = encrypt(&m, &gy, &mut rng);
    let decrypted = decrypt(&encrypted, &y);
    assert_eq!(m, decrypted);
}

#[test]
fn encoding() {
    let mut rng = OsRng;
    let x = GroupElement::random(&mut rng);
    let y = GroupElement::random(&mut rng);
    let msg = encrypt(&x, &y, &mut rng);
    let encoded = msg.encode_to_base64();
    let decoded = ElGamal::decode_from_base64(&encoded).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn decode_encode() {
    #[cfg(not(feature = "elgamal2"))]
    let original = "NESP1FCKkF7nWbqM9cvuUEUPgHaF8qnLeW9RLe_5FCMs-daoTGSyJKa5HRKxk0jFMHVuZ77pJMacNLmtRnlkZEpkKEPWnLzh_s8ievM3gTqeBYm20E23K6hExSxMOw8D";
    #[cfg(feature = "elgamal2")]
    let original = "xGOnBZzbSrvKUQYBtww0vi8jZWzN9qkrm5OnI2pnEFJu4DkZP2jLLGT-yWa_qnkC_ScCwQwcQtZk_z_z7s_gVQ==";

    let decoded = ElGamal::decode_from_base64(original).unwrap();
    let encoded = decoded.encode_to_base64();
    assert_eq!(original, encoded);
}