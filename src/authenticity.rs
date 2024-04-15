use sha2::{Sha512, Digest};
use crate::arithmetic::*;
use crate::elgamal::ElGamal;

pub type AuthenticityTag = [u8; 64];

pub fn authenticity_tag(v_data: &ElGamal, v_pseudonym: &ElGamal, metadata: &GroupElement, system_id: &String, shared_secret: &ScalarNonZero) -> AuthenticityTag {
    let mut hasher = Sha512::default();
    hasher.update(&v_data.encode());
    hasher.update(&v_pseudonym.encode());
    hasher.update(&metadata.encode());
    hasher.update(system_id.as_bytes());
    hasher.update(shared_secret.encode());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    bytes
}

pub fn verify_authenticity_tag(tag: &AuthenticityTag, v_data: &ElGamal, v_pseudonym: &ElGamal, metadata: &GroupElement, system_id: &String, shared_secret: &ScalarNonZero) -> bool {
    let expected_tag = authenticity_tag(v_data, v_pseudonym, metadata, system_id, shared_secret);
    tag == &expected_tag
}
