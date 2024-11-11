use crate::internal::arithmetic::GroupElement;
use crate::low_level::elgamal::ElGamal;
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct Pseudonym {
    pub(crate) value: GroupElement,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct DataPoint {
    pub(crate) value: GroupElement,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct EncryptedPseudonym {
    pub value: ElGamal,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct EncryptedDataPoint {
    pub value: ElGamal,
}
impl Pseudonym {
    pub fn from_point(value: GroupElement) -> Self {
        Self { value }
    }
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from_point(GroupElement::random(rng))
    }
    pub fn encode(&self) -> [u8; 32] {
        self.value.encode()
    }
    pub fn encode_to_hex(&self) -> String {
        self.value.encode_to_hex()
    }
    pub fn decode(bytes: &[u8; 32]) -> Option<Self> {
        GroupElement::decode(bytes).map(|x| Self::from_point(x))
    }
    pub fn decode_from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::decode_from_slice(slice).map(|x| Self::from_point(x))
    }
    pub fn decode_from_hex(hex: &str) -> Option<Self> {
        GroupElement::decode_from_hex(hex).map(|x| Self::from_point(x))
    }
    pub fn from_hash(hash: &[u8; 64]) -> Self {
        Self::from_point(GroupElement::decode_from_hash(hash))
    }
    pub fn from_bytes(data: &[u8; 16]) -> Self {
        Self::from_point(GroupElement::decode_lizard(data))
    }
    pub fn to_bytes(&self) -> Option<[u8; 16]> {
        self.value.encode_lizard()
    }
}
impl DataPoint {
    pub fn from_point(value: GroupElement) -> Self {
        Self { value }
    }
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from_point(GroupElement::random(rng))
    }
    pub fn encode(&self) -> [u8; 32] {
        self.value.encode()
    }
    pub fn encode_to_hex(&self) -> String {
        self.value.encode_to_hex()
    }
    pub fn decode(bytes: &[u8; 32]) -> Option<Self> {
        GroupElement::decode(bytes).map(|x| Self::from_point(x))
    }
    pub fn decode_from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::decode_from_slice(slice).map(|x| Self::from_point(x))
    }
    pub fn decode_from_hex(hex: &str) -> Option<Self> {
        GroupElement::decode_from_hex(hex).map(|x| Self::from_point(x))
    }
    pub fn from_hash(hash: &[u8; 64]) -> Self {
        Self::from_point(GroupElement::decode_from_hash(hash))
    }
    pub fn from_bytes(data: &[u8; 16]) -> Self {
        Self::from_point(GroupElement::decode_lizard(data))
    }
    pub fn to_bytes(&self) -> Option<[u8; 16]> {
        self.value.encode_lizard()
    }
    pub fn bytes_into_multiple_messages(data: &[u8]) -> Vec<Self> {
        data.chunks(16)
            .map(|x| Self::from_bytes(x.try_into().unwrap()))
            .collect()
    }
}
pub trait Encrypted {
    type UnencryptedType: Encryptable;
    const IS_PSEUDONYM: bool;
    fn value(&self) -> &ElGamal;
    fn from_value(value: ElGamal) -> Self;
}
pub trait Encryptable {
    type EncryptedType: Encrypted;
    fn value(&self) -> &GroupElement;
    fn from_value(value: GroupElement) -> Self;
}
impl Encryptable for Pseudonym {
    type EncryptedType = EncryptedPseudonym;
    fn value(&self) -> &GroupElement {
        &self.value
    }
    fn from_value(value: GroupElement) -> Self {
        Self::from_point(value)
    }
}
impl Encryptable for DataPoint {
    type EncryptedType = EncryptedDataPoint;
    fn value(&self) -> &GroupElement {
        &self.value
    }
    fn from_value(value: GroupElement) -> Self {
        Self::from_point(value)
    }
}
impl Encrypted for EncryptedPseudonym {
    type UnencryptedType = Pseudonym;
    const IS_PSEUDONYM: bool = true;
    fn value(&self) -> &ElGamal {
        &self.value
    }
    fn from_value(value: ElGamal) -> Self {
        Self { value }
    }
}
impl Encrypted for EncryptedDataPoint {
    type UnencryptedType = DataPoint;
    const IS_PSEUDONYM: bool = false;
    fn value(&self) -> &ElGamal {
        &self.value
    }
    fn from_value(value: ElGamal) -> Self {
        Self { value }
    }
}
