//! Byte-level wire formats of
//! [draft-doesburg-cfrg-coprf](https://datatracker.ietf.org/doc/draft-doesburg-cfrg-coprf/)
//! (plain, non-verifiable mode, ristretto255), so that batches of ciphertexts and session
//! material can be exchanged between implementations without a serialization framework.
//!
//! The layouts follow the draft's TLS-presentation-style structs exactly:
//!
//! ```text
//! struct {
//!   uint8      type;                   // 0x01 pseudonym, 0x02 attribute
//!   opaque     d_from<0..2^16-1>;      // pseudonymization domain the data comes from
//!   opaque     d_to<0..2^16-1>;        // pseudonymization domain the data goes to
//!   opaque     c_from<0..2^16-1>;      // encryption context the data comes from
//!   opaque     c_to<0..2^16-1>;        // encryption context the data goes to
//!   Element    Y_from;                 // the public key the items are encrypted under
//!   Ciphertext items<1..2^32-1>;       // 64 bytes each: B || C
//! } BatchRequest;
//!
//! struct {
//!   Element    Y_to;                   // the public key the items are now encrypted under
//!   Ciphertext items<1..2^32-1>;
//! } BatchResponse;
//! ```
//!
//! Variable-length fields carry a big-endian length prefix (2 bytes for identifiers, 4 bytes for
//! the item count); elements are 32-byte ristretto255 encodings; a ciphertext is
//! [`ElGamal::to_bytes`] without the `elgamal3` key field. Decoding is strict: unknown types,
//! truncated input, trailing bytes, empty batches and invalid elements (including the identity)
//! are rejected.
//!
//! A session key share is encoded as `SerializeScalar(u_i)`; [`SessionKeyShares`] concatenates
//! the pseudonym and attribute shares.
//!
//! Serde support on the library's types is an independent layer for application-level formats;
//! this module is the interoperable one.

use crate::elgamal::arithmetic::group_elements::GroupElement;
use crate::elgamal::arithmetic::scalars::ScalarNonZero;
use crate::elgamal::ElGamal;
use crate::keys::distribution::{
    AttributeSessionKeyShare, PseudonymSessionKeyShare, SessionKeyShare, SessionKeyShares,
};
use thiserror::Error;

/// Length of an element encoding (`Ne` in the draft).
pub const ELEMENT_LENGTH: usize = 32;
/// Length of a scalar encoding (`Ns` in the draft).
pub const SCALAR_LENGTH: usize = 32;
/// Length of a ciphertext on the wire: `B || C`.
pub const CIPHERTEXT_LENGTH: usize = 2 * ELEMENT_LENGTH;
/// Longest identifier that fits the 2-byte length prefix.
pub const MAX_IDENTIFIER_LENGTH: usize = u16::MAX as usize;
/// Most items that fit the 4-byte item count.
pub const MAX_ITEMS: usize = u32::MAX as usize;

/// A wire encoding or decoding failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// The batch type byte is neither pseudonym (0x01) nor attribute (0x02).
    #[error("unknown batch type {0:#04x}")]
    UnknownType(u8),
    /// The input ends before the structure does.
    #[error(
        "truncated input: expected {expected} bytes at offset {offset}, {available} available"
    )]
    Truncated {
        offset: usize,
        expected: usize,
        available: usize,
    },
    /// Bytes remain after the structure.
    #[error("{0} trailing bytes after the structure")]
    TrailingBytes(usize),
    /// A batch must carry at least one item.
    #[error("a batch must carry at least one item")]
    EmptyBatch,
    /// An identifier is longer than the 2-byte length prefix allows.
    #[error("identifier of {0} bytes exceeds the maximum of {MAX_IDENTIFIER_LENGTH}")]
    IdentifierTooLong(usize),
    /// More items than the 4-byte count allows.
    #[error("{0} items exceed the maximum of {MAX_ITEMS}")]
    TooManyItems(usize),
    /// A 32-byte field is not a valid group element (or is the identity).
    #[error("invalid group element at offset {offset}")]
    InvalidElement { offset: usize },
    /// A 32-byte field is not a valid non-zero scalar.
    #[error("invalid scalar at offset {offset}")]
    InvalidScalar { offset: usize },
    /// An identifier is not valid UTF-8 and cannot name a libpep domain or context.
    #[error("identifier is not valid UTF-8")]
    IdentifierNotUtf8,
    /// With `elgamal3`, an item claims a different public key than the batch.
    #[cfg(feature = "elgamal3")]
    #[error("item {index} is encrypted under a different key than the batch")]
    KeyMismatch { index: usize },
}

/// The kind of data in a batch: the `type` field of a request.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(u8)]
pub enum BatchKind {
    /// Encrypted pseudonyms, which are reshuffled and rekeyed.
    Pseudonym = 0x01,
    /// Encrypted attributes, which are only rekeyed.
    Attribute = 0x02,
}

impl BatchKind {
    /// The type byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Decode the type byte.
    pub fn from_byte(byte: u8) -> Result<Self, WireError> {
        match byte {
            0x01 => Ok(Self::Pseudonym),
            0x02 => Ok(Self::Attribute),
            other => Err(WireError::UnknownType(other)),
        }
    }
}

/// A request to transcrypt a batch of ciphertexts of one kind from one domain and context to
/// another. The identifiers are opaque byte strings whose meaning is application specific; libpep
/// uses them as the payloads of [`PseudonymizationDomain`](crate::contexts::PseudonymizationDomain)
/// and [`EncryptionContext`](crate::contexts::EncryptionContext).
///
/// A request is valid by construction: [`new`](Self::new) and [`from_bytes`](Self::from_bytes)
/// reject what cannot be encoded, so [`to_bytes`](Self::to_bytes) cannot fail.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BatchRequest {
    kind: BatchKind,
    d_from: Vec<u8>,
    d_to: Vec<u8>,
    c_from: Vec<u8>,
    c_to: Vec<u8>,
    y_from: GroupElement,
    items: Vec<ElGamal>,
}

/// The transcrypted items of a [`BatchRequest`] and the public key they are now encrypted under.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BatchResponse {
    y_to: GroupElement,
    items: Vec<ElGamal>,
}

/// Sequential reader over a byte slice with the draft's field decoders.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let available = self.bytes.len() - self.offset;
        if available < n {
            return Err(WireError::Truncated {
                offset: self.offset,
                expected: n,
                available,
            });
        }
        let out = &self.bytes[self.offset..self.offset + n];
        self.offset += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// `opaque x<0..2^16-1>`
    fn identifier(&mut self) -> Result<Vec<u8>, WireError> {
        let len = self.u16()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    /// `Element`, rejecting invalid encodings and the identity.
    fn element(&mut self) -> Result<GroupElement, WireError> {
        let offset = self.offset;
        GroupElement::from_slice(self.take(ELEMENT_LENGTH)?)
            .ok_or(WireError::InvalidElement { offset })
    }

    /// `Ciphertext items<1..2^32-1>`, with the given key as the `elgamal3` key field.
    fn items(&mut self, key: &GroupElement) -> Result<Vec<ElGamal>, WireError> {
        let count = self.u32()? as usize;
        if count == 0 {
            return Err(WireError::EmptyBatch);
        }
        let mut items = Vec::with_capacity(count.min(self.bytes.len() / CIPHERTEXT_LENGTH));
        for _ in 0..count {
            let gb = self.element()?;
            let gc = self.element()?;
            items.push(ElGamal {
                gb,
                gc,
                #[cfg(feature = "elgamal3")]
                gy: *key,
            });
        }
        #[cfg(not(feature = "elgamal3"))]
        let _ = key;
        Ok(items)
    }

    fn finish(self) -> Result<(), WireError> {
        let rest = self.bytes.len() - self.offset;
        if rest == 0 {
            Ok(())
        } else {
            Err(WireError::TrailingBytes(rest))
        }
    }
}

fn write_identifier(out: &mut Vec<u8>, id: &[u8]) {
    // Validated on construction.
    out.extend_from_slice(&(id.len() as u16).to_be_bytes());
    out.extend_from_slice(id);
}

fn write_items(out: &mut Vec<u8>, items: &[ElGamal]) {
    // Validated on construction.
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for item in items {
        out.extend_from_slice(&item.gb.to_bytes());
        out.extend_from_slice(&item.gc.to_bytes());
    }
}

fn check_identifier(id: &[u8]) -> Result<(), WireError> {
    if u16::try_from(id.len()).is_err() {
        Err(WireError::IdentifierTooLong(id.len()))
    } else {
        Ok(())
    }
}

fn check_items(items: &[ElGamal], key: &GroupElement) -> Result<(), WireError> {
    if items.is_empty() {
        return Err(WireError::EmptyBatch);
    }
    if u32::try_from(items.len()).is_err() {
        return Err(WireError::TooManyItems(items.len()));
    }
    #[cfg(feature = "elgamal3")]
    if let Some(index) = items.iter().position(|item| item.gy != *key) {
        return Err(WireError::KeyMismatch { index });
    }
    #[cfg(not(feature = "elgamal3"))]
    let _ = key;
    Ok(())
}

fn identifier_str(id: &[u8]) -> Result<&str, WireError> {
    std::str::from_utf8(id).map_err(|_| WireError::IdentifierNotUtf8)
}

impl BatchRequest {
    /// Assemble a request, checking that every field fits its encoding and that the batch is not
    /// empty. With `elgamal3`, every item must be encrypted under `y_from`.
    pub fn new(
        kind: BatchKind,
        d_from: impl Into<Vec<u8>>,
        d_to: impl Into<Vec<u8>>,
        c_from: impl Into<Vec<u8>>,
        c_to: impl Into<Vec<u8>>,
        y_from: GroupElement,
        items: Vec<ElGamal>,
    ) -> Result<Self, WireError> {
        let (d_from, d_to, c_from, c_to) = (d_from.into(), d_to.into(), c_from.into(), c_to.into());
        for id in [&d_from, &d_to, &c_from, &c_to] {
            check_identifier(id)?;
        }
        check_items(&items, &y_from)?;
        Ok(Self {
            kind,
            d_from,
            d_to,
            c_from,
            c_to,
            y_from,
            items,
        })
    }

    /// The kind of data in the batch.
    pub fn kind(&self) -> BatchKind {
        self.kind
    }
    /// The pseudonymization domain the data comes from.
    pub fn d_from(&self) -> &[u8] {
        &self.d_from
    }
    /// The pseudonymization domain the data goes to.
    pub fn d_to(&self) -> &[u8] {
        &self.d_to
    }
    /// The encryption context the data comes from.
    pub fn c_from(&self) -> &[u8] {
        &self.c_from
    }
    /// The encryption context the data goes to.
    pub fn c_to(&self) -> &[u8] {
        &self.c_to
    }
    /// The public key the items are encrypted under.
    pub fn y_from(&self) -> &GroupElement {
        &self.y_from
    }
    /// The ciphertexts.
    pub fn items(&self) -> &[ElGamal] {
        &self.items
    }

    /// The identifiers as strings, in the order `d_from, d_to, c_from, c_to`.
    ///
    /// # Errors
    ///
    /// If an identifier is not valid UTF-8.
    pub fn identifiers(&self) -> Result<[&str; 4], WireError> {
        Ok([
            identifier_str(&self.d_from)?,
            identifier_str(&self.d_to)?,
            identifier_str(&self.c_from)?,
            identifier_str(&self.c_to)?,
        ])
    }

    /// Encode as the draft's `BatchRequest` struct.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + 4 * 2
                + self.d_from.len()
                + self.d_to.len()
                + self.c_from.len()
                + self.c_to.len()
                + ELEMENT_LENGTH
                + 4
                + self.items.len() * CIPHERTEXT_LENGTH,
        );
        out.push(self.kind.to_byte());
        for id in [&self.d_from, &self.d_to, &self.c_from, &self.c_to] {
            write_identifier(&mut out, id);
        }
        out.extend_from_slice(&self.y_from.to_bytes());
        write_items(&mut out, &self.items);
        out
    }

    /// Decode the draft's `BatchRequest` struct, rejecting an unknown type, truncated input,
    /// trailing bytes, an empty batch and invalid elements.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let kind = BatchKind::from_byte(r.u8()?)?;
        let d_from = r.identifier()?;
        let d_to = r.identifier()?;
        let c_from = r.identifier()?;
        let c_to = r.identifier()?;
        let y_from = r.element()?;
        let items = r.items(&y_from)?;
        r.finish()?;
        Ok(Self {
            kind,
            d_from,
            d_to,
            c_from,
            c_to,
            y_from,
            items,
        })
    }
}

impl BatchResponse {
    /// Assemble a response, checking that the batch is not empty and fits its encoding. With
    /// `elgamal3`, every item must be encrypted under `y_to`.
    pub fn new(y_to: GroupElement, items: Vec<ElGamal>) -> Result<Self, WireError> {
        check_items(&items, &y_to)?;
        Ok(Self { y_to, items })
    }

    /// The public key the items are now encrypted under.
    pub fn y_to(&self) -> &GroupElement {
        &self.y_to
    }
    /// The transcrypted ciphertexts.
    pub fn items(&self) -> &[ElGamal] {
        &self.items
    }

    /// Encode as the draft's `BatchResponse` struct.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ELEMENT_LENGTH + 4 + self.items.len() * CIPHERTEXT_LENGTH);
        out.extend_from_slice(&self.y_to.to_bytes());
        write_items(&mut out, &self.items);
        out
    }

    /// Decode the draft's `BatchResponse` struct, rejecting truncated input, trailing bytes, an
    /// empty batch and invalid elements.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let y_to = r.element()?;
        let items = r.items(&y_to)?;
        r.finish()?;
        Ok(Self { y_to, items })
    }
}

/// Length of the encoding of [`SessionKeyShares`]: one scalar per share.
pub const SESSION_KEY_SHARES_LENGTH: usize = 2 * SCALAR_LENGTH;

impl SessionKeyShares {
    /// Encode as `SerializeScalar(u_pseudonym) || SerializeScalar(u_attribute)`, the draft's
    /// session key share encoding in plain mode for each of the two shares.
    pub fn to_bytes(&self) -> [u8; SESSION_KEY_SHARES_LENGTH] {
        let mut out = [0u8; SESSION_KEY_SHARES_LENGTH];
        out[..SCALAR_LENGTH].copy_from_slice(&self.pseudonym.to_bytes());
        out[SCALAR_LENGTH..].copy_from_slice(&self.attribute.to_bytes());
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), rejecting a wrong length and zero scalars.
    pub fn from_bytes(bytes: &[u8; SESSION_KEY_SHARES_LENGTH]) -> Result<Self, WireError> {
        Self::from_slice(bytes)
    }

    /// Decode from a slice, rejecting a wrong length and zero scalars.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let pseudonym = read_share::<PseudonymSessionKeyShare>(&mut r)?;
        let attribute = read_share::<AttributeSessionKeyShare>(&mut r)?;
        r.finish()?;
        Ok(Self {
            pseudonym,
            attribute,
        })
    }
}

fn read_share<S: SessionKeyShare>(r: &mut Reader<'_>) -> Result<S, WireError> {
    let offset = r.offset;
    ScalarNonZero::from_slice(r.take(SCALAR_LENGTH)?)
        .map(S::from_scalar)
        .ok_or(WireError::InvalidScalar { offset })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::elgamal::arithmetic::group_elements::G;
    use crate::elgamal::encrypt;

    fn ciphertexts(n: usize, key: &GroupElement) -> Vec<ElGamal> {
        let rng = &mut rand::rng();
        (0..n)
            .map(|_| encrypt(&GroupElement::random(rng), key, rng))
            .collect()
    }

    fn request(n: usize) -> BatchRequest {
        let key = ScalarNonZero::random(&mut rand::rng()) * G;
        BatchRequest::new(
            BatchKind::Pseudonym,
            "domain-a",
            "domain-b",
            "session-a",
            "session-b",
            key,
            ciphertexts(n, &key),
        )
        .unwrap()
    }

    #[test]
    fn request_round_trip() {
        let req = request(3);
        let bytes = req.to_bytes();
        let expected_len =
            1 + (2 + 8) + (2 + 8) + (2 + 9) + (2 + 9) + 32 + 4 + 3 * CIPHERTEXT_LENGTH;
        assert_eq!(bytes.len(), expected_len);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(&bytes[1..3], &[0, 8]);
        assert_eq!(&bytes[3..11], b"domain-a");
        assert_eq!(BatchRequest::from_bytes(&bytes).unwrap(), req);
    }

    #[test]
    fn response_round_trip() {
        let key = ScalarNonZero::random(&mut rand::rng()) * G;
        let resp = BatchResponse::new(key, ciphertexts(2, &key)).unwrap();
        let bytes = resp.to_bytes();
        assert_eq!(bytes.len(), 32 + 4 + 2 * CIPHERTEXT_LENGTH);
        assert_eq!(&bytes[32..36], &[0, 0, 0, 2]);
        assert_eq!(BatchResponse::from_bytes(&bytes).unwrap(), resp);
    }

    #[test]
    fn attribute_kind_and_empty_identifiers() {
        let key = ScalarNonZero::random(&mut rand::rng()) * G;
        let req = BatchRequest::new(
            BatchKind::Attribute,
            "",
            "",
            "s1",
            "s2",
            key,
            ciphertexts(1, &key),
        )
        .unwrap();
        let bytes = req.to_bytes();
        assert_eq!(bytes[0], 0x02);
        let back = BatchRequest::from_bytes(&bytes).unwrap();
        assert_eq!(back.identifiers().unwrap(), ["", "", "s1", "s2"]);
        assert_eq!(back, req);
    }

    #[test]
    fn rejects_unknown_type() {
        let mut bytes = request(1).to_bytes();
        bytes[0] = 0x03;
        assert_eq!(
            BatchRequest::from_bytes(&bytes),
            Err(WireError::UnknownType(0x03))
        );
    }

    #[test]
    fn rejects_truncated_input() {
        let bytes = request(2).to_bytes();
        for cut in [0, 1, 2, 5, 40, bytes.len() - 65, bytes.len() - 1] {
            assert!(
                matches!(
                    BatchRequest::from_bytes(&bytes[..cut]),
                    Err(WireError::Truncated { .. })
                ),
                "cut at {cut}"
            );
        }
        let req = request(1);
        let resp = BatchResponse::new(*req.y_from(), req.items().to_vec()).unwrap();
        let bytes = resp.to_bytes();
        assert!(matches!(
            BatchResponse::from_bytes(&bytes[..bytes.len() - 1]),
            Err(WireError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = request(1).to_bytes();
        bytes.push(0);
        assert_eq!(
            BatchRequest::from_bytes(&bytes),
            Err(WireError::TrailingBytes(1))
        );
        let resp =
            BatchResponse::from_bytes(&bytes[bytes.len() - 1 - 32 - 4 - 64..bytes.len() - 1]);
        assert!(resp.is_ok());
        assert_eq!(
            BatchResponse::from_bytes(&bytes[bytes.len() - 1 - 32 - 4 - 64..]),
            Err(WireError::TrailingBytes(1))
        );
    }

    #[test]
    fn rejects_zero_items() {
        let req = request(1);
        let mut bytes = req.to_bytes();
        let count_at = bytes.len() - 4 - CIPHERTEXT_LENGTH;
        bytes[count_at..count_at + 4].copy_from_slice(&[0, 0, 0, 0]);
        bytes.truncate(count_at + 4);
        assert_eq!(BatchRequest::from_bytes(&bytes), Err(WireError::EmptyBatch));
        assert_eq!(
            BatchRequest::new(
                BatchKind::Pseudonym,
                "a",
                "b",
                "c",
                "d",
                *req.y_from(),
                vec![]
            ),
            Err(WireError::EmptyBatch)
        );
        assert_eq!(
            BatchResponse::new(*req.y_from(), vec![]),
            Err(WireError::EmptyBatch)
        );
    }

    #[test]
    fn rejects_invalid_and_identity_elements() {
        let req = request(1);
        let bytes = req.to_bytes();
        let key_at = bytes.len() - 4 - CIPHERTEXT_LENGTH - 32;
        // Identity as Y_from.
        let mut identity = bytes.clone();
        identity[key_at..key_at + 32].copy_from_slice(&GroupElement::identity().to_bytes());
        assert_eq!(
            BatchRequest::from_bytes(&identity),
            Err(WireError::InvalidElement { offset: key_at })
        );
        // Non-canonical encoding as the B of the first item.
        let b_at = bytes.len() - CIPHERTEXT_LENGTH;
        let mut invalid = bytes.clone();
        invalid[b_at..b_at + 32].copy_from_slice(&[0xff; 32]);
        assert_eq!(
            BatchRequest::from_bytes(&invalid),
            Err(WireError::InvalidElement { offset: b_at })
        );
        // Identity as the C of the first item.
        let c_at = bytes.len() - 32;
        let mut identity_c = bytes;
        identity_c[c_at..].copy_from_slice(&GroupElement::identity().to_bytes());
        assert_eq!(
            BatchRequest::from_bytes(&identity_c),
            Err(WireError::InvalidElement { offset: c_at })
        );
    }

    #[test]
    fn rejects_oversized_identifier() {
        let key = ScalarNonZero::random(&mut rand::rng()) * G;
        let long = vec![b'x'; MAX_IDENTIFIER_LENGTH + 1];
        assert_eq!(
            BatchRequest::new(
                BatchKind::Pseudonym,
                long.clone(),
                "b",
                "c",
                "d",
                key,
                ciphertexts(1, &key)
            ),
            Err(WireError::IdentifierTooLong(MAX_IDENTIFIER_LENGTH + 1))
        );
        let max = vec![b'x'; MAX_IDENTIFIER_LENGTH];
        let req = BatchRequest::new(
            BatchKind::Pseudonym,
            max,
            "b",
            "c",
            "d",
            key,
            ciphertexts(1, &key),
        )
        .unwrap();
        assert_eq!(BatchRequest::from_bytes(&req.to_bytes()).unwrap(), req);
    }

    #[test]
    fn non_utf8_identifier_is_carried_but_not_a_context() {
        let key = ScalarNonZero::random(&mut rand::rng()) * G;
        let req = BatchRequest::new(
            BatchKind::Pseudonym,
            vec![0xff, 0xfe],
            "b",
            "c",
            "d",
            key,
            ciphertexts(1, &key),
        )
        .unwrap();
        let back = BatchRequest::from_bytes(&req.to_bytes()).unwrap();
        assert_eq!(back.d_from(), &[0xff, 0xfe]);
        assert_eq!(back.identifiers(), Err(WireError::IdentifierNotUtf8));
    }

    #[cfg(feature = "elgamal3")]
    #[test]
    fn rejects_items_under_another_key() {
        let rng = &mut rand::rng();
        let key = ScalarNonZero::random(rng) * G;
        let other = ScalarNonZero::random(rng) * G;
        let mut items = ciphertexts(2, &key);
        items[1] = encrypt(&GroupElement::random(rng), &other, rng);
        assert_eq!(
            BatchRequest::new(BatchKind::Pseudonym, "a", "b", "c", "d", key, items.clone()),
            Err(WireError::KeyMismatch { index: 1 })
        );
        assert_eq!(
            BatchResponse::new(key, items),
            Err(WireError::KeyMismatch { index: 1 })
        );
    }

    #[test]
    fn session_key_shares_round_trip() {
        let rng = &mut rand::rng();
        let shares = SessionKeyShares {
            pseudonym: PseudonymSessionKeyShare::from_scalar(ScalarNonZero::random(rng)),
            attribute: AttributeSessionKeyShare::from_scalar(ScalarNonZero::random(rng)),
        };
        let bytes = shares.to_bytes();
        assert_eq!(&bytes[..32], &shares.pseudonym.to_bytes());
        assert_eq!(&bytes[32..], &shares.attribute.to_bytes());
        assert_eq!(SessionKeyShares::from_bytes(&bytes).unwrap(), shares);
        assert_eq!(SessionKeyShares::from_slice(&bytes).unwrap(), shares);
    }

    #[test]
    fn session_key_shares_reject_bad_input() {
        let rng = &mut rand::rng();
        let shares = SessionKeyShares {
            pseudonym: PseudonymSessionKeyShare::from_scalar(ScalarNonZero::random(rng)),
            attribute: AttributeSessionKeyShare::from_scalar(ScalarNonZero::random(rng)),
        };
        let bytes = shares.to_bytes();
        assert!(matches!(
            SessionKeyShares::from_slice(&bytes[..63]),
            Err(WireError::Truncated { .. })
        ));
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(
            SessionKeyShares::from_slice(&long),
            Err(WireError::TrailingBytes(1))
        );
        let mut zero = bytes;
        zero[32..].copy_from_slice(&[0u8; 32]);
        assert_eq!(
            SessionKeyShares::from_bytes(&zero),
            Err(WireError::InvalidScalar { offset: 32 })
        );
        let mut unreduced = bytes;
        unreduced[..32].copy_from_slice(&[0xff; 32]);
        assert_eq!(
            SessionKeyShares::from_bytes(&unreduced),
            Err(WireError::InvalidScalar { offset: 0 })
        );
    }
}
