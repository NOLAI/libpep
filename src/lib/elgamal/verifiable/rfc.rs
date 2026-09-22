//! Wire layouts for the verifiable mode of draft-doesburg-cfrg-coprf, in the RFC 9497
//! proof encoding of [`crate::elgamal::dleq`].
//!
//! These are the byte layouts of the draft's "Wire Encodings" section, for modeVcoPRF on
//! ristretto255 (`Ne = Ns = 32`):
//!
//! | Structure | Layout | Size |
//! |:----------|:-------|-----:|
//! | Proof | `SerializeScalar(c) \|\| SerializeScalar(s)` | `2 * Ns` = 64 |
//! | [`RerandomizeMaterial`] | `R \|\| Yr \|\| proof_r` | `2 * Ne + 2 * Ns` = 128 |
//! | [`PseudonymBatchHeader`] | `S \|\| K \|\| T \|\| Y_to \|\| proof_S \|\| proof_K \|\| proof_T \|\| proof_B \|\| proof_C` | `4 * Ne + 10 * Ns` = 448 |
//! | [`AttributeBatchHeader`] | `K \|\| Y_to \|\| proof_K \|\| proof_B` | `2 * Ne + 4 * Ns` = 192 |
//! | [`SessionKeyShareMaterial`] | `SerializeScalar(u_i) \|\| U_i \|\| proof_u` | `Ne + 3 * Ns` = 128 |
//!
//! So verifiable transcryption adds 128 bytes per pseudonym plus 448 bytes per batch, and
//! 128 bytes per attribute plus 192 bytes per batch.
//!
//! Every `from_slice` is strict: it rejects a wrong length, a non-canonical scalar, and any
//! element that fails [`GroupElement::from_slice`] (which already rejects the identity).

use crate::elgamal::arithmetic::group_elements::GroupElement;
use crate::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
use crate::elgamal::dleq::{Proof, PROOF_SIZE};

/// Size of a serialized group element, `Ne` for ristretto255.
pub const ELEMENT_SIZE: usize = 32;
/// Size of a serialized scalar, `Ns` for ristretto255.
pub const SCALAR_SIZE: usize = 32;

/// Wire size of [`RerandomizeMaterial`]: `2 * Ne + 2 * Ns`.
pub const RERANDOMIZE_MATERIAL_SIZE: usize = 2 * ELEMENT_SIZE + PROOF_SIZE;
/// Wire size of [`PseudonymBatchHeader`]: `4 * Ne + 10 * Ns`.
pub const PSEUDONYM_BATCH_HEADER_SIZE: usize = 4 * ELEMENT_SIZE + 5 * PROOF_SIZE;
/// Wire size of [`AttributeBatchHeader`]: `2 * Ne + 4 * Ns`.
pub const ATTRIBUTE_BATCH_HEADER_SIZE: usize = 2 * ELEMENT_SIZE + 2 * PROOF_SIZE;
/// Wire size of [`SessionKeyShareMaterial`]: `Ne + 3 * Ns`.
pub const SESSION_KEY_SHARE_SIZE: usize = ELEMENT_SIZE + SCALAR_SIZE + PROOF_SIZE;

/// Reads a group element from `bytes[at..at + Ne]`, rejecting the identity.
fn take_element(bytes: &[u8], at: usize) -> Option<GroupElement> {
    GroupElement::from_slice(bytes.get(at..at + ELEMENT_SIZE)?)
}

/// Reads a proof from `bytes[at..at + 2 * Ns]`.
fn take_proof(bytes: &[u8], at: usize) -> Option<Proof> {
    Proof::from_slice(bytes.get(at..at + PROOF_SIZE)?)
}

/// Per-ciphertext rerandomization material: `(R, Yr, proof_r)`.
///
/// Each ciphertext of a batch MUST carry its own, with its own `r`; sharing one across a batch
/// would make the outputs linkable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RerandomizeMaterial {
    /// `R = r * G`.
    pub r: GroupElement,
    /// `Yr = r * Y`.
    pub yr: GroupElement,
    /// Proof that the same `r` relates `G` to `R` and `Y` to `Yr`.
    pub proof_r: Proof,
}

impl RerandomizeMaterial {
    /// Serialize as `R || Yr || proof_r`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; RERANDOMIZE_MATERIAL_SIZE] {
        let mut out = [0u8; RERANDOMIZE_MATERIAL_SIZE];
        out[..32].copy_from_slice(&self.r.to_bytes());
        out[32..64].copy_from_slice(&self.yr.to_bytes());
        out[64..].copy_from_slice(&self.proof_r.to_bytes());
        out
    }

    /// Deserialize from exactly [`RERANDOMIZE_MATERIAL_SIZE`] bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != RERANDOMIZE_MATERIAL_SIZE {
            return None;
        }
        Some(Self {
            r: take_element(bytes, 0)?,
            yr: take_element(bytes, 32)?,
            proof_r: take_proof(bytes, 64)?,
        })
    }
}

/// Per-batch header for a verifiable pseudonym transcryption (VRRSK).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PseudonymBatchHeader {
    /// `S = s * G`, the commitment to the reshuffle factor.
    pub s: GroupElement,
    /// `K = k * G`, the commitment to the rekey factor.
    pub k: GroupElement,
    /// `T = t * G` with `t = s * k^-1`.
    pub t: GroupElement,
    /// `Y_to = k * Y`, the key the output is encrypted under.
    pub y_to: GroupElement,
    /// Proof chaining `S` to the recorded `S_from` / `S_to` commitments.
    pub proof_s: Proof,
    /// Proof chaining `K` to the recorded `K_from` / `K_to` commitments.
    pub proof_k: Proof,
    /// Proof that `S = k * T` and `Y_to = k * Y`.
    pub proof_t: Proof,
    /// Batched proof over the `B` components.
    pub proof_b: Proof,
    /// Batched proof over the `C` components.
    pub proof_c: Proof,
}

impl PseudonymBatchHeader {
    /// Serialize as `S || K || T || Y_to || proof_S || proof_K || proof_T || proof_B || proof_C`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PSEUDONYM_BATCH_HEADER_SIZE] {
        let mut out = [0u8; PSEUDONYM_BATCH_HEADER_SIZE];
        out[..32].copy_from_slice(&self.s.to_bytes());
        out[32..64].copy_from_slice(&self.k.to_bytes());
        out[64..96].copy_from_slice(&self.t.to_bytes());
        out[96..128].copy_from_slice(&self.y_to.to_bytes());
        for (i, proof) in [
            self.proof_s,
            self.proof_k,
            self.proof_t,
            self.proof_b,
            self.proof_c,
        ]
        .iter()
        .enumerate()
        {
            let at = 128 + i * PROOF_SIZE;
            out[at..at + PROOF_SIZE].copy_from_slice(&proof.to_bytes());
        }
        out
    }

    /// Deserialize from exactly [`PSEUDONYM_BATCH_HEADER_SIZE`] bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PSEUDONYM_BATCH_HEADER_SIZE {
            return None;
        }
        Some(Self {
            s: take_element(bytes, 0)?,
            k: take_element(bytes, 32)?,
            t: take_element(bytes, 64)?,
            y_to: take_element(bytes, 96)?,
            proof_s: take_proof(bytes, 128)?,
            proof_k: take_proof(bytes, 128 + PROOF_SIZE)?,
            proof_t: take_proof(bytes, 128 + 2 * PROOF_SIZE)?,
            proof_b: take_proof(bytes, 128 + 3 * PROOF_SIZE)?,
            proof_c: take_proof(bytes, 128 + 4 * PROOF_SIZE)?,
        })
    }
}

/// Per-batch header for a verifiable attribute rekey (VRRK).
///
/// Attributes are only rerandomized and rekeyed, so there is no reshuffle factor and the `B`
/// proof runs in the inverse direction with `(Y, Y_to)` appended to the lists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributeBatchHeader {
    /// `K = k * G`, the commitment to the attribute rekey factor.
    pub k: GroupElement,
    /// `Y_to = k * Y`.
    pub y_to: GroupElement,
    /// Proof chaining `K` to the recorded attribute commitments.
    pub proof_k: Proof,
    /// Batched proof over the `B` components, in the inverse direction.
    pub proof_b: Proof,
}

impl AttributeBatchHeader {
    /// Serialize as `K || Y_to || proof_K || proof_B`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ATTRIBUTE_BATCH_HEADER_SIZE] {
        let mut out = [0u8; ATTRIBUTE_BATCH_HEADER_SIZE];
        out[..32].copy_from_slice(&self.k.to_bytes());
        out[32..64].copy_from_slice(&self.y_to.to_bytes());
        out[64..64 + PROOF_SIZE].copy_from_slice(&self.proof_k.to_bytes());
        out[64 + PROOF_SIZE..].copy_from_slice(&self.proof_b.to_bytes());
        out
    }

    /// Deserialize from exactly [`ATTRIBUTE_BATCH_HEADER_SIZE`] bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ATTRIBUTE_BATCH_HEADER_SIZE {
            return None;
        }
        Some(Self {
            k: take_element(bytes, 0)?,
            y_to: take_element(bytes, 32)?,
            proof_k: take_proof(bytes, 64)?,
            proof_b: take_proof(bytes, 64 + PROOF_SIZE)?,
        })
    }
}

/// A session key share with its proof of correct construction.
///
/// The share itself is secret: this is sent only to the receiver requesting the session key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionKeyShareMaterial {
    /// The share `u_i = b_i * k_c,i`.
    pub u: ScalarNonZero,
    /// `U_i = u_i * G`.
    pub u_commitment: GroupElement,
    /// Proof that the same `b_i` relates `G` to `B_i` and `K_c,i` to `U_i`.
    pub proof_u: Proof,
}

impl SessionKeyShareMaterial {
    /// Serialize as `SerializeScalar(u) || U || proof_u`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SESSION_KEY_SHARE_SIZE] {
        let mut out = [0u8; SESSION_KEY_SHARE_SIZE];
        out[..32].copy_from_slice(&self.u.to_bytes());
        out[32..64].copy_from_slice(&self.u_commitment.to_bytes());
        out[64..].copy_from_slice(&self.proof_u.to_bytes());
        out
    }

    /// Deserialize from exactly [`SESSION_KEY_SHARE_SIZE`] bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SESSION_KEY_SHARE_SIZE {
            return None;
        }
        Some(Self {
            u: ScalarNonZero::from_slice(bytes.get(0..32)?)?,
            u_commitment: take_element(bytes, 32)?,
            proof_u: take_proof(bytes, 64)?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::elgamal::arithmetic::group_elements::G;
    use crate::elgamal::dleq::generate_proof;
    use crate::protocol::Context;

    fn a_proof() -> Proof {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        generate_proof(&k, &G, &(k * G), &[c], &[k * c], &Context::default(), rng).unwrap()
    }

    fn an_element() -> GroupElement {
        GroupElement::random(&mut rand::rng())
    }

    /// The sizes are those tabulated in the draft's "Wire Encodings" section.
    #[test]
    fn wire_sizes_match_the_draft() {
        assert_eq!(PROOF_SIZE, 64);
        assert_eq!(RERANDOMIZE_MATERIAL_SIZE, 128);
        assert_eq!(PSEUDONYM_BATCH_HEADER_SIZE, 448);
        assert_eq!(ATTRIBUTE_BATCH_HEADER_SIZE, 192);
        assert_eq!(SESSION_KEY_SHARE_SIZE, 128);
    }

    #[test]
    fn rerandomize_material_round_trip() {
        let m = RerandomizeMaterial {
            r: an_element(),
            yr: an_element(),
            proof_r: a_proof(),
        };
        let bytes = m.to_bytes();
        assert_eq!(RerandomizeMaterial::from_slice(&bytes).unwrap(), m);
        assert!(RerandomizeMaterial::from_slice(&bytes[..127]).is_none());
    }

    #[test]
    fn pseudonym_batch_header_round_trip() {
        let h = PseudonymBatchHeader {
            s: an_element(),
            k: an_element(),
            t: an_element(),
            y_to: an_element(),
            proof_s: a_proof(),
            proof_k: a_proof(),
            proof_t: a_proof(),
            proof_b: a_proof(),
            proof_c: a_proof(),
        };
        let bytes = h.to_bytes();
        assert_eq!(PseudonymBatchHeader::from_slice(&bytes).unwrap(), h);
        assert!(PseudonymBatchHeader::from_slice(&bytes[..447]).is_none());
    }

    #[test]
    fn attribute_batch_header_round_trip() {
        let h = AttributeBatchHeader {
            k: an_element(),
            y_to: an_element(),
            proof_k: a_proof(),
            proof_b: a_proof(),
        };
        let bytes = h.to_bytes();
        assert_eq!(AttributeBatchHeader::from_slice(&bytes).unwrap(), h);
        assert!(AttributeBatchHeader::from_slice(&bytes[..191]).is_none());
    }

    #[test]
    fn session_key_share_round_trip() {
        let m = SessionKeyShareMaterial {
            u: ScalarNonZero::random(&mut rand::rng()),
            u_commitment: an_element(),
            proof_u: a_proof(),
        };
        let bytes = m.to_bytes();
        assert_eq!(SessionKeyShareMaterial::from_slice(&bytes).unwrap(), m);
        assert!(SessionKeyShareMaterial::from_slice(&bytes[..127]).is_none());
    }

    /// The identity element is not a valid encoding anywhere in these structures.
    #[test]
    fn identity_elements_are_rejected() {
        let mut bytes = RerandomizeMaterial {
            r: an_element(),
            yr: an_element(),
            proof_r: a_proof(),
        }
        .to_bytes();
        bytes[..32].copy_from_slice(&GroupElement::identity().to_bytes());
        assert!(RerandomizeMaterial::from_slice(&bytes).is_none());
    }

    /// Trailing bytes must be rejected, not silently ignored.
    #[test]
    fn trailing_bytes_are_rejected() {
        let m = RerandomizeMaterial {
            r: an_element(),
            yr: an_element(),
            proof_r: a_proof(),
        };
        let mut bytes = m.to_bytes().to_vec();
        bytes.push(0);
        assert!(RerandomizeMaterial::from_slice(&bytes).is_none());
    }
}
