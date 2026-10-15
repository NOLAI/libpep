//! DLEQ proofs in the encoding of RFC 9497, generic over the [`Group`].

use crate::elgamal::arithmetic::ciphersuite::Ciphersuite;
use crate::elgamal::arithmetic::group::Group;
use rand_core::{CryptoRng, Rng};
use sha2::Digest;

/// A DLEQ proof in the encoding of RFC 9497: the challenge `c` and the response `s`.
///
/// Serializes to [`LENGTH`](Self::LENGTH) bytes as `SerializeScalar(c) || SerializeScalar(s)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Proof<G: Group> {
    /// The challenge scalar.
    pub c: G::ScalarCanBeZero,
    /// The response scalar.
    pub s: G::ScalarCanBeZero,
}

impl<G: Group> Proof<G> {
    /// The length of a serialized proof in bytes: two scalars.
    pub const LENGTH: usize = 2 * G::NS;

    /// Serialize as `SerializeScalar(c) || SerializeScalar(s)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LENGTH);
        out.extend_from_slice(G::serialize_scalar_can_be_zero(&self.c).as_ref());
        out.extend_from_slice(G::serialize_scalar_can_be_zero(&self.s).as_ref());
        out
    }

    /// Deserialize from exactly [`LENGTH`](Self::LENGTH) bytes.
    ///
    /// Returns `None` if the input has another length or either half is not a canonical scalar
    /// encoding.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::LENGTH {
            return None;
        }
        Some(Self {
            c: G::deserialize_scalar_can_be_zero(&bytes[..G::NS])?,
            s: G::deserialize_scalar_can_be_zero(&bytes[G::NS..])?,
        })
    }
}

/// Errors that can occur while generating a proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProofError {
    /// The `cs` and `ds` lists have different lengths, or are empty.
    #[error("DLEQ proof needs equally long, non-empty element lists (got {cs} and {ds})")]
    MismatchedLists {
        /// Length of the `cs` list.
        cs: usize,
        /// Length of the `ds` list.
        ds: usize,
    },
}

/// The domain separation tags a proof transcript needs.
///
/// RFC 9497 uses the context string in two distinct ways here, and the difference matters for
/// interoperability: `seedDST` is `"Seed-" || contextString` and appears *inside* the seed
/// transcript, whereas the trailing `"Composite"` and `"Challenge"` labels are bare literals,
/// with the context string entering only through `HashToScalar`'s own DST
/// (`"HashToScalar-" || contextString`).
///
/// Normally built from the [`Ciphersuite`], whose context string is prefixed `"coPRFV1-"`.
/// RFC 9497's own test vectors use its `"OPRFV1-"` prefix, so the test module builds these
/// directly in order to cross-check the transcript against Appendix A.1.2.
#[derive(Clone)]
pub(crate) struct Dsts {
    /// `"Seed-" || contextString`, hashed inside the seed transcript.
    pub(crate) seed: Vec<u8>,
    /// `"HashToScalar-" || contextString`, the DST of every `HashToScalar` call.
    pub(crate) hash_to_scalar: Vec<u8>,
}

impl Dsts {
    pub(crate) fn from_ciphersuite(ciphersuite: &Ciphersuite) -> Self {
        Self {
            seed: ciphersuite.dst(b"Seed-"),
            hash_to_scalar: ciphersuite.dst(b"HashToScalar-"),
        }
    }
}

/// `HashToScalar` of RFC 9497 in the full scalar field: zero is zero.
fn hash_to_scalar<G: Group>(msg: &[u8], dst: &[u8]) -> G::ScalarCanBeZero {
    G::hash_to_scalar(msg, dst).map_or_else(Default::default, Into::into)
}

/// `I2OSP(len(bytes), 2) || bytes`, the length-prefixed encoding RFC 9497 uses in transcripts.
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    debug_assert!(bytes.len() <= u16::MAX as usize);
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The seed transcript of `ComputeComposites`:
/// `I2OSP(len(Bm),2) || Bm || I2OSP(len("Seed-"||ctx),2) || "Seed-"||ctx`.
fn compute_seed<G: Group>(b: &G::Element, dsts: &Dsts) -> Vec<u8> {
    let mut transcript = Vec::new();
    push_len_prefixed(&mut transcript, G::serialize_element(b).as_ref());
    push_len_prefixed(&mut transcript, &dsts.seed);
    // RFC 9497 uses the ciphersuite's plain hash here, not expand_message_xmd.
    G::Hash::digest(&transcript).to_vec()
}

/// `ComputeComposites` of RFC 9497, Section 2.2.1.
///
/// Folds the `(C_i, D_i)` pairs into a single pair `(M, Z)` with per-index weights derived from
/// the seed, so that one proof covers the whole list. When the prover's scalar `k` is known the
/// fast path computes `Z = k * M` directly; otherwise `Z` is accumulated from the `ds`.
fn compute_composites<G: Group>(
    k: Option<&G::Scalar>,
    b: &G::Element,
    cs: &[G::Element],
    ds: &[G::Element],
    dsts: &Dsts,
) -> (G::Element, G::Element) {
    let seed = compute_seed::<G>(b, dsts);

    let mut m = G::identity();
    let mut z = G::identity();

    for (i, (c_i, d_i)) in cs.iter().zip(ds.iter()).enumerate() {
        let mut transcript = Vec::new();
        push_len_prefixed(&mut transcript, &seed);
        transcript.extend_from_slice(&(i as u16).to_be_bytes());
        push_len_prefixed(&mut transcript, G::serialize_element(c_i).as_ref());
        push_len_prefixed(&mut transcript, G::serialize_element(d_i).as_ref());
        transcript.extend_from_slice(b"Composite");

        let d_i_scalar = hash_to_scalar::<G>(&transcript, &dsts.hash_to_scalar);
        m = m + d_i_scalar * *c_i;
        if k.is_none() {
            z = z + d_i_scalar * *d_i;
        }
    }

    if let Some(k) = k {
        z = *k * m;
    }
    (m, z)
}

/// The challenge transcript of RFC 9497, Section 2.2:
/// the length-prefixed elements `B, M, Z, t2, t3` followed by the bare label `"Challenge"`.
fn challenge<G: Group>(
    b: &G::Element,
    m: &G::Element,
    z: &G::Element,
    t2: &G::Element,
    t3: &G::Element,
    dsts: &Dsts,
) -> G::ScalarCanBeZero {
    let mut transcript = Vec::new();
    for element in [b, m, z, t2, t3] {
        push_len_prefixed(&mut transcript, G::serialize_element(element).as_ref());
    }
    transcript.extend_from_slice(b"Challenge");
    hash_to_scalar::<G>(&transcript, &dsts.hash_to_scalar)
}

/// `GenerateProof` of RFC 9497, Section 2.2, domain separated by the group's
/// [`CIPHERSUITE`](Group::CIPHERSUITE).
///
/// Proves that `b = k * a` and `ds[i] = k * cs[i]` for every `i`, without revealing `k`.
///
/// # Errors
///
/// Returns [`ProofError::MismatchedLists`] if `cs` and `ds` differ in length or are empty.
pub fn generate_proof<G: Group, R: Rng + CryptoRng>(
    k: &G::Scalar,
    a: &G::Element,
    b: &G::Element,
    cs: &[G::Element],
    ds: &[G::Element],
    rng: &mut R,
) -> Result<Proof<G>, ProofError> {
    if cs.is_empty() || cs.len() != ds.len() {
        return Err(ProofError::MismatchedLists {
            cs: cs.len(),
            ds: ds.len(),
        });
    }

    let dsts = Dsts::from_ciphersuite(&G::CIPHERSUITE);
    Ok(generate_proof_with::<G>(
        k,
        a,
        b,
        cs,
        ds,
        &dsts,
        &G::random_scalar(rng),
    ))
}

/// The deterministic core of [`generate_proof`], with the proof's random scalar supplied.
///
/// Separated so that the RFC 9497 test vectors, which fix `ProofRandomScalar`, can be
/// reproduced exactly. Callers outside the tests must use [`generate_proof`], which samples
/// the scalar freshly: reusing one across proofs leaks the secret.
pub(crate) fn generate_proof_with<G: Group>(
    k: &G::Scalar,
    a: &G::Element,
    b: &G::Element,
    cs: &[G::Element],
    ds: &[G::Element],
    dsts: &Dsts,
    r: &G::Scalar,
) -> Proof<G> {
    let (m, z) = compute_composites::<G>(Some(k), b, cs, ds, dsts);

    let t2 = *r * *a;
    let t3 = *r * m;

    let c = challenge::<G>(b, &m, &z, &t2, &t3, dsts);
    // s = r - c * k, in the full scalar field (c and s may be zero).
    let s = G::ScalarCanBeZero::from(*r) - c * G::ScalarCanBeZero::from(*k);

    Proof { c, s }
}

/// `VerifyProof` of RFC 9497, Section 2.2, domain separated by the group's
/// [`CIPHERSUITE`](Group::CIPHERSUITE).
///
/// Checks that the same scalar relates `a` to `b` and every `cs[i]` to `ds[i]`. Returns `false`
/// on any mismatch, and also when the lists are empty or of different lengths.
#[must_use]
pub fn verify_proof<G: Group>(
    a: &G::Element,
    b: &G::Element,
    cs: &[G::Element],
    ds: &[G::Element],
    proof: &Proof<G>,
) -> bool {
    verify_proof_with::<G>(
        a,
        b,
        cs,
        ds,
        proof,
        &Dsts::from_ciphersuite(&G::CIPHERSUITE),
    )
}

/// The DST-parameterised core of [`verify_proof`].
pub(crate) fn verify_proof_with<G: Group>(
    a: &G::Element,
    b: &G::Element,
    cs: &[G::Element],
    ds: &[G::Element],
    proof: &Proof<G>,
    dsts: &Dsts,
) -> bool {
    if cs.is_empty() || cs.len() != ds.len() {
        return false;
    }

    let (m, z) = compute_composites::<G>(None, b, cs, ds, dsts);

    // t2 = s * A + c * B, t3 = s * M + c * Z
    let t2 = proof.s * *a + proof.c * *b;
    let t3 = proof.s * m + proof.c * z;

    let expected = challenge::<G>(b, &m, &z, &t2, &t3, dsts);
    expected == proof.c
}
