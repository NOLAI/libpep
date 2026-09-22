//! Discrete-logarithm-equivalence (DLEQ) proofs in the encoding of RFC 9497.
//!
//! A DLEQ proof shows that the same secret scalar `k` relates two pairs of group elements,
//! `B = k * A` and `D_i = k * C_i`, without revealing `k`. This module implements the
//! `GenerateProof` / `VerifyProof` pair of [RFC 9497, Section 2.2], including the
//! `ComputeComposites` batching that lets a single proof cover many `(C_i, D_i)` pairs
//! transformed with the same scalar.
//!
//! # Relation to [`super::zkps`]
//!
//! [`super::zkps::Proof`] is the four-element encoding `(N, C1, C2, s)` of the published paper.
//! It remains available and unchanged. The encoding here is the RFC's: a proof is the two
//! scalars `(c, s)` and the verifier recomputes the commitments. Proofs in the two encodings are
//! **not** interchangeable.
//!
//! # Domain separation
//!
//! The transcripts end in the bare labels `"Composite"` and `"Challenge"`, and the context
//! string enters through the DSTs of `HashToScalar` (`"HashToScalar-" || contextString`) and of
//! the seed (`"Seed-" || contextString`), exactly as in the RFC. The context string comes from
//! the protocol [`Context`], so two deployments with different context strings produce proofs
//! that never verify against one another.
//!
//! The implementation is cross-checked against the ristretto255-SHA512 VOPRF test vectors of
//! RFC 9497 Appendix A.1.2, for both a single pair and a batch of two.
//!
//! # Example
//!
//! ```
//! # use libpep::elgamal::arithmetic::group_elements::{GroupElement, G};
//! # use libpep::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
//! # use libpep::elgamal::dleq::{generate_proof, verify_proof};
//! # use libpep::protocol::Context;
//! let mut rng = rand::rng();
//! let ctx = Context::default();
//!
//! let k = ScalarNonZero::random(&mut rng);
//! let a = G;
//! let b = k * a;
//! let cs = [GroupElement::random(&mut rng), GroupElement::random(&mut rng)];
//! let ds = [k * cs[0], k * cs[1]];
//!
//! let proof = generate_proof(&k, &a, &b, &cs, &ds, &ctx, &mut rng).unwrap();
//! assert!(verify_proof(&a, &b, &cs, &ds, &proof, &ctx));
//! ```
//!
//! [RFC 9497, Section 2.2]: https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2

use rand_core::{CryptoRng, Rng};

use crate::elgamal::arithmetic::group_elements::GroupElement;
use crate::elgamal::arithmetic::hashing::hash_to_scalar;
use crate::elgamal::arithmetic::scalars::{ScalarCanBeZero, ScalarNonZero, ScalarTraits};
use crate::protocol::Context;

/// Byte length of a serialized proof: two scalars.
pub const PROOF_SIZE: usize = 64;

/// A DLEQ proof in the encoding of RFC 9497: the challenge `c` and the response `s`.
///
/// Serializes to exactly [`PROOF_SIZE`] bytes as `SerializeScalar(c) || SerializeScalar(s)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Proof {
    /// The challenge scalar.
    pub c: ScalarCanBeZero,
    /// The response scalar.
    pub s: ScalarCanBeZero,
}

impl Proof {
    /// Serialize as `SerializeScalar(c) || SerializeScalar(s)`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PROOF_SIZE] {
        let mut out = [0u8; PROOF_SIZE];
        out[..32].copy_from_slice(&self.c.to_bytes());
        out[32..].copy_from_slice(&self.s.to_bytes());
        out
    }

    /// Deserialize from exactly [`PROOF_SIZE`] bytes.
    ///
    /// Returns `None` if the input is not [`PROOF_SIZE`] bytes or either half is not a
    /// canonical scalar encoding.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PROOF_SIZE {
            return None;
        }
        Some(Self {
            c: ScalarCanBeZero::from_slice(&bytes[..32])?,
            s: ScalarCanBeZero::from_slice(&bytes[32..])?,
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
/// Normally built from the protocol [`Context`], whose context string is prefixed `"coPRFV1-"`.
/// RFC 9497's own test vectors use its `"OPRFV1-"` prefix, so the test module builds these
/// directly in order to cross-check the transcript against Appendix A.1.2.
#[derive(Clone)]
struct Dsts {
    /// `"Seed-" || contextString`, hashed inside the seed transcript.
    seed: Vec<u8>,
    /// `"HashToScalar-" || contextString`, the DST of every `HashToScalar` call.
    hash_to_scalar: Vec<u8>,
}

impl Dsts {
    fn from_context(context: &Context) -> Self {
        Self {
            seed: context.dst(b"Seed-"),
            hash_to_scalar: context.dst(b"HashToScalar-"),
        }
    }
}

/// `I2OSP(len(bytes), 2) || bytes`, the length-prefixed encoding RFC 9497 uses in transcripts.
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    debug_assert!(bytes.len() <= u16::MAX as usize);
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The seed transcript of `ComputeComposites`:
/// `I2OSP(len(Bm),2) || Bm || I2OSP(len("Seed-"||ctx),2) || "Seed-"||ctx`.
fn compute_seed(b: &GroupElement, dsts: &Dsts) -> Vec<u8> {
    use sha2::Digest;
    let mut transcript = Vec::new();
    push_len_prefixed(&mut transcript, &b.to_bytes());
    push_len_prefixed(&mut transcript, &dsts.seed);
    // RFC 9497 uses the ciphersuite's plain hash here, not expand_message_xmd.
    sha2::Sha512::digest(&transcript).to_vec()
}

/// `ComputeComposites` of RFC 9497, Section 2.2.1.
///
/// Folds the `(C_i, D_i)` pairs into a single pair `(M, Z)` with per-index weights derived from
/// the seed, so that one proof covers the whole list. When the prover's scalar `k` is known the
/// fast path computes `Z = k * M` directly; otherwise `Z` is accumulated from the `ds`.
fn compute_composites(
    k: Option<&ScalarNonZero>,
    b: &GroupElement,
    cs: &[GroupElement],
    ds: &[GroupElement],
    dsts: &Dsts,
) -> (GroupElement, GroupElement) {
    let seed = compute_seed(b, dsts);

    let mut m = GroupElement::identity();
    let mut z = GroupElement::identity();

    for (i, (c_i, d_i)) in cs.iter().zip(ds.iter()).enumerate() {
        let mut transcript = Vec::new();
        push_len_prefixed(&mut transcript, &seed);
        transcript.extend_from_slice(&(i as u16).to_be_bytes());
        push_len_prefixed(&mut transcript, &c_i.to_bytes());
        push_len_prefixed(&mut transcript, &d_i.to_bytes());
        transcript.extend_from_slice(b"Composite");

        let d_i_scalar = hash_to_scalar(&transcript, &dsts.hash_to_scalar);
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
fn challenge(
    b: &GroupElement,
    m: &GroupElement,
    z: &GroupElement,
    t2: &GroupElement,
    t3: &GroupElement,
    dsts: &Dsts,
) -> ScalarCanBeZero {
    let mut transcript = Vec::new();
    push_len_prefixed(&mut transcript, &b.to_bytes());
    push_len_prefixed(&mut transcript, &m.to_bytes());
    push_len_prefixed(&mut transcript, &z.to_bytes());
    push_len_prefixed(&mut transcript, &t2.to_bytes());
    push_len_prefixed(&mut transcript, &t3.to_bytes());
    transcript.extend_from_slice(b"Challenge");
    hash_to_scalar(&transcript, &dsts.hash_to_scalar)
}

/// `GenerateProof` of RFC 9497, Section 2.2.
///
/// Proves that `b = k * a` and `ds[i] = k * cs[i]` for every `i`, without revealing `k`.
///
/// # Errors
///
/// Returns [`ProofError::MismatchedLists`] if `cs` and `ds` differ in length or are empty.
pub fn generate_proof<R: Rng + CryptoRng>(
    k: &ScalarNonZero,
    a: &GroupElement,
    b: &GroupElement,
    cs: &[GroupElement],
    ds: &[GroupElement],
    context: &Context,
    rng: &mut R,
) -> Result<Proof, ProofError> {
    if cs.is_empty() || cs.len() != ds.len() {
        return Err(ProofError::MismatchedLists {
            cs: cs.len(),
            ds: ds.len(),
        });
    }

    let dsts = Dsts::from_context(context);
    Ok(generate_proof_with(
        k,
        a,
        b,
        cs,
        ds,
        &dsts,
        &ScalarNonZero::random(rng),
    ))
}

/// The deterministic core of [`generate_proof`], with the proof's random scalar supplied.
///
/// Separated so that the RFC 9497 test vectors, which fix `ProofRandomScalar`, can be
/// reproduced exactly. Callers outside the tests must use [`generate_proof`], which samples
/// the scalar freshly: reusing one across proofs leaks the secret.
fn generate_proof_with(
    k: &ScalarNonZero,
    a: &GroupElement,
    b: &GroupElement,
    cs: &[GroupElement],
    ds: &[GroupElement],
    dsts: &Dsts,
    r: &ScalarNonZero,
) -> Proof {
    let (m, z) = compute_composites(Some(k), b, cs, ds, dsts);

    let t2 = *r * *a;
    let t3 = *r * m;

    let c = challenge(b, &m, &z, &t2, &t3, dsts);
    // s = r - c * k, in the full scalar field (c and s may be zero). `ScalarCanBeZero` has no
    // multiplication operator, so the product is formed on the underlying scalars.
    let ck = ScalarCanBeZero(c.raw() * k.raw());
    let s = ScalarCanBeZero(*r.raw()) - ck;

    Proof { c, s }
}

/// `VerifyProof` of RFC 9497, Section 2.2.
///
/// Checks that the same scalar relates `a` to `b` and every `cs[i]` to `ds[i]`. Returns `false`
/// on any mismatch, and also when the lists are empty or of different lengths.
#[must_use]
pub fn verify_proof(
    a: &GroupElement,
    b: &GroupElement,
    cs: &[GroupElement],
    ds: &[GroupElement],
    proof: &Proof,
    context: &Context,
) -> bool {
    verify_proof_with(a, b, cs, ds, proof, &Dsts::from_context(context))
}

/// The DST-parameterised core of [`verify_proof`].
fn verify_proof_with(
    a: &GroupElement,
    b: &GroupElement,
    cs: &[GroupElement],
    ds: &[GroupElement],
    proof: &Proof,
    dsts: &Dsts,
) -> bool {
    if cs.is_empty() || cs.len() != ds.len() {
        return false;
    }

    let (m, z) = compute_composites(None, b, cs, ds, dsts);

    // t2 = s * A + c * B, t3 = s * M + c * Z
    let t2 = proof.s * *a + proof.c * *b;
    let t3 = proof.s * m + proof.c * z;

    let expected = challenge(b, &m, &z, &t2, &t3, dsts);
    expected == proof.c
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::elgamal::arithmetic::group_elements::G;

    fn ctx() -> Context {
        Context::default()
    }

    #[test]
    fn single_pair_round_trip() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        let proof = generate_proof(&k, &G, &(k * G), &[c], &[k * c], &ctx(), rng).unwrap();
        assert!(verify_proof(&G, &(k * G), &[c], &[k * c], &proof, &ctx()));
    }

    #[test]
    fn batched_round_trip() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let cs: Vec<_> = (0..3).map(|_| GroupElement::random(rng)).collect();
        let ds: Vec<_> = cs.iter().map(|c| k * *c).collect();
        let proof = generate_proof(&k, &G, &(k * G), &cs, &ds, &ctx(), rng).unwrap();
        assert!(verify_proof(&G, &(k * G), &cs, &ds, &proof, &ctx()));
    }

    /// A batched proof must not verify if any single `d_i` is replaced.
    #[test]
    fn batched_proof_rejects_a_single_tampered_element() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let cs: Vec<_> = (0..3).map(|_| GroupElement::random(rng)).collect();
        let ds: Vec<_> = cs.iter().map(|c| k * *c).collect();
        let proof = generate_proof(&k, &G, &(k * G), &cs, &ds, &ctx(), rng).unwrap();

        for i in 0..ds.len() {
            let mut tampered = ds.clone();
            tampered[i] = GroupElement::random(rng);
            assert!(
                !verify_proof(&G, &(k * G), &cs, &tampered, &proof, &ctx()),
                "tampering with d_{i} was not detected"
            );
        }
    }

    #[test]
    fn wrong_scalar_does_not_verify() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let other = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        let proof = generate_proof(&k, &G, &(k * G), &[c], &[k * c], &ctx(), rng).unwrap();
        assert!(!verify_proof(
            &G,
            &(other * G),
            &[c],
            &[k * c],
            &proof,
            &ctx()
        ));
    }

    /// The context string is part of the challenge, so proofs do not cross deployments.
    #[test]
    fn proofs_are_context_separated() {
        use crate::protocol::Mode;
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        let a = Context::default();
        let b = Context::new(Mode::VcoPRF, "other-deployment");
        let proof = generate_proof(&k, &G, &(k * G), &[c], &[k * c], &a, rng).unwrap();
        assert!(verify_proof(&G, &(k * G), &[c], &[k * c], &proof, &a));
        assert!(!verify_proof(&G, &(k * G), &[c], &[k * c], &proof, &b));
    }

    #[test]
    fn mismatched_lists_are_rejected() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        assert_eq!(
            generate_proof(&k, &G, &(k * G), &[c], &[], &ctx(), rng).unwrap_err(),
            ProofError::MismatchedLists { cs: 1, ds: 0 }
        );
        assert_eq!(
            generate_proof(&k, &G, &(k * G), &[], &[], &ctx(), rng).unwrap_err(),
            ProofError::MismatchedLists { cs: 0, ds: 0 }
        );
    }

    /// The DSTs of RFC 9497's own VOPRF ciphersuite, whose context string is
    /// `"OPRFV1-" || I2OSP(modeVOPRF, 1) || "-" || "ristretto255-SHA512"` with modeVOPRF = 0x01.
    ///
    /// This is deliberately NOT our [`Context`]: the draft uses the prefix `"coPRFV1-"` so that
    /// pseudonyms of the two protocols are domain separated on the same group. Reproducing the
    /// RFC's vectors therefore requires the RFC's own context string.
    fn rfc9497_voprf_dsts() -> Dsts {
        let mut ctx = b"OPRFV1-".to_vec();
        ctx.push(0x01);
        ctx.push(b'-');
        ctx.extend_from_slice(b"ristretto255-SHA512");
        let with = |label: &[u8]| {
            let mut d = label.to_vec();
            d.extend_from_slice(&ctx);
            d
        };
        Dsts {
            seed: with(b"Seed-"),
            hash_to_scalar: with(b"HashToScalar-"),
        }
    }

    fn element(hex_str: &str) -> GroupElement {
        GroupElement::from_slice(&hex::decode(hex_str).unwrap()).unwrap()
    }

    fn scalar(hex_str: &str) -> ScalarNonZero {
        ScalarNonZero::from_slice(&hex::decode(hex_str).unwrap()).unwrap()
    }

    /// Cross-check `GenerateProof` against RFC 9497 Appendix A.1.2, Test Vector 1 (batch size 1).
    ///
    /// With `a = G`, `b = pkSm`, `cs = [BlindedElement]`, `ds = [EvaluationElement]` and the
    /// vector's fixed `ProofRandomScalar`, the produced proof bytes must equal the vector's.
    #[test]
    fn rfc9497_appendix_a_1_2_single() {
        let dsts = rfc9497_voprf_dsts();
        let sk = scalar("e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909");
        let pk = element("c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e");
        let blinded = element("863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945");
        let evaluated = element("aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e");
        let r = scalar("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e");
        let expected = "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd06\
                        6d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d";

        // The vector's key material must be self-consistent for the rest to mean anything.
        assert_eq!(sk * G, pk, "pkSm is not skSm * G");
        assert_eq!(
            sk * blinded,
            evaluated,
            "EvaluationElement is not skSm * BlindedElement"
        );

        let proof = generate_proof_with(&sk, &G, &pk, &[blinded], &[evaluated], &dsts, &r);
        assert_eq!(hex::encode(proof.to_bytes()), expected);
        assert!(verify_proof_with(
            &G,
            &pk,
            &[blinded],
            &[evaluated],
            &proof,
            &dsts
        ));
    }

    /// The same cross-check for Test Vector 3 (batch size 2), which exercises
    /// `ComputeComposites` over more than one pair.
    #[test]
    fn rfc9497_appendix_a_1_2_batched() {
        let dsts = rfc9497_voprf_dsts();
        let sk = scalar("e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909");
        let pk = element("c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e");
        let blinded = [
            element("863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"),
            element("90a0145ea9da29254c3a56be4fe185465ebb3bf2a1801f7124bbbadac751e654"),
        ];
        let evaluated = [
            element("aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e"),
            element("cc5ac221950a49ceaa73c8db41b82c20372a4c8d63e5dded2db920b7eee36a2a"),
        ];
        let r = scalar("419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c");
        let expected = "cc203910175d786927eeb44ea847328047892ddf8590e723c37205cb74600b0a\
                        5ab5337c8eb4ceae0494c2cf89529dcf94572ed267473d567aeed6ab873dee08";

        let proof = generate_proof_with(&sk, &G, &pk, &blinded, &evaluated, &dsts, &r);
        assert_eq!(hex::encode(proof.to_bytes()), expected);
        assert!(verify_proof_with(
            &G, &pk, &blinded, &evaluated, &proof, &dsts
        ));

        // And the batched proof must still be sensitive to each element.
        for i in 0..evaluated.len() {
            let mut tampered = evaluated;
            tampered[i] = G;
            assert!(!verify_proof_with(
                &G, &pk, &blinded, &tampered, &proof, &dsts
            ));
        }
    }

    #[test]
    fn proof_serialization_round_trip() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        let proof = generate_proof(&k, &G, &(k * G), &[c], &[k * c], &ctx(), rng).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), PROOF_SIZE);
        assert_eq!(Proof::from_slice(&bytes).unwrap(), proof);
        assert!(Proof::from_slice(&bytes[..63]).is_none());
    }
}
