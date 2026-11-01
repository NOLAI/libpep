//! Discrete-logarithm-equivalence (DLEQ) proofs in the two-scalar `(c, s)` encoding.
//!
//! A DLEQ proof shows that the same secret scalar `k` relates two pairs of group elements,
//! `B = k * A` and `D_i = k * C_i`, without revealing `k`. The module follows the proof of the
//! verifiable OPRF in [RFC 9497], Section 2.2: `GenerateProof` and `VerifyProof`, with the
//! `ComputeComposites` batching that lets one proof cover many `(C_i, D_i)` pairs transformed
//! with the same scalar. Only the domain separation tags differ, as they come from the
//! [`Ciphersuite`].
//!
//! [RFC 9497]: https://www.rfc-editor.org/rfc/rfc9497
//!
//! # Relation to [`super::zkps`]
//!
//! [`super::zkps::Proof`] is the four-element encoding `(N, C1, C2, s)` of the published paper.
//! The encoding here differs: a proof is the two scalars `(c, s)` and the verifier recomputes the
//! commitments. Proofs in the two encodings are not interchangeable.
//!
//! # Domain separation
//!
//! The transcripts end in the bare labels `"Composite"` and `"Challenge"`, and the context
//! string enters through the DSTs of `HashToScalar` (`"HashToScalar-" || contextString`) and of
//! the seed (`"Seed-" || contextString`). The context string comes from [`Ciphersuite::ID`], so
//! proofs of two ciphersuites never verify against one another.
//!
//! The tests reproduce the proofs of the RFC 9497 ristretto255-SHA512 VOPRF test vectors
//! (Appendix A.1.2), for a single pair and for a batch of two.
//!
//! # Example
//!
//! ```
//! # use libpep::elgamal::arithmetic::group_elements::{GroupElement, G};
//! # use libpep::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
//! # use libpep::elgamal::arithmetic::Ristretto255Sha512;
//! # use libpep::elgamal::dleq::{generate_proof, verify_proof};
//! let mut rng = rand::rng();
//!
//! let k = ScalarNonZero::random(&mut rng);
//! let a = G;
//! let b = k * a;
//! let cs = [GroupElement::random(&mut rng), GroupElement::random(&mut rng)];
//! let ds = [k * cs[0], k * cs[1]];
//!
//! let proof = generate_proof::<Ristretto255Sha512, _>(&k, &a, &b, &cs, &ds, &mut rng).unwrap();
//! assert!(verify_proof::<Ristretto255Sha512>(&a, &b, &cs, &ds, &proof));
//! ```

use crate::elgamal::arithmetic::ciphersuite::{
    Ciphersuite, CiphersuiteId, ElementOf, ScalarCanBeZeroOf, ScalarOf,
};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::arithmetic::Ristretto255;
use rand_core::{CryptoRng, Rng};
use sha2::Digest;

/// A DLEQ proof in the two-scalar encoding: the challenge `c` and the response `s`.
///
/// Serializes to [`LENGTH`](Self::LENGTH) bytes as `SerializeScalar(c) || SerializeScalar(s)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Proof<G: Group = Ristretto255> {
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
/// The context string is used in two distinct ways here, and the difference matters for
/// interoperability: `seedDST` is `"Seed-" || contextString` and appears *inside* the seed
/// transcript, whereas the trailing `"Composite"` and `"Challenge"` labels are bare literals,
/// with the context string entering only through `HashToScalar`'s own DST
/// (`"HashToScalar-" || contextString`).
///
/// Normally built from the [`CiphersuiteId`], whose context string is prefixed `"nPEPV1-"`.
/// The RFC 9497 test vectors use `"OPRFV1-"`, so the test module builds these directly.
#[derive(Clone)]
pub(crate) struct Dsts {
    /// `"Seed-" || contextString`, hashed inside the seed transcript.
    pub(crate) seed: Vec<u8>,
    /// `"HashToScalar-" || contextString`, the DST of every `HashToScalar` call.
    pub(crate) hash_to_scalar: Vec<u8>,
}

impl Dsts {
    pub(crate) fn from_ciphersuite(ciphersuite: &CiphersuiteId) -> Self {
        Self {
            seed: ciphersuite.dst(b"Seed-"),
            hash_to_scalar: ciphersuite.dst(b"HashToScalar-"),
        }
    }
}

/// `HashToScalar` in the full scalar field: zero is zero.
fn hash_to_scalar<C: Ciphersuite>(msg: &[u8], dst: &[u8]) -> ScalarCanBeZeroOf<C> {
    C::hash_to_scalar(msg, dst).map_or_else(Default::default, Into::into)
}

/// `I2OSP(len(bytes), 2) || bytes`, the length-prefixed encoding used in transcripts.
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    debug_assert!(bytes.len() <= u16::MAX as usize);
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The seed transcript of `ComputeComposites`:
/// `I2OSP(len(Bm),2) || Bm || I2OSP(len("Seed-"||ctx),2) || "Seed-"||ctx`.
fn compute_seed<C: Ciphersuite>(b: &ElementOf<C>, dsts: &Dsts) -> Vec<u8> {
    let mut transcript = Vec::new();
    push_len_prefixed(&mut transcript, C::Group::serialize_element(b).as_ref());
    push_len_prefixed(&mut transcript, &dsts.seed);
    // The ciphersuite's plain hash is used here, not expand_message_xmd.
    C::Hash::digest(&transcript).to_vec()
}

/// `ComputeComposites`.
///
/// Folds the `(C_i, D_i)` pairs into a single pair `(M, Z)` with per-index weights derived from
/// the seed, so that one proof covers the whole list. When the prover's scalar `k` is known the
/// fast path computes `Z = k * M` directly; otherwise `Z` is accumulated from the `ds`.
fn compute_composites<C: Ciphersuite>(
    k: Option<&ScalarOf<C>>,
    b: &ElementOf<C>,
    cs: &[ElementOf<C>],
    ds: &[ElementOf<C>],
    dsts: &Dsts,
) -> (ElementOf<C>, ElementOf<C>) {
    let seed = compute_seed::<C>(b, dsts);

    let mut m = C::Group::identity();
    let mut z = C::Group::identity();

    for (i, (c_i, d_i)) in cs.iter().zip(ds.iter()).enumerate() {
        let mut transcript = Vec::new();
        push_len_prefixed(&mut transcript, &seed);
        transcript.extend_from_slice(&(i as u16).to_be_bytes());
        push_len_prefixed(&mut transcript, C::Group::serialize_element(c_i).as_ref());
        push_len_prefixed(&mut transcript, C::Group::serialize_element(d_i).as_ref());
        transcript.extend_from_slice(b"Composite");

        let d_i_scalar = hash_to_scalar::<C>(&transcript, &dsts.hash_to_scalar);
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

/// The challenge transcript:
/// the length-prefixed elements `B, M, Z, t2, t3` followed by the bare label `"Challenge"`.
fn challenge<C: Ciphersuite>(
    b: &ElementOf<C>,
    m: &ElementOf<C>,
    z: &ElementOf<C>,
    t2: &ElementOf<C>,
    t3: &ElementOf<C>,
    dsts: &Dsts,
) -> ScalarCanBeZeroOf<C> {
    let mut transcript = Vec::new();
    for element in [b, m, z, t2, t3] {
        push_len_prefixed(
            &mut transcript,
            C::Group::serialize_element(element).as_ref(),
        );
    }
    transcript.extend_from_slice(b"Challenge");
    hash_to_scalar::<C>(&transcript, &dsts.hash_to_scalar)
}

/// `GenerateProof`, domain separated by the ciphersuite's
/// [`ID`](Ciphersuite::ID).
///
/// Proves that `b = k * a` and `ds[i] = k * cs[i]` for every `i`, without revealing `k`.
///
/// # Errors
///
/// Returns [`ProofError::MismatchedLists`] if `cs` and `ds` differ in length or are empty.
pub fn generate_proof<C: Ciphersuite, R: Rng + CryptoRng>(
    k: &ScalarOf<C>,
    a: &ElementOf<C>,
    b: &ElementOf<C>,
    cs: &[ElementOf<C>],
    ds: &[ElementOf<C>],
    rng: &mut R,
) -> Result<Proof<C::Group>, ProofError> {
    if cs.is_empty() || cs.len() != ds.len() {
        return Err(ProofError::MismatchedLists {
            cs: cs.len(),
            ds: ds.len(),
        });
    }

    let dsts = Dsts::from_ciphersuite(&C::ID);
    Ok(generate_proof_with::<C>(
        k,
        a,
        b,
        cs,
        ds,
        &dsts,
        &C::Group::random_scalar(rng),
    ))
}

/// The deterministic core of [`generate_proof`], with the proof's random scalar supplied.
///
/// Separated so that published test vectors, which fix `ProofRandomScalar`, can be
/// reproduced exactly. Callers outside the tests must use [`generate_proof`], which samples
/// the scalar freshly: reusing one across proofs leaks the secret.
pub(crate) fn generate_proof_with<C: Ciphersuite>(
    k: &ScalarOf<C>,
    a: &ElementOf<C>,
    b: &ElementOf<C>,
    cs: &[ElementOf<C>],
    ds: &[ElementOf<C>],
    dsts: &Dsts,
    r: &ScalarOf<C>,
) -> Proof<C::Group> {
    let (m, z) = compute_composites::<C>(Some(k), b, cs, ds, dsts);

    let t2 = *r * *a;
    let t3 = *r * m;

    let c = challenge::<C>(b, &m, &z, &t2, &t3, dsts);
    // s = r - c * k, in the full scalar field (c and s may be zero).
    let s = ScalarCanBeZeroOf::<C>::from(*r) - c * ScalarCanBeZeroOf::<C>::from(*k);

    Proof { c, s }
}

/// `VerifyProof`, domain separated by the ciphersuite's
/// [`ID`](Ciphersuite::ID).
///
/// Checks that the same scalar relates `a` to `b` and every `cs[i]` to `ds[i]`. Returns `false`
/// on any mismatch, and also when the lists are empty or of different lengths.
#[must_use]
pub fn verify_proof<C: Ciphersuite>(
    a: &ElementOf<C>,
    b: &ElementOf<C>,
    cs: &[ElementOf<C>],
    ds: &[ElementOf<C>],
    proof: &Proof<C::Group>,
) -> bool {
    verify_proof_with::<C>(a, b, cs, ds, proof, &Dsts::from_ciphersuite(&C::ID))
}

/// The DST-parameterised core of [`verify_proof`].
pub(crate) fn verify_proof_with<C: Ciphersuite>(
    a: &ElementOf<C>,
    b: &ElementOf<C>,
    cs: &[ElementOf<C>],
    ds: &[ElementOf<C>],
    proof: &Proof<C::Group>,
    dsts: &Dsts,
) -> bool {
    if cs.is_empty() || cs.len() != ds.len() {
        return false;
    }

    let (m, z) = compute_composites::<C>(None, b, cs, ds, dsts);

    // t2 = s * A + c * B, t3 = s * M + c * Z
    let t2 = proof.s * *a + proof.c * *b;
    let t3 = proof.s * m + proof.c * z;

    let expected = challenge::<C>(b, &m, &z, &t2, &t3, dsts);
    expected == proof.c
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::elgamal::arithmetic::Ristretto255;
    use crate::elgamal::arithmetic::Ristretto255Sha512;

    type C = Ristretto255Sha512;

    type Proof = super::Proof<Ristretto255>;
    const PROOF_SIZE: usize = Proof::LENGTH;

    fn generate_proof<R: Rng + CryptoRng>(
        k: &ScalarNonZero,
        a: &GroupElement,
        b: &GroupElement,
        cs: &[GroupElement],
        ds: &[GroupElement],
        rng: &mut R,
    ) -> Result<Proof, ProofError> {
        super::generate_proof::<C, R>(k, a, b, cs, ds, rng)
    }

    fn verify_proof(
        a: &GroupElement,
        b: &GroupElement,
        cs: &[GroupElement],
        ds: &[GroupElement],
        proof: &Proof,
    ) -> bool {
        super::verify_proof::<C>(a, b, cs, ds, proof)
    }

    #[test]
    fn single_pair_round_trip() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        let proof = generate_proof(&k, &G, &(k * G), &[c], &[k * c], rng).unwrap();
        assert!(verify_proof(&G, &(k * G), &[c], &[k * c], &proof));
    }

    #[test]
    fn batched_round_trip() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let cs: Vec<_> = (0..3).map(|_| GroupElement::random(rng)).collect();
        let ds: Vec<_> = cs.iter().map(|c| k * *c).collect();
        let proof = generate_proof(&k, &G, &(k * G), &cs, &ds, rng).unwrap();
        assert!(verify_proof(&G, &(k * G), &cs, &ds, &proof));
    }

    /// A batched proof must not verify if any single `d_i` is replaced.
    #[test]
    fn batched_proof_rejects_a_single_tampered_element() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let cs: Vec<_> = (0..3).map(|_| GroupElement::random(rng)).collect();
        let ds: Vec<_> = cs.iter().map(|c| k * *c).collect();
        let proof = generate_proof(&k, &G, &(k * G), &cs, &ds, rng).unwrap();

        for i in 0..ds.len() {
            let mut tampered = ds.clone();
            tampered[i] = GroupElement::random(rng);
            assert!(
                !verify_proof(&G, &(k * G), &cs, &tampered, &proof),
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
        let proof = generate_proof(&k, &G, &(k * G), &[c], &[k * c], rng).unwrap();
        assert!(!verify_proof(&G, &(other * G), &[c], &[k * c], &proof));
    }

    /// The context string is part of the challenge, so proofs do not cross ciphersuites.
    #[test]
    fn proofs_are_ciphersuite_separated() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        // A different ciphersuite identifier gives a different context string, so the challenge
        // differs and a proof made under one does not verify under the other.
        let ours = Dsts::from_ciphersuite(&C::ID);
        let other = Dsts::from_ciphersuite(&crate::ciphersuite!("other-suite"));
        let r = ScalarNonZero::random(rng);
        let proof = generate_proof_with::<C>(&k, &G, &(k * G), &[c], &[k * c], &ours, &r);
        assert!(verify_proof(&G, &(k * G), &[c], &[k * c], &proof));
        assert!(!verify_proof_with::<C>(
            &G,
            &(k * G),
            &[c],
            &[k * c],
            &proof,
            &other
        ));
    }

    #[test]
    fn mismatched_lists_are_rejected() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        assert_eq!(
            generate_proof(&k, &G, &(k * G), &[c], &[], rng).unwrap_err(),
            ProofError::MismatchedLists { cs: 1, ds: 0 }
        );
        assert_eq!(
            generate_proof(&k, &G, &(k * G), &[], &[], rng).unwrap_err(),
            ProofError::MismatchedLists { cs: 0, ds: 0 }
        );
    }

    /// The DSTs of the RFC 9497 test vectors, whose context string is
    /// `"OPRFV1-" || I2OSP(modeVOPRF, 1) || "-" || "ristretto255-SHA512"` with modeVOPRF = 0x01.
    fn voprf_dsts() -> Dsts {
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

    /// Cross-check `GenerateProof` against RFC 9497, Appendix A.1.2, Test Vector 1 (batch size 1).
    ///
    /// With `a = G`, `b = pkSm`, `cs = [BlindedElement]`, `ds = [EvaluationElement]` and the
    /// vector's fixed `ProofRandomScalar`, the produced proof bytes must equal the vector's.
    #[test]
    fn voprf_appendix_a_1_2_single() {
        let dsts = voprf_dsts();
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

        let proof = generate_proof_with::<C>(&sk, &G, &pk, &[blinded], &[evaluated], &dsts, &r);
        assert_eq!(hex::encode(proof.to_bytes()), expected);
        assert!(verify_proof_with::<C>(
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
    fn voprf_appendix_a_1_2_batched() {
        let dsts = voprf_dsts();
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

        let proof = generate_proof_with::<C>(&sk, &G, &pk, &blinded, &evaluated, &dsts, &r);
        assert_eq!(hex::encode(proof.to_bytes()), expected);
        assert!(verify_proof_with::<C>(
            &G, &pk, &blinded, &evaluated, &proof, &dsts
        ));

        // And the batched proof must still be sensitive to each element.
        for i in 0..evaluated.len() {
            let mut tampered = evaluated;
            tampered[i] = G;
            assert!(!verify_proof_with::<C>(
                &G, &pk, &blinded, &tampered, &proof, &dsts
            ));
        }
    }

    #[test]
    fn proof_serialization_round_trip() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        let proof = generate_proof(&k, &G, &(k * G), &[c], &[k * c], rng).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), PROOF_SIZE);
        assert_eq!(Proof::from_slice(&bytes).unwrap(), proof);
        assert!(Proof::from_slice(&bytes[..63]).is_none());
    }
}
