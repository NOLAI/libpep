//! Batched verifiable rekey and rekey-2.

use super::commitments::{FactorCommitment, RekeyFactorCommitment};
use super::rekey::VerifiableRekey;
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
use crate::elgamal::zkps::generic::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A batch of [`VerifiableRekey`] proofs sharing one rekey factor.
///
/// No header is needed: the rekey-factor commitment `K = k·G` is supplied
/// by the verifier as part of the published per-transition commitments.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableRekeyBatch<G: Group> {
    pub(crate) inners: Vec<VerifiableRekey<G>>,
}

impl<G: Group> VerifiableRekeyBatch<G> {
    /// The per-message inner proofs.
    pub fn inners(&self) -> &[VerifiableRekey<G>] {
        &self.inners
    }
}

impl<G: Group> VerifiableRekeyBatch<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(ciphertexts: &[ElGamal<G>], k: &G::Scalar, rng: &mut R) -> Self {
        Self {
            inners: ciphertexts
                .iter()
                .map(|v| VerifiableRekey::new(v, k, rng))
                .collect(),
        }
    }

    /// Apply each entry's rekey to the corresponding ciphertext,
    /// **without verifying** any proofs. Internal prover-side use only.
    pub(crate) fn result(&self, originals: &[ElGamal<G>]) -> Vec<ElGamal<G>> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.result(o))
            .collect()
    }

    /// Verify the whole batch against `originals`.
    #[must_use]
    pub fn verify(&self, originals: &[ElGamal<G>], commitment: &RekeyFactorCommitment<G>) -> bool {
        originals.len() == self.inners.len()
            && self
                .inners
                .iter()
                .zip(originals.iter())
                .all(|(inner, o)| inner.verify(o, commitment))
    }

    reconstruct! {
        verified(originals: &[ElGamal<G>], commitment: &RekeyFactorCommitment<G>) -> Vec<ElGamal<G>> = verify(originals, commitment);
        unverified(originals: &[ElGamal<G>]) = result(originals);
    }
}

/// A batch of [`super::VerifiableRekey2`] proofs sharing one `(k_from, k_to)` factor pair.
///
/// Mirrors [`super::VerifiableRekey2`]'s layout (`gk`, `p_gk_to`, `inner: VerifiableRekey`)
/// at batch level — the inner scalar `k = k_from⁻¹·k_to` is hoisted into the
/// single `gk`/`p_gk_to` pair, and the per-message inners are still ordinary
/// [`VerifiableRekey`] values that verify against [`Self::combined_commitment`].
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableRekey2Batch<G: Group> {
    /// `K = (k_from⁻¹·k_to)·G`.
    pub(crate) gk: G::Element,
    /// `ZKP{K_to = k_from * K}`.
    pub(crate) p_gk_to: Proof<G>,
    /// One [`VerifiableRekey`] per ciphertext, under the combined scalar.
    pub(crate) inners: Vec<VerifiableRekey<G>>,
}

impl<G: Group> VerifiableRekey2Batch<G> {
    /// The combined commitment `K = (k_from⁻¹·k_to)·G`.
    pub fn gk(&self) -> &G::Element {
        &self.gk
    }
    /// The per-factor sub-proof `ZKP{K_to = k_from * K}`.
    pub fn p_gk_to(&self) -> &Proof<G> {
        &self.p_gk_to
    }
    /// The per-message inner proofs.
    pub fn inners(&self) -> &[VerifiableRekey<G>] {
        &self.inners
    }
}

impl<G: Group> VerifiableRekey2Batch<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal<G>],
        k_from: &G::Scalar,
        k_to: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let k = G::scalar_inverse(k_from) * *k_to;
        let gk = k * G::generator();
        let (_gk_from, p_gk_to) = create_proof::<G, R>(k_from, &gk, rng);
        let inners = ciphertexts
            .iter()
            .map(|v| VerifiableRekey::new(v, &k, rng))
            .collect();
        Self {
            gk,
            p_gk_to,
            inners,
        }
    }

    /// Apply each entry's rekey to the corresponding ciphertext,
    /// **without verifying** any proofs. Internal prover-side use only.
    pub(crate) fn result(&self, originals: &[ElGamal<G>]) -> Vec<ElGamal<G>> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.result(o))
            .collect()
    }

    /// The combined commitment `K = (k_from⁻¹·k_to)·G`.
    pub fn combined_commitment(&self) -> RekeyFactorCommitment<G> {
        RekeyFactorCommitment(FactorCommitment(self.gk))
    }

    /// Verify the hoisted `(gk, p_gk_to)` block once against the published
    /// `K_from`, `K_to` commitments. After this passes, every inner can be
    /// verified against [`Self::combined_commitment`].
    #[must_use]
    pub fn verify_factor(
        &self,
        from_commitments: &RekeyFactorCommitment<G>,
        to_commitments: &RekeyFactorCommitment<G>,
    ) -> bool {
        let gk_from = from_commitments.point();
        let gk_to = to_commitments.point();
        *self.p_gk_to == gk_to && verify_proof::<G>(&gk_from, &self.gk, &self.p_gk_to)
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        originals: &[ElGamal<G>],
        from_commitments: &RekeyFactorCommitment<G>,
        to_commitments: &RekeyFactorCommitment<G>,
    ) -> bool {
        if !self.verify_factor(from_commitments, to_commitments) {
            return false;
        }
        if originals.len() != self.inners.len() {
            return false;
        }
        let commitment = self.combined_commitment();
        self.inners
            .iter()
            .zip(originals.iter())
            .all(|(inner, o)| inner.verify(o, &commitment))
    }

    reconstruct! {
        verified(originals: &[ElGamal<G>], from_commitments: &RekeyFactorCommitment<G>, to_commitments: &RekeyFactorCommitment<G>) -> Vec<ElGamal<G>> = verify(originals, from_commitments, to_commitments);
        unverified(originals: &[ElGamal<G>]) = result(originals);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::elgamal::encrypt;
    use crate::elgamal::primitives::{rekey, rekey2};
    use crate::elgamal::verifiable::{
        RekeyFactorCommitment, VerifiableRekey2Batch, VerifiableRekeyBatch,
    };
    use crate::elgamal::ElGamal;

    fn setup_ct() -> ElGamal {
        let mut rng = rand::rng();
        let sk = ScalarNonZero::random(&mut rng);
        let pk = sk * G;
        let m = GroupElement::random(&mut rng);
        encrypt(&m, &pk, &mut rng)
    }

    fn setup_pk_cts(n: usize) -> Vec<ElGamal> {
        (0..n).map(|_| setup_ct()).collect()
    }

    #[test]
    fn rekey_batch_honest_verifies() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(5);
        let k = ScalarNonZero::random(&mut rng);
        let batch = VerifiableRekeyBatch::new(&cts, &k, &mut rng);
        let expected_news: Vec<_> = cts.iter().map(|c| rekey(c, &k)).collect();
        let com = RekeyFactorCommitment::new(&k);
        let news = batch.verified_reconstruct(&cts, &com).expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify(&cts, &com));
    }

    #[test]
    fn rekey_batch_tampered_proof_fails() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(3);
        let k = ScalarNonZero::random(&mut rng);
        let mut batch = VerifiableRekeyBatch::new(&cts, &k, &mut rng);
        // Tamper an inner proof's response.
        batch.inners[1].p_gb.c1 = batch.inners[1].p_gb.c1 + GroupElement::random(&mut rng);
        let com = RekeyFactorCommitment::new(&k);
        assert!(!batch.verify(&cts, &com));
        assert!(batch.verified_reconstruct(&cts, &com).is_none());
    }

    #[test]
    fn rekey2_batch_honest_verifies() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(5);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let batch = VerifiableRekey2Batch::new(&cts, &k_from, &k_to, &mut rng);
        let expected_news: Vec<_> = cts.iter().map(|c| rekey2(c, &k_from, &k_to)).collect();
        let from = RekeyFactorCommitment::new(&k_from);
        let to = RekeyFactorCommitment::new(&k_to);
        let news = batch
            .verified_reconstruct(&cts, &from, &to)
            .expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify(&cts, &from, &to));
    }

    #[test]
    fn rekey2_batch_factor_tamper_fails() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(2);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let mut batch = VerifiableRekey2Batch::new(&cts, &k_from, &k_to, &mut rng);
        let from = RekeyFactorCommitment::new(&k_from);
        let to = RekeyFactorCommitment::new(&k_to);
        batch.gk = batch.gk + GroupElement::random(&mut rng);
        assert!(!batch.verify(&cts, &from, &to));
    }
}
