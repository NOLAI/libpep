use crate::high_level::*;
use crate::proved::*;
use crate::utils::{make_rekey_factor, make_pseudonymisation_factor};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct ProvedEncryptedPseudonym(pub ProvedRSK);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct ProvedEncryptedDataPoint(pub ProvedRekey);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct PseudonymizationContextVerifiers(pub PseudonymizationFactorVerifiers);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct EncryptionContextVerifiers(pub RekeyFactorVerifiers);
impl PseudonymizationContextVerifiers {
    pub fn new<R: RngCore + CryptoRng>(
        context: &PseudonymizationContext,
        secret: &PseudonymizationSecret,
        rng: &mut R,
    ) -> (Self, PseudonymizationFactorVerifiersProof) {
        let factor = make_pseudonymisation_factor(secret, context);
        let (verifiers, proof) = PseudonymizationFactorVerifiers::new(&*factor, rng);
        (PseudonymizationContextVerifiers(verifiers), proof)
    }
}
impl EncryptionContextVerifiers {
    pub fn new<R: RngCore + CryptoRng>(
        context: &EncryptionContext,
        secret: &EncryptionSecret,
        rng: &mut R,
    ) -> (Self, RekeyFactorVerifiersProof) {
        let factor = make_rekey_factor(secret, context);
        let (verifiers, proof) = RekeyFactorVerifiers::new(&*factor, rng);
        (EncryptionContextVerifiers(verifiers), proof)
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct PseudonymizationInfoProof {
    pub reshuffle_proof: Reshuffle2FactorsProof,
    pub rekey_proof: Rekey2FactorsProof,
    pub rsk_proof: RSK2FactorsProof,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct RekeyInfoProof(pub Rekey2FactorsProof);
impl PseudonymizationInfoProof {
    pub fn new<R: RngCore + CryptoRng>(factors: &PseudonymizationInfo, rng: &mut R) -> Self {
        let reshuffle_proof = Reshuffle2FactorsProof::new(&factors.s.from, &factors.s.to, rng);
        let rekey_proof = Rekey2FactorsProof::new(&factors.k.from, &factors.k.to, rng);
        let rsk_proof = RSK2FactorsProof::new(
            &factors.s.from,
            &factors.s.to,
            &factors.k.from,
            &factors.k.to,
            rng,
        );
        PseudonymizationInfoProof {
            reshuffle_proof,
            rekey_proof,
            rsk_proof,
        }
    }
    #[must_use]
    pub fn verify(
        &self,
        pseudo_verifiers_from: &PseudonymizationFactorVerifiers,
        pseudo_verifiers_to: &PseudonymizationFactorVerifiers,
        rekey_verifiers_from: &RekeyFactorVerifiers,
        rekey_verifiers_to: &RekeyFactorVerifiers,
    ) -> bool {
        self.reshuffle_proof
            .verify(pseudo_verifiers_from, pseudo_verifiers_to)
            && self
                .rekey_proof
                .verify(rekey_verifiers_from, rekey_verifiers_to)
            && self
                .rsk_proof
                .verify(&self.reshuffle_proof, &self.rekey_proof)
    }
}
impl RekeyInfoProof {
    pub fn new<R: RngCore + CryptoRng>(factors: &RekeyInfo, rng: &mut R) -> Self {
        let rekey_proof = Rekey2FactorsProof::new(&factors.from, &factors.to, rng);
        RekeyInfoProof(rekey_proof)
    }
    #[must_use]
    pub fn verify(
        &self,
        verifiers_from: &RekeyFactorVerifiers,
        verifiers_to: &RekeyFactorVerifiers,
    ) -> bool {
        self.0.verify(verifiers_from, verifiers_to)
    }
}
impl From<&PseudonymizationInfoProof> for RekeyInfoProof {
    fn from(info: &PseudonymizationInfoProof) -> Self {
        RekeyInfoProof(info.rekey_proof.clone())
    }
}

impl ProvedEncryptedPseudonym {
    pub fn new(value: ProvedRSK) -> Self {
        ProvedEncryptedPseudonym(value)
    }

    pub fn reconstruct(
        &self,
        original: &EncryptedPseudonym,
        proof: &PseudonymizationInfoProof,
    ) -> Option<EncryptedPseudonym> {
        let reconstructed = self.verified_reconstruct2(original, &proof.rsk_proof);
        if reconstructed.is_none() {
            return None;
        }
        Some(EncryptedPseudonym::from(reconstructed?))
    }
}
impl ProvedEncryptedDataPoint {
    pub fn new(value: ProvedRekey) -> Self {
        ProvedEncryptedDataPoint(value)
    }
    pub fn reconstruct(
        &self,
        original: &EncryptedDataPoint,
        proof: &RekeyInfoProof,
    ) -> Option<EncryptedDataPoint> {
        let reconstructed = self.verified_reconstruct2(&original, &proof.0);
        if reconstructed.is_none() {
            return None;
        }
        Some(EncryptedDataPoint::from(reconstructed?))
    }
}

/// Proved pseudonymize an encrypted pseudonym, from one context to another context
pub fn proved_pseudonymize<R: RngCore + CryptoRng>(
    p: &EncryptedPseudonym,
    pseudonymization_info: &PseudonymizationInfo,
    rng: &mut R,
) -> ProvedEncryptedPseudonym {
    ProvedEncryptedPseudonym::new(prove_rsk2(
        &p,
        &pseudonymization_info.s.from,
        &pseudonymization_info.s.to,
        &pseudonymization_info.k.from,
        &pseudonymization_info.k.to,
        rng,
    ))
}

/// Proved rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn proved_rekey<R: RngCore + CryptoRng>(
    p: &EncryptedDataPoint,
    rekey_info: &RekeyInfo,
    rng: &mut R,
) -> ProvedEncryptedDataPoint {
    ProvedEncryptedDataPoint::new(prove_rekey2(&p, &rekey_info.from, &rekey_info.to, rng))
}

#[must_use]
pub fn verify_pseudonymization_info(
    info: &PseudonymizationInfoProof,
    pseudo_verifiers_from: &PseudonymizationFactorVerifiers,
    pseudo_verifiers_to: &PseudonymizationFactorVerifiers,
    rekey_verifiers_from: &RekeyFactorVerifiers,
    rekey_verifiers_to: &RekeyFactorVerifiers,
) -> bool {
    info.reshuffle_proof
        .verify(pseudo_verifiers_from, pseudo_verifiers_to)
        && info
            .rekey_proof
            .verify(rekey_verifiers_from, rekey_verifiers_to)
        && info
            .rsk_proof
            .verify(&info.reshuffle_proof, &info.rekey_proof)
}
#[must_use]
pub fn verify_rekey_info(
    info: &RekeyInfoProof,
    verifiers_from: &RekeyFactorVerifiers,
    verifiers_to: &RekeyFactorVerifiers,
) -> bool {
    info.verify(verifiers_from, verifiers_to)
}

pub fn verify_pseudonymization(
    msg: &ProvedEncryptedPseudonym,
    original: &EncryptedPseudonym,
    proof: &PseudonymizationInfoProof,
) -> Option<EncryptedPseudonym> {
    let reconstructed = msg.verified_reconstruct2(original, &proof.rsk_proof);
    if reconstructed.is_none() {
        return None;
    }
    Some(EncryptedPseudonym::from(reconstructed?))
}

pub fn verified_decrypt_pseudonym(
    x: &ProvedEncryptedPseudonym,
    original: &EncryptedPseudonym,
    sk: &SessionSecretKey,
    proof: &PseudonymizationInfoProof,
) -> Option<Pseudonym> {
    let reconstructed = verify_pseudonymization(x, original, proof);
    if reconstructed.is_none() {
        return None;
    }
    Some(decrypt_pseudonym(&reconstructed?, sk))
}

pub fn verify_rekey(
    msg: &ProvedEncryptedDataPoint,
    original: &EncryptedDataPoint,
    proof: &RekeyInfoProof,
) -> Option<EncryptedDataPoint> {
    let reconstructed = msg.verified_reconstruct2(original, &proof.0);
    if reconstructed.is_none() {
        return None;
    }
    Some(EncryptedDataPoint::from(reconstructed?))
}

pub fn verified_decrypt_data(
    x: &ProvedEncryptedDataPoint,
    original: &EncryptedDataPoint,
    sk: &SessionSecretKey,
    proof: &RekeyInfoProof,
) -> Option<DataPoint> {
    let reconstructed = verify_rekey(x, original, proof);
    if reconstructed.is_none() {
        return None;
    }
    Some(decrypt_data(&reconstructed?, sk))
}
