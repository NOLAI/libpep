use crate::arithmetic::*;
use crate::high_level::*;
use crate::high_level_proved::*;
use crate::proved::{PseudonymizationFactorVerifiers, PseudonymizationFactorVerifiersProof, RekeyFactorVerifiers, RekeyFactorVerifiersProof};
use crate::utils::*;
use crate::verifiers_cache::VerifiersCache;
use derive_more::{Deref, From};
use rand_core::{CryptoRng, OsRng, RngCore};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct BlindingFactor(pub ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct BlindedGlobalSecretKey(pub ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct SessionKeyShare(pub ScalarNonZero);
impl BlindingFactor {
    pub fn new(x: ScalarNonZero) -> Self {
        BlindingFactor(x)
    }
    pub fn random() -> Self {
        BlindingFactor(ScalarNonZero::random(&mut OsRng))
    }
}
pub fn make_blinded_global_secret_key(global_secret_key: &GlobalSecretKey, blinding_factors: &Vec<BlindingFactor>) -> BlindedGlobalSecretKey {
    let y = global_secret_key.clone();
    let x = blinding_factors.iter().fold(*y, |acc, x| acc * x.deref());
    BlindedGlobalSecretKey(x)
}
pub type PEPSystemID = String;

pub struct PEPSystem {
    pub system_id: PEPSystemID,
    pseudonymisation_secret: PseudonymizationSecret,
    rekeying_secret: EncryptionSecret,
    blinding_factor: BlindingFactor,
    pub verifier: PEPVerifier,
}
impl PEPSystem {
    pub fn new(
        system_id: PEPSystemID,
        pseudonymisation_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
        blinding_factor: BlindingFactor,
        pseudo_verifiers_cache: Box<dyn VerifiersCache<Key=PseudonymizationContext, Verifiers=PseudonymizationFactorVerifiers>>,
        session_verifiers_cache: Box<dyn VerifiersCache<Key=EncryptionContext, Verifiers=RekeyFactorVerifiers>>,
    ) -> Self {
        Self {
            system_id,
            pseudonymisation_secret,
            rekeying_secret,
            blinding_factor,
            verifier: PEPVerifier::new(pseudo_verifiers_cache, session_verifiers_cache),
        }
    }
    pub fn session_key_share(&self, context: &EncryptionContext) -> SessionKeyShare {
        let k = make_decryption_factor(&self.rekeying_secret, &context);
        SessionKeyShare(*k * &self.blinding_factor.invert())
    }
    pub fn rekey_info(&self, from_enc: &EncryptionContext, to_enc: &EncryptionContext) -> RekeyInfo {
        RekeyInfo::new(from_enc, to_enc, &self.rekeying_secret)
    }
    pub fn pseudonymization_info(&self, from_pseudo: &PseudonymizationContext, to_pseudo: &PseudonymizationContext, from_enc: &EncryptionContext, to_enc: &EncryptionContext) -> PseudonymizationInfo {
        PseudonymizationInfo::new(from_pseudo, to_pseudo, from_enc, to_enc, &self.pseudonymisation_secret, &self.rekeying_secret)
    }
    pub fn pseudo_context_verifiers<R: RngCore + CryptoRng>(&self, context: &PseudonymizationContext, rng: &mut R) -> (PseudonymizationContextVerifiers, PseudonymizationFactorVerifiersProof) {
        PseudonymizationContextVerifiers::new(context, &self.pseudonymisation_secret, rng)
    }
    pub fn enc_context_verifiers<R: RngCore + CryptoRng>(&self, context: &EncryptionContext, rng: &mut R) -> (EncryptionContextVerifiers, RekeyFactorVerifiersProof) {
        EncryptionContextVerifiers::new(context, &self.rekeying_secret, rng)
    }
    pub fn pseudo_info_proof<R: RngCore + CryptoRng>(&self, info: &PseudonymizationInfo, rng: &mut R) -> PseudonymizationInfoProof {
        PseudonymizationInfoProof::new(info, rng)
    }
    pub fn rekey_info_proof<R: RngCore + CryptoRng>(&self, info: &RekeyInfo, rng: &mut R) -> RekeyInfoProof {
        RekeyInfoProof::new(info, rng)
    }
    pub fn rekey(&self, p: &EncryptedDataPoint, rekey_info: &RekeyInfo) -> EncryptedDataPoint {
        rekey(p, rekey_info)
    }
    pub fn pseudonymize(&self, p: &EncryptedPseudonym, pseudonymization_info: &PseudonymizationInfo) -> EncryptedPseudonym {
        pseudonymize(p, pseudonymization_info)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(&self, encrypted: EncryptedPseudonym, rng: &mut R) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(&encrypted, rng)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_data_point<R: RngCore + CryptoRng>(&self, encrypted: EncryptedDataPoint, rng: &mut R) -> EncryptedDataPoint {
        rerandomize_encrypted(&encrypted, rng)
    }
    pub fn proved_pseudonymize<R: RngCore + CryptoRng>(&self, p: &EncryptedPseudonym, pseudonymization_info: &PseudonymizationInfo, rng: &mut R) -> ProvedEncryptedPseudonym {
        proved_pseudonymize(p, pseudonymization_info, rng)
    }
    pub fn proved_rekey<R: RngCore + CryptoRng>(&self, p: &EncryptedDataPoint, rekey_info: &RekeyInfo, rng: &mut R) -> ProvedEncryptedDataPoint {
        proved_rekey(p, rekey_info, rng)
    }
    pub fn proved_distributed_pseudonymize<R: RngCore + CryptoRng>(&self, messages: &Vec<(PEPSystemID, ProvedEncryptedPseudonym)>, pseudo_proofs: &Vec<(PEPSystemID, PseudonymizationInfoProof)>, original: &EncryptedPseudonym, pseudonymization_info: &PseudonymizationInfo, rng: &mut R) -> Option<ProvedEncryptedPseudonym> {
        if messages.len() == 0 {
            return Some(self.proved_pseudonymize(original, pseudonymization_info, rng));
        }
        let result = self.verifier.verify_pseudonym_transcryption(messages, pseudo_proofs, original);
        result.map(|x| proved_pseudonymize(&x, pseudonymization_info, rng))
    }
    pub fn proved_distributed_rekey<R: RngCore + CryptoRng>(&self, messages: &Vec<(PEPSystemID, ProvedEncryptedDataPoint)>, rekey_proofs: &Vec<(PEPSystemID, RekeyInfoProof)>, original: &EncryptedDataPoint, rekey_info: &RekeyInfo, rng: &mut R) -> Option<ProvedEncryptedDataPoint> {
        if messages.len() == 0 {
            return Some(self.proved_rekey(original, rekey_info, rng));
        }
        let result = self.verifier.verify_data_transcryption(messages, rekey_proofs, original);
        result.map(|x| proved_rekey(&x, rekey_info, rng))
    }
}
pub struct PEPVerifier {
    pseudo_verifiers_cache: Box<dyn VerifiersCache<Key=PseudonymizationContext, Verifiers=PseudonymizationFactorVerifiers>>,
    session_verifiers_cache: Box<dyn VerifiersCache<Key=EncryptionContext, Verifiers=RekeyFactorVerifiers>>,
}
impl PEPVerifier {
    pub fn new(pseudo_verifiers_cache: Box<dyn VerifiersCache<Key=PseudonymizationContext, Verifiers=PseudonymizationFactorVerifiers>>, session_verifiers_cache: Box<dyn VerifiersCache<Key=EncryptionContext, Verifiers=RekeyFactorVerifiers>>) -> Self {
        Self {
            pseudo_verifiers_cache,
            session_verifiers_cache,
        }
    }
    pub fn has_pseudo_verifiers(&self, system_id: &PEPSystemID, context: &PseudonymizationContext) -> bool {
        self.pseudo_verifiers_cache.has(system_id, context)
    }
    pub fn has_rekey_verifiers(&self, system_id: &PEPSystemID, context: &EncryptionContext) -> bool {
        self.session_verifiers_cache.has(system_id, context)
    }
    pub fn store_pseudo_verifiers(&mut self, system_id: PEPSystemID, context: PseudonymizationContext, verifiers: &PseudonymizationContextVerifiers, proof: &PseudonymizationFactorVerifiersProof) {
        if proof.verify(&verifiers) {
            self.pseudo_verifiers_cache.store(system_id, context, verifiers.0);
        } else {
            panic!("Invalid proof");
        }
    }
    pub fn store_rekey_verifiers(&mut self, system_id: PEPSystemID, context: EncryptionContext, verifiers: &EncryptionContextVerifiers, proof: &RekeyFactorVerifiersProof) {
        if proof.verify(&verifiers) {
            self.session_verifiers_cache.store(system_id, context, verifiers.0);
        } else {
            panic!("Invalid proof");
        }
    }
    #[must_use]
    pub fn verify_pseudonymization_info_proof(&self, proof: &PseudonymizationInfoProof, system_id: &PEPSystemID, pseudo_context_from: &PseudonymizationContext, pseudo_context_to: &PseudonymizationContext, enc_context_from: &EncryptionContext, enc_context_to: &EncryptionContext) -> bool {
        let pseudo_verifiers_from = self.pseudo_verifiers_cache.retrieve(system_id, pseudo_context_from).unwrap();
        let pseudo_verifiers_to = self.pseudo_verifiers_cache.retrieve(system_id, pseudo_context_to).unwrap();
        let rekey_verifiers_from = self.session_verifiers_cache.retrieve(system_id, enc_context_from).unwrap();
        let rekey_verifiers_to = self.session_verifiers_cache.retrieve(system_id, enc_context_to).unwrap();
        proof.verify(&pseudo_verifiers_from, &pseudo_verifiers_to, &rekey_verifiers_from, &rekey_verifiers_to)
    }
    #[must_use]
    pub fn verify_rekey_info_proof(&self, proof: &RekeyInfoProof, system_id: &PEPSystemID, enc_context_from: &EncryptionContext, enc_context_to: &EncryptionContext) -> bool {
        let rekey_verifiers_from = self.session_verifiers_cache.retrieve(system_id, enc_context_from).unwrap();
        let rekey_verifiers_to = self.session_verifiers_cache.retrieve(system_id, enc_context_to).unwrap();
        proof.verify(&rekey_verifiers_from, &rekey_verifiers_to)
    }
    pub fn verify_pseudonym_transcryption(&self, messages: &Vec<(PEPSystemID, ProvedEncryptedPseudonym)>, pseudo_proofs: &Vec<(PEPSystemID, PseudonymizationInfoProof)>, original: &EncryptedPseudonym) -> Option<EncryptedPseudonym> {
        assert_eq!(messages.len(), pseudo_proofs.len());

        let mut previous = original.clone();

        for i in 0..messages.len() {
            let (_system_id1, message) = &messages[i];
            let (_system_id2, pseudo_info_proof) = &pseudo_proofs[i];
            assert_eq!(_system_id1, _system_id2);

            let reconstructed = verify_pseudonymization(message, &previous, pseudo_info_proof);
            if reconstructed.is_none() {
                return None;
            }
            previous = reconstructed.unwrap();
        }
        Some(previous)
    }
    pub fn verify_data_transcryption(&self, messages: &Vec<(PEPSystemID, ProvedEncryptedDataPoint)>, rekey_proofs: &Vec<(PEPSystemID, RekeyInfoProof)>, original: &EncryptedDataPoint) -> Option<EncryptedDataPoint> {
        assert_eq!(messages.len(), rekey_proofs.len());
        let mut previous = original.clone();

        for i in 0..messages.len() {
            let (_system_id1, message) = &messages[i];
            let (_system_id2, rekey_info_proof) = &rekey_proofs[i];
            assert_eq!(_system_id1, _system_id2);

            let reconstructed = verify_rekey(message, &previous, rekey_info_proof);
            if reconstructed.is_none() {
                return None;
            }
            previous = reconstructed.unwrap();
        }
        Some(previous)
    }
}

pub struct PEPClient {
    session_secret_key: SessionSecretKey,
    session_public_key: SessionPublicKey,
    pub verifier: PEPVerifier,
}
impl PEPClient {
    pub fn new(blinded_global_private_key: BlindedGlobalSecretKey,
               session_key_shares: Vec<SessionKeyShare>,
               pseudo_verifiers_cache: Box<dyn VerifiersCache<Key=PseudonymizationContext, Verifiers=PseudonymizationFactorVerifiers>>,
               session_verifiers_cache: Box<dyn VerifiersCache<Key=EncryptionContext, Verifiers=RekeyFactorVerifiers>>,
    ) -> Self {
        let secret_key = SessionSecretKey(session_key_shares.iter().fold(*blinded_global_private_key, |acc, x| acc * x.deref()));
        let public_key = SessionPublicKey(secret_key.deref() * &G);
        Self {
            session_secret_key: secret_key,
            session_public_key: public_key,
            verifier: PEPVerifier::new(pseudo_verifiers_cache, session_verifiers_cache),
        }
    }
    pub fn decrypt_pseudonym(&self, p: &EncryptedPseudonym) -> Pseudonym {
        decrypt_pseudonym(&p, &self.session_secret_key)
    }
    pub fn decrypt_data(&self, data: &EncryptedDataPoint) -> DataPoint {
        decrypt_data(&data, &self.session_secret_key)
    }
    pub fn encrypt_data<R: RngCore + CryptoRng>(&self, data: &DataPoint, rng: &mut R) -> EncryptedDataPoint {
        encrypt_data(data, &(self.session_public_key), rng)
    }
    pub fn encrypt_pseudonym<R: RngCore + CryptoRng>(&self, p: &Pseudonym, rng: &mut R) -> EncryptedPseudonym {
        encrypt_pseudonym(p, &(self.session_public_key), rng)
    }
    pub fn verified_decrypt_pseudonym(&self, messages: &Vec<(PEPSystemID, ProvedEncryptedPseudonym)>, pseudo_proofs: &Vec<(PEPSystemID, PseudonymizationInfoProof)>, original: &EncryptedPseudonym) -> Option<(Pseudonym, EncryptedPseudonym)> {
        let result = self.verifier.verify_pseudonym_transcryption(messages, pseudo_proofs, original);
        result.map(|x| (decrypt_pseudonym(&x, &self.session_secret_key), x))
    }
    pub fn verified_decrypt_data(&self, messages: &Vec<(PEPSystemID, ProvedEncryptedDataPoint)>, rekey_proofs: &Vec<(PEPSystemID, RekeyInfoProof)>, original: &EncryptedDataPoint) -> Option<(DataPoint, EncryptedDataPoint)> {
        let result = self.verifier.verify_data_transcryption(messages, rekey_proofs, original);
        result.map(|x| (decrypt_data(&x, &self.session_secret_key), x))
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(&self, encrypted: EncryptedPseudonym, rng: &mut R) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(&encrypted, rng)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_data_point<R: RngCore + CryptoRng>(&self, encrypted: EncryptedDataPoint, rng: &mut R) -> EncryptedDataPoint {
        rerandomize_encrypted(&encrypted, rng)
    }
}
