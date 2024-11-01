use crate::arithmetic::{GroupElement, G};
use crate::distributed::{PEPClient, PEPSystem};
use crate::high_level::*;
use crate::high_level_proved::*;
use crate::proved::{
    PseudonymizationFactorVerifiers, PseudonymizationFactorVerifiersProof, RekeyFactorVerifiers,
    RekeyFactorVerifiersProof,
};
use crate::verifiers_cache::VerifiersCache;
use derive_more::Deref;
use rand_core::{CryptoRng, RngCore};

pub type PEPSystemID = String;

pub struct PEPVerifier {
    pseudo_verifiers_cache: Box<
        dyn VerifiersCache<
            Key = PseudonymizationContext,
            Verifiers = PseudonymizationFactorVerifiers,
        >,
    >,
    session_verifiers_cache:
        Box<dyn VerifiersCache<Key = EncryptionContext, Verifiers = RekeyFactorVerifiers>>,
}
impl PEPVerifier {
    pub fn new(
        pseudo_verifiers_cache: Box<
            dyn VerifiersCache<
                Key = PseudonymizationContext,
                Verifiers = PseudonymizationFactorVerifiers,
            >,
        >,
        session_verifiers_cache: Box<
            dyn VerifiersCache<Key = EncryptionContext, Verifiers = RekeyFactorVerifiers>,
        >,
    ) -> Self {
        Self {
            pseudo_verifiers_cache,
            session_verifiers_cache,
        }
    }
    pub fn has_pseudo_verifiers(
        &self,
        system_id: &PEPSystemID,
        context: &PseudonymizationContext,
    ) -> bool {
        self.pseudo_verifiers_cache.has(system_id, context)
    }
    pub fn has_rekey_verifiers(
        &self,
        system_id: &PEPSystemID,
        context: &EncryptionContext,
    ) -> bool {
        self.session_verifiers_cache.has(system_id, context)
    }
    pub fn store_pseudo_verifiers(
        &mut self,
        system_id: PEPSystemID,
        context: PseudonymizationContext,
        verifiers: &PseudonymizationContextVerifiers,
        proof: &PseudonymizationFactorVerifiersProof,
    ) {
        if verifiers.val == GroupElement::identity() || verifiers.val == G {
            panic!("Weak verifiers are not allowed");
        }

        // TODO check if the no other system uses the same or reversed verifiers

        if proof.verify(&verifiers) {
            self.pseudo_verifiers_cache
                .store(system_id, context, verifiers.0);
        } else {
            panic!("Invalid proof");
        }
    }
    pub fn store_rekey_verifiers(
        &mut self,
        system_id: PEPSystemID,
        context: EncryptionContext,
        verifiers: &EncryptionContextVerifiers,
        proof: &RekeyFactorVerifiersProof,
    ) {
        if verifiers.val == GroupElement::identity() || verifiers.val == G {
            panic!("Weak verifiers are not allowed");
        }

        // TODO check if the no other system uses the same or reversed verifiers

        if proof.verify(&verifiers) {
            self.session_verifiers_cache
                .store(system_id, context, verifiers.0);
        } else {
            panic!("Invalid proof");
        }
    }
    #[must_use]
    pub fn verify_pseudonymization_info_proof(
        &self,
        proof: &PseudonymizationInfoProof,
        system_id: &PEPSystemID,
        pseudo_context_from: &PseudonymizationContext,
        pseudo_context_to: &PseudonymizationContext,
        enc_context_from: &EncryptionContext,
        enc_context_to: &EncryptionContext,
    ) -> bool {
        let pseudo_verifiers_from = self
            .pseudo_verifiers_cache
            .retrieve(system_id, pseudo_context_from)
            .unwrap();
        let pseudo_verifiers_to = self
            .pseudo_verifiers_cache
            .retrieve(system_id, pseudo_context_to)
            .unwrap();
        let rekey_verifiers_from = self
            .session_verifiers_cache
            .retrieve(system_id, enc_context_from)
            .unwrap();
        let rekey_verifiers_to = self
            .session_verifiers_cache
            .retrieve(system_id, enc_context_to)
            .unwrap();
        proof.verify(
            &pseudo_verifiers_from,
            &pseudo_verifiers_to,
            &rekey_verifiers_from,
            &rekey_verifiers_to,
        )
    }
    #[must_use]
    pub fn verify_rekey_info_proof(
        &self,
        proof: &RekeyInfoProof,
        system_id: &PEPSystemID,
        enc_context_from: &EncryptionContext,
        enc_context_to: &EncryptionContext,
    ) -> bool {
        let rekey_verifiers_from = self
            .session_verifiers_cache
            .retrieve(system_id, enc_context_from)
            .unwrap();
        let rekey_verifiers_to = self
            .session_verifiers_cache
            .retrieve(system_id, enc_context_to)
            .unwrap();
        proof.verify(&rekey_verifiers_from, &rekey_verifiers_to)
    }
    pub fn verify_pseudonym_transcryption(
        &self,
        messages: &Vec<(PEPSystemID, ProvedEncryptedPseudonym)>,
        pseudo_proofs: &Vec<(PEPSystemID, PseudonymizationInfoProof)>,
        original: &EncryptedPseudonym,
    ) -> Option<EncryptedPseudonym> {
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
    pub fn verify_data_transcryption(
        &self,
        messages: &Vec<(PEPSystemID, ProvedEncryptedDataPoint)>,
        rekey_proofs: &Vec<(PEPSystemID, RekeyInfoProof)>,
        original: &EncryptedDataPoint,
    ) -> Option<EncryptedDataPoint> {
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

#[derive(Deref)]
pub struct ProvedPEPSystem {
    pub system_id: PEPSystemID,
    #[deref]
    pub system: PEPSystem,
    pub verifier: PEPVerifier,
}

impl ProvedPEPSystem {
    pub fn new(system_id: PEPSystemID, system: PEPSystem, verifier: PEPVerifier) -> Self {
        Self {
            system_id,
            system,
            verifier,
        }
    }
    pub fn pseudo_context_verifiers<R: RngCore + CryptoRng>(
        &self,
        context: &PseudonymizationContext,
        rng: &mut R,
    ) -> (
        PseudonymizationContextVerifiers,
        PseudonymizationFactorVerifiersProof,
    ) {
        PseudonymizationContextVerifiers::new(context, &self.system.pseudonymisation_secret, rng)
    }
    pub fn enc_context_verifiers<R: RngCore + CryptoRng>(
        &self,
        context: &EncryptionContext,
        rng: &mut R,
    ) -> (EncryptionContextVerifiers, RekeyFactorVerifiersProof) {
        EncryptionContextVerifiers::new(context, &self.system.rekeying_secret, rng)
    }
    pub fn pseudo_info_proof<R: RngCore + CryptoRng>(
        &self,
        info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> PseudonymizationInfoProof {
        PseudonymizationInfoProof::new(info, rng)
    }
    pub fn rekey_info_proof<R: RngCore + CryptoRng>(
        &self,
        info: &RekeyInfo,
        rng: &mut R,
    ) -> RekeyInfoProof {
        RekeyInfoProof::new(info, rng)
    }
    pub fn proved_pseudonymize<R: RngCore + CryptoRng>(
        &self,
        p: &EncryptedPseudonym,
        pseudonymization_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> ProvedEncryptedPseudonym {
        proved_pseudonymize(p, pseudonymization_info, rng)
    }
    pub fn proved_rekey<R: RngCore + CryptoRng>(
        &self,
        p: &EncryptedDataPoint,
        rekey_info: &RekeyInfo,
        rng: &mut R,
    ) -> ProvedEncryptedDataPoint {
        proved_rekey(p, rekey_info, rng)
    }
    pub fn proved_distributed_pseudonymize<R: RngCore + CryptoRng>(
        &self,
        messages: &Vec<(PEPSystemID, ProvedEncryptedPseudonym)>,
        pseudo_proofs: &Vec<(PEPSystemID, PseudonymizationInfoProof)>,
        original: &EncryptedPseudonym,
        pseudonymization_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Option<ProvedEncryptedPseudonym> {
        if messages.len() == 0 {
            return Some(self.proved_pseudonymize(original, pseudonymization_info, rng));
        }
        let result =
            self.verifier
                .verify_pseudonym_transcryption(messages, pseudo_proofs, original);
        result.map(|x| proved_pseudonymize(&x, pseudonymization_info, rng))
    }
    pub fn proved_distributed_rekey<R: RngCore + CryptoRng>(
        &self,
        messages: &Vec<(PEPSystemID, ProvedEncryptedDataPoint)>,
        rekey_proofs: &Vec<(PEPSystemID, RekeyInfoProof)>,
        original: &EncryptedDataPoint,
        rekey_info: &RekeyInfo,
        rng: &mut R,
    ) -> Option<ProvedEncryptedDataPoint> {
        if messages.len() == 0 {
            return Some(self.proved_rekey(original, rekey_info, rng));
        }
        let result = self
            .verifier
            .verify_data_transcryption(messages, rekey_proofs, original);
        result.map(|x| proved_rekey(&x, rekey_info, rng))
    }
}
#[derive(Deref)]
pub struct ProvedPEPClient {
    #[deref]
    pub client: PEPClient,
    pub verifier: PEPVerifier,
}

impl ProvedPEPClient {
    pub fn new(client: PEPClient, verifier: PEPVerifier) -> Self {
        Self { client, verifier }
    }
    pub fn verified_decrypt_pseudonym(
        &self,
        messages: &Vec<(PEPSystemID, ProvedEncryptedPseudonym)>,
        pseudo_proofs: &Vec<(PEPSystemID, PseudonymizationInfoProof)>,
        original: &EncryptedPseudonym,
    ) -> Option<(Pseudonym, EncryptedPseudonym)> {
        let result =
            self.verifier
                .verify_pseudonym_transcryption(messages, pseudo_proofs, original);
        result.map(|x| (decrypt(&x, &self.session_secret_key), x))
    }
    pub fn verified_decrypt_data(
        &self,
        messages: &Vec<(PEPSystemID, ProvedEncryptedDataPoint)>,
        rekey_proofs: &Vec<(PEPSystemID, RekeyInfoProof)>,
        original: &EncryptedDataPoint,
    ) -> Option<(DataPoint, EncryptedDataPoint)> {
        let result = self
            .verifier
            .verify_data_transcryption(messages, rekey_proofs, original);
        result.map(|x| (decrypt(&x, &self.session_secret_key), x))
    }
}
