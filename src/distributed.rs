use std::collections::HashMap;
use rand_core::{CryptoRng, RngCore};
use crate::arithmetic::*;
use crate::authenticity::*;
use crate::elgamal::*;
use crate::proved::*;
use crate::utils::*;
use crate::zkps::*;

pub type GlobalPublicKey = GroupElement;
pub type GlobalSecretKey = ScalarNonZero;
pub type BlindedGlobalSecretKey = ScalarNonZero;
pub type SessionKeyShare = ScalarNonZero;
pub type SessionKey = ScalarNonZero;

pub type Message = GroupElement;
pub type Ciphertext = ElGamal;
pub type Context = String;
pub type DecryptionContext = Context;
pub type PseudonymizationContext = Context;
pub type SystemId = String;

pub struct TrustedPEPFactorVerifiersCache {
    cache: HashMap<(SystemId, Context), FactorVerifiers>,
}

impl TrustedPEPFactorVerifiersCache {
    fn new() -> Self {
        TrustedPEPFactorVerifiersCache {
            cache: HashMap::new(),
        }
    }
    fn store(&mut self, system_id: SystemId, context: Context, verifiers: FactorVerifiers) {
        self.cache.insert((system_id, context), verifiers);
    }
    fn retrieve(&self, system_id: &SystemId, context: &Context) -> Option<&FactorVerifiers> {
        self.cache.get(&(system_id.to_string(), context.to_string()))
    }
    fn contains(&self, verifiers: &FactorVerifiers) -> bool {
        self.cache.values().any(|x| x == verifiers)
    }
    fn dump(&self) -> Vec<(SystemId, Context, FactorVerifiers)> {
        self.cache.iter().map(|((system_id, context), verifiers)| (system_id.clone(), context.clone(), verifiers.clone())).collect()
    }
    fn load(&mut self, data: Vec<(SystemId, Context, FactorVerifiers)>) {
        for (system_id, context, verifiers) in data {
            self.store(system_id, context, verifiers);
        }
    }
}

pub struct PEPClient {
    // A PEPClient is a client that can verify PEP operations performed by a PEPSystem.
    pub config: PEPNetworkConfig,
    pub trusted_pseudonymisation_factors: TrustedPEPFactorVerifiersCache,
    pub trusted_rekeying_factors: TrustedPEPFactorVerifiersCache,
}

pub struct PEPSystem {
    // A PEPSystem is a system that can perform PEP operations on messages (and verify them).
    pub client: PEPClient,
    pub system_id: String,
    pseudonymisation_secret: String,
    rekeying_secret: String,
    blinding_factor: ScalarNonZero,
}

#[derive(Eq, PartialEq, Clone)]
pub struct PEPNetworkConfig {
    // A PEPNetworkConfig is a configuration of a PEP network generated during the setup phase.
    pub global_public_key: GlobalPublicKey,
    pub blinded_global_private_key: BlindedGlobalSecretKey,
    pub system_ids: Vec<String>,
    pub blinded_global_key_group_elements: Vec<GroupElement>,
}

impl PEPNetworkConfig {
    pub fn new(global_public_key: GlobalPublicKey, blinded_global_private_key: BlindedGlobalSecretKey, system_ids: Vec<SystemId>, blinded_global_key_group_elements: Vec<GroupElement>) -> Self {
        Self {
            global_public_key,
            blinded_global_private_key,
            system_ids,
            blinded_global_key_group_elements,
        }
    }
}

impl PEPSystem {
    pub fn new(system_id: SystemId, config: PEPNetworkConfig, pseudonymisation_secret: String, rekeying_secret: String, blinding_factor: ScalarNonZero) -> Self {
        Self {
            client: PEPClient::new(config),
            system_id,
            pseudonymisation_secret,
            rekeying_secret,
            blinding_factor,
        }
    }
    pub fn pseudonymize<R: RngCore + CryptoRng>(&self, message: &Ciphertext, pc_from: &PseudonymizationContext, pc_to: &PseudonymizationContext, dc_from: &DecryptionContext, dc_to: &DecryptionContext, rng: &mut R) -> ProvedRSKFromTo {
        let s_from = make_pseudonymisation_factor(&self.pseudonymisation_secret, pc_from);
        let s_to = make_pseudonymisation_factor(&self.pseudonymisation_secret, pc_to);
        let k_from = make_decryption_factor(&self.rekeying_secret, dc_from);
        let k_to = make_decryption_factor(&self.rekeying_secret, dc_to);
        ProvedRSKFromTo::new(message, &s_from, &s_to, &k_from, &k_to, rng)
    }
    pub fn rekey<R: RngCore + CryptoRng>(&self, message: &Ciphertext, dc_from: &DecryptionContext, dc_to: &DecryptionContext, rng: &mut R) -> ProvedRekeyFromTo {
        let k_from = make_decryption_factor(&self.rekeying_secret, dc_from);
        let k_to = make_decryption_factor(&self.rekeying_secret, dc_to);
        ProvedRekeyFromTo::new(message, &k_from, &k_to, rng)
    }
    pub fn pseudonymisation_factor_verifiers_proof<R: RngCore + CryptoRng>(&self, pc: &PseudonymizationContext, rng: &mut R) -> (ReshuffleFactorVerifiers, FactorVerifiersProof) {
        let s = make_pseudonymisation_factor(&self.pseudonymisation_secret, pc);
        FactorVerifiers::new(&s, rng)
    }
    pub fn rekeying_factor_verifiers_proof<R: RngCore + CryptoRng>(&self, dc: &DecryptionContext, rng: &mut R) -> (RekeyFactorVerifiers, FactorVerifiersProof) {
        let s = make_decryption_factor(&self.rekeying_secret, dc);
        FactorVerifiers::new(&s, rng)
    }
    pub fn session_key_share<R: RngCore + CryptoRng>(&self, dc: &DecryptionContext, rng: &mut R) -> (SessionKeyShare, Proof) {
        let k = make_decryption_factor(&self.rekeying_secret, dc);
        let sks = k * &self.blinding_factor.invert();
        let (_gbi, proof) = create_proof(&self.blinding_factor.invert(), &(k * G), rng);
        (sks, proof)
    }
    pub fn verify_authenticity_tag(&self, tag: &AuthenticityTag, data: &ElGamal, pseudonym: &ElGamal, metadata: &Message, dc: &DecryptionContext) -> bool {
        let k = make_decryption_factor(&self.rekeying_secret, dc);
        let sks = k * &self.blinding_factor.invert();
        verify_authenticity_tag(tag, data, pseudonym, metadata, &self.system_id, &sks)
    }
}

impl PEPClient {
    pub fn new(config: PEPNetworkConfig) -> Self {
        Self {
            config,
            trusted_pseudonymisation_factors: TrustedPEPFactorVerifiersCache::new(),
            trusted_rekeying_factors: TrustedPEPFactorVerifiersCache::new(),
        }
    }
    fn verify_system_pseudonymize(&self, system_id: &SystemId, msg_in: &Ciphertext, proved: &ProvedRSKFromTo, pc_from: &PseudonymizationContext, pc_to: &PseudonymizationContext, dc_from: &DecryptionContext, dc_to: &DecryptionContext) -> Result<Ciphertext, &'static str> {
        let trusted_s_from = self.trusted_pseudonymisation_factors.retrieve(system_id, pc_from).unwrap();
        let trusted_s_to = self.trusted_pseudonymisation_factors.retrieve(system_id, pc_to).unwrap();
        let trusted_k_from = self.trusted_rekeying_factors.retrieve(system_id, dc_from).unwrap();
        let trusted_k_to = self.trusted_rekeying_factors.retrieve(system_id, dc_to).unwrap();

        let msg_out = proved.verified_reconstruct(msg_in, trusted_s_from, trusted_s_to, trusted_k_from, trusted_k_to);
        if msg_out.is_none() {
            return Err("invalid proof");
        }

        Ok(msg_out.unwrap())
    }
    pub fn verify_pseudonymize(&self, messages: &Vec<(String, ElGamal, ProvedRSKFromTo)>, pc_from: &PseudonymizationContext, pc_to: &PseudonymizationContext, dc_from: &DecryptionContext, dc_to: &DecryptionContext) -> Result<Ciphertext, &'static str> {
        let mut msg_out = None;
        let mut visited_systems = Vec::new();
        for (system_id, msg_in, proved) in messages {
            if !self.config.system_ids.contains(&String::from(system_id)) {
                return Err("invalid system id");
            }
            if visited_systems.contains(&system_id) {
                return Err("system visited twice");
            }
            if msg_out.is_some() && msg_out.unwrap() != *msg_in {
                return Err("inconsistent messages");
            }
            let verification = self.verify_system_pseudonymize(&system_id, &msg_in, proved, pc_from, pc_to, dc_from, dc_to);
            if verification.is_err() {
                return verification;
            }
            msg_out = Some(verification.unwrap());
            visited_systems.push(system_id);
        }
        Ok(msg_out.unwrap())
    }
    fn verify_system_rekey(&self, system_id: &SystemId, msg_in: &Ciphertext, proved_rekey: &ProvedRekeyFromTo, dc_from: &DecryptionContext, dc_to: &DecryptionContext) -> Result<Ciphertext, &'static str> {
        let trusted_k_from = self.trusted_rekeying_factors.retrieve(system_id, dc_from).unwrap();
        let trusted_k_to = self.trusted_rekeying_factors.retrieve(system_id, dc_to).unwrap();

        let msg_out = proved_rekey.verified_reconstruct(msg_in, trusted_k_from, trusted_k_to);
        if msg_out.is_none() {
            return Err("invalid proof");
        }
        Ok(msg_out.unwrap())
    }
    pub fn verify_rekey(&self, messages: &Vec<(String, ElGamal, ProvedRekeyFromTo)>, dc_from: &DecryptionContext, dc_to: &DecryptionContext) -> Result<Ciphertext, &'static str> {
        let mut msg_out = None;
        let mut visited_systems = Vec::new();
        for (system_id, msg_in, proved) in messages {
            if !self.config.system_ids.contains(&String::from(system_id)) {
                return Err("invalid system id");
            }
            if visited_systems.contains(&system_id) {
                return Err("system visited twice");
            }
            if msg_out.is_some() && msg_out.unwrap() != *msg_in {
                return Err("inconsistent messages");
            }
            let verification = self.verify_system_rekey(&system_id, &msg_in, &proved, dc_from, dc_to);
            if verification.is_err() {
                return verification;
            }
            msg_out = Some(verification.unwrap());
            visited_systems.push(system_id);
        }
        Ok(msg_out.unwrap())
    }
    pub fn trust_pseudonymisation_factor_verifiers(&mut self, system_id: &SystemId, pc: &PseudonymizationContext, verifiers: &ReshuffleFactorVerifiers, proof: &FactorVerifiersProof) {
        assert!(&proof.verify(verifiers));
        self.trusted_pseudonymisation_factors.store(system_id.to_string(), pc.to_string(), *verifiers);
    }
    pub fn trust_rekeying_factor_verifiers(&mut self, system_id: &SystemId, dc: &DecryptionContext, verifiers: &RekeyFactorVerifiers, proof: &FactorVerifiersProof) {
        assert!(&proof.verify(verifiers));
        self.trusted_rekeying_factors.store(system_id.to_string(), dc.to_string(), *verifiers);
    }

    #[must_use]
    pub fn verify_session_key_share(&self, dkp: &SessionKeyShare, system_id: &SystemId, dc: &DecryptionContext, proof: &Proof) -> bool {
        let gk = self.trusted_rekeying_factors.retrieve(system_id, dc).unwrap().0;
        let blinded_global_key_group_element = self.config.blinded_global_key_group_elements[self.config.system_ids.iter().position(|x| x == system_id).unwrap()];
        verify_proof(&blinded_global_key_group_element, &gk, proof) && proof.n == *dkp * G
    }
    #[must_use]
    pub fn verify_session_key_shares(&self, skss: &Vec<(SystemId, (SessionKeyShare, Proof))>, dc: &DecryptionContext) -> bool {
        for (sid, (dkp, proof)) in skss {
            assert!(self.verify_session_key_share(&dkp, &sid, dc, &proof));
        }
        true
    }
    pub fn session_key(&self, skss: &Vec<(SystemId, (SessionKeyShare, Proof))>, dc: &DecryptionContext) -> Option<SessionKey> {
        if self.verify_session_key_shares(skss, dc) {
            Some(skss.iter().fold(self.config.blinded_global_private_key, |acc, (_sid, (dkp, _p))| acc * dkp))
        } else {
            None
        }
    }
    pub fn decrypt(&self, msg: &Ciphertext, session_key: SessionKey) -> Message {
        decrypt(msg, &session_key)
    }
    pub fn encrypt<R: RngCore + CryptoRng>(&self, msg: &Message, session_key: SessionKey, rng: &mut R) -> Ciphertext {
        // Note this is the only operation that requires a random number generator
        // If the ciphertext cannot securely generate ciphertexts, the network should rerandomize the ciphertexts to prevent linkability
        encrypt(msg, &(session_key * G), rng)
    }
    // pub fn authenticity_tags<R: RngCore + CryptoRng>(&self, data: &ElGamal, pseudonym: &ElGamal, metadata: &Message, skss: &Vec<(SystemId, (SessionKeyShare, Proof))>) -> Option<Vec<AuthenticityTag>> {
    //     skss.iter().map(|(sid, (dkp, _p))| authenticity_tag(data, pseudonym, metadata, sid, &dkp)).collect()
    // }
    pub fn encrypt_global<R: RngCore + CryptoRng>(&self, msg: &Message, rng: &mut R) -> Ciphertext {
        // Note this is the only operation that requires a random number generator
        // If the ciphertext cannot securely generate ciphertexts, the network should rerandomize the ciphertexts to prevent linkability
        encrypt(msg, &self.config.global_public_key, rng)
    }
}
