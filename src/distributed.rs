use std::collections::HashMap;
use rand_core::{CryptoRng, RngCore};
use crate::arithmetic::*;
use crate::elgamal::*;
use crate::proved::*;
use crate::simple::*;
use crate::zkps::*;

pub type GlobalPublicKey = GroupElement;
pub type GlobalSecretKey = ScalarNonZero;
pub type BlindedGlobalSecretKey = ScalarNonZero;
pub type DecryptionKeyPart = ScalarNonZero;
pub type DecryptionKey = ScalarNonZero;

pub type Message = GroupElement;
pub type Ciphertext = ElGamal;
pub type Context = String;
pub type SystemId = String;

pub struct TrustedPEPFactorVerifiersCache {
    cache: HashMap<(SystemId, Context), PEPFactorVerifiers>,
}

impl TrustedPEPFactorVerifiersCache {
    fn new() -> Self {
        TrustedPEPFactorVerifiersCache {
            cache: HashMap::new(),
        }
    }
    fn store(&mut self, system_id: SystemId, context: Context, verifiers: PEPFactorVerifiers) {
        self.cache.insert((system_id, context), verifiers);
    }
    fn retrieve(&self, system_id: &SystemId, context: &Context) -> Option<&PEPFactorVerifiers> {
        self.cache.get(&(system_id.to_string(), context.to_string()))
    }
    fn contains(&self, verifiers: &PEPFactorVerifiers) -> bool {
        self.cache.values().any(|x| x == verifiers)
    }
    fn dump(&self) -> Vec<(SystemId, Context, PEPFactorVerifiers)> {
        self.cache.iter().map(|((system_id, context), verifiers)| (system_id.clone(), context.clone(), verifiers.clone())).collect()
    }
    fn load(&mut self, data: Vec<(SystemId, Context, PEPFactorVerifiers)>) {
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
    pub fn pseudonymize<R: RngCore + CryptoRng>(&self, message: &Ciphertext, pc_from: &Context, pc_to: &Context, dc: &Context, rng: &mut R) -> ProvedRSKFromTo {
        let n_from = make_pseudonymisation_factor(&self.pseudonymisation_secret, pc_from);
        let n_to = make_pseudonymisation_factor(&self.pseudonymisation_secret, pc_to);
        let k = make_decryption_factor(&self.rekeying_secret, dc);
        ProvedRSKFromTo::new(message, &n_from, &n_to, &k, rng)
    }
    pub fn transcrypt<R: RngCore + CryptoRng>(&self, message: &Ciphertext, dc: &Context, rng: &mut R) -> ProvedRekey {
        let k = make_decryption_factor(&self.rekeying_secret, dc);
        ProvedRekey::new(message, &k, rng)
    }
    pub fn pseudonymisation_factor_verifiers_proof<R: RngCore + CryptoRng>(&self, pc: &Context, rng: &mut R) -> (ReshuffleFactorVerifiers, PEPFactorVerifiersProof) {
        let n = make_pseudonymisation_factor(&self.pseudonymisation_secret, pc);
        generate_pep_factor_verifiers(&n, rng)
    }
    pub fn rekeying_factor_verifiers_proof<R: RngCore + CryptoRng>(&self, dc: &Context, rng: &mut R) -> (RekeyFactorVerifiers, PEPFactorVerifiersProof) {
        let n = make_decryption_factor(&self.rekeying_secret, dc);
        generate_pep_factor_verifiers(&n, rng)
    }
    pub fn decryption_key_part<R: RngCore + CryptoRng>(&self, dc: &Context, rng: &mut R) -> (DecryptionKeyPart, Proof) {
        let k = make_decryption_factor(&self.rekeying_secret, dc);
        let dkp = k * &self.blinding_factor.invert();
        let (_gbi, proof) = create_proof(&self.blinding_factor.invert(), &(k * G), rng);
        (dkp, proof)
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
    fn verify_system_pseudonymize(&self, system_id: &SystemId, msg_in: &Ciphertext, proved: &ProvedRSKFromTo, pc_from: &Context, pc_to: &Context, dc: &Context) -> Result<Ciphertext, &'static str> {
        let trusted_from = self.trusted_pseudonymisation_factors.retrieve(system_id, pc_from).unwrap();
        let trusted_to = self.trusted_pseudonymisation_factors.retrieve(system_id, pc_to).unwrap();
        let trusted_k = self.trusted_rekeying_factors.retrieve(system_id, dc).unwrap();

        let msg_out = proved.verified_reconstruct(msg_in, trusted_from, trusted_to, trusted_k);
        if msg_out.is_none() {
            return Err("invalid proof");
        }

        Ok(msg_out.unwrap())
    }
    pub fn verify_pseudonymize(&self, messages: &Vec<(String, ElGamal, ProvedRSKFromTo)>, pc_from: &Context, pc_to: &Context, dc: &Context) -> Result<Ciphertext, &'static str> {
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
            let verification = self.verify_system_pseudonymize(&system_id, &msg_in, proved, pc_from, pc_to, dc);
            if verification.is_err() {
                return verification;
            }
            msg_out = Some(verification.unwrap());
            visited_systems.push(system_id);
        }
        Ok(msg_out.unwrap())
    }
    fn verify_system_transcrypt(&self, system_id: &SystemId, msg_in: &Ciphertext, proved_rekey: &ProvedRekey, dc: &Context) -> Result<Ciphertext, &'static str> {
        let trusted_k = self.trusted_rekeying_factors.retrieve(system_id, dc).unwrap();

        let msg_out = proved_rekey.verified_reconstruct(msg_in, trusted_k);
        if msg_out.is_none() {
            return Err("invalid proof");
        }
        Ok(msg_out.unwrap())
    }
    pub fn verify_transcrypt(&self, messages: &Vec<(String, ElGamal, ProvedRekey)>, dc: &Context) -> Result<Ciphertext, &'static str> {
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
            let verification = self.verify_system_transcrypt(&system_id, &msg_in, &proved, dc);
            if verification.is_err() {
                return verification;
            }
            msg_out = Some(verification.unwrap());
            visited_systems.push(system_id);
        }
        Ok(msg_out.unwrap())
    }
    pub fn trust_pseudonymisation_factor_verifiers(&mut self, system_id: &SystemId, pc: &Context, verifiers: &ReshuffleFactorVerifiers, proof: &PEPFactorVerifiersProof) {
        assert!(verify_pep_factor_verifiers(&verifiers, &proof));
        self.trusted_pseudonymisation_factors.store(system_id.to_string(), pc.to_string(), *verifiers);
    }
    pub fn trust_rekeying_factor_verifiers(&mut self, system_id: &SystemId, dc: &Context, verifiers: &RekeyFactorVerifiers, proof: &PEPFactorVerifiersProof) {
        assert!(verify_pep_factor_verifiers(&verifiers, &proof));
        self.trusted_rekeying_factors.store(system_id.to_string(), dc.to_string(), *verifiers);
    }

    #[must_use]
    pub fn verify_decryption_key_part(&self, dkp: &DecryptionKeyPart, system_id: &SystemId, dc: &Context, proof: &Proof) -> bool {
        let gk = self.trusted_rekeying_factors.retrieve(system_id, dc).unwrap().0;
        let blinded_global_key_group_element = self.config.blinded_global_key_group_elements[self.config.system_ids.iter().position(|x| x == system_id).unwrap()];
        verify_proof(&blinded_global_key_group_element, &gk, proof) && proof.n == *dkp * G
    }
    #[must_use]
    pub fn verify_decryption_key_parts(&self, dkps: &Vec<(SystemId, (DecryptionKeyPart, Proof))>, dc: &Context) -> bool {
        for (sid, (dkp, proof)) in dkps {
            assert!(self.verify_decryption_key_part(&dkp, &sid, dc, &proof));
        }
        true
    }
    pub fn decryption_key(&self, dkps: &Vec<(SystemId, (DecryptionKeyPart, Proof))>, dc: &Context) -> Option<DecryptionKey> {
        if self.verify_decryption_key_parts(dkps, dc) {
            Some(dkps.iter().fold(self.config.blinded_global_private_key, |acc, (_sid, (dkp, _p))| acc * dkp))
        } else {
            None
        }
    }
    pub fn decrypt(&self, msg: &Ciphertext, dkps: &Vec<(SystemId, (DecryptionKeyPart, Proof))>, dc: &Context) -> Message {
        let dk = self.decryption_key(dkps, dc).unwrap();
        decrypt(msg, &dk)
    }
    pub fn encrypt<R: RngCore + CryptoRng>(&self, msg: &Message, rng: &mut R) -> Ciphertext {
        // Note this is the only operation that requires a random number generator
        // If the ciphertext cannot securely generate ciphertexts, the network should rerandomize the ciphertexts to prevent linkability
        encrypt(msg, &self.config.global_public_key, rng)
    }
}
