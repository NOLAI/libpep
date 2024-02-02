use rand_core::OsRng;
use crate::arithmetic::*;
use crate::distributed::*;
use crate::elgamal::*;
use crate::primitives::*;
use crate::proved::*;
use crate::simple::*;
use crate::zkps::*;

#[test]
fn elgamal_encryption() {
    let mut rng = OsRng;
    // secret key
    let s = ScalarNonZero::random(&mut rng);
    // public key
    let p = s * G;

    // choose a random value to encrypt
    let value = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&value, &p, &mut OsRng);
    let decrypted = decrypt(&encrypted, &s);

    assert_eq!(value, decrypted);


    let encoded = encrypted.encode();
    let decoded = ElGamal::decode(&encoded);

    assert_eq!(Some(encrypted), decoded);
}

#[test]
fn pep_assumptions() {
    let mut rng = OsRng;
    // secret key of system
    let sk = ScalarNonZero::random(&mut rng);
    // public key of system
    let pk = sk * G;

    // secret key of service provider
    let sj = ScalarNonZero::random(&mut rng);
    let yj = sj * sk;
    assert_eq!(yj * G, sj * pk);

    // Lemma 2: RS(RK(..., k), n) == RK(RS(..., n), k)
    let value = GroupElement::random(&mut rng);
    let encrypted = encrypt(&value, &pk, &mut OsRng);
    let k = ScalarNonZero::random(&mut rng);
    let n = ScalarNonZero::random(&mut rng);
    assert_eq!(reshuffle(&rekey(&encrypted, &k), &n), rekey(&reshuffle(&encrypted, &n), &k));
    assert_eq!(reshuffle(&rekey(&encrypted, &k), &n), rsk(&encrypted, &n, &k));
}

#[test]
fn elgamal_signature() {
    let mut rng = OsRng;
    // secret key
    let s = ScalarNonZero::random(&mut rng);
    let s2 = ScalarNonZero::random(&mut rng);
    // public key
    let gp = s * G;

    let v = GroupElement::random(&mut rng);
    let mut signature = sign(&v, &s, &mut rng);
    assert!(verify(&v, &signature, &gp));

    signature = sign(&v, &s2, &mut rng);
    assert!(!verify(&v, &signature, &gp));
}

#[test]
fn pep_schnorr_basic_offline() {
    let mut rng = OsRng;
    // given a secret a and public M, proof that a certain triplet (A, M, N) is actually calculated by (a*G, M, a * M)
    // using Fiat-Shamir transform

    // prover
    let a = ScalarNonZero::random(&mut rng);
    let gm = GroupElement::random(&mut rng);

    let (ga, p) = create_proof(&a, &gm, &mut rng);
    assert_eq!(a * gm, *p);

    // verifier
    assert!(verify_proof(&ga, &gm, &p));
}

#[test]
fn pep_factor_verifiers_proof() {
    let mut rng = OsRng;

    let x = ScalarNonZero::random(&mut rng);
    let (verifiers, proof) = PEPFactorVerifiers::new(&x, &mut rng);
    assert!(&proof.verify(&verifiers))
}

#[test]
fn pep_proved_rerandomize() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let s = ScalarNonZero::random(&mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedRerandomize::new(&msg, &s, &mut rng);

    let checked = proved.verified_reconstruct(&msg);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(gm, decrypt(checked.as_ref().unwrap(), &y));
    assert_eq!(&rerandomize(&msg, &s), checked.as_ref().unwrap());
}

#[test]
fn pep_proved_reshuffle() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let n = ScalarNonZero::random(&mut rng);

    let (verifiers, _) = PEPFactorVerifiers::new(&n, &mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedReshuffle::new(&msg, &n, &mut rng);

    let checked = proved.verified_reconstruct(&msg, &verifiers);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(n * gm, decrypt(checked.as_ref().unwrap(), &y));
    assert_eq!(&reshuffle(&msg, &n), checked.as_ref().unwrap());
}

#[test]
fn pep_proved_rekey() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let k = ScalarNonZero::random(&mut rng);

    let (verifiers, _) = PEPFactorVerifiers::new(&k, &mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedRekey::new(&msg, &k, &mut rng);
    let checked = proved.verified_reconstruct(&msg, &verifiers);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(gm, decrypt(checked.as_ref().unwrap(), &(k * y)));
}

#[test]
fn pep_proved_reshuffle_from_to() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let n_from = ScalarNonZero::random(&mut rng);
    let n_to = ScalarNonZero::random(&mut rng);

    let (verifiers_from, _) = PEPFactorVerifiers::new(&n_from, &mut rng);
    let (verifiers_to, _) = PEPFactorVerifiers::new(&n_to, &mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedReshuffleFromTo::new(&msg, &n_from, &n_to, &mut rng);

    let checked = proved.verified_reconstruct(&msg, &verifiers_from, &verifiers_to);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(n_from.invert() * n_to * gm, decrypt(checked.as_ref().unwrap(), &y));
    assert_eq!(&reshuffle_from_to(&msg, &n_from, &n_to), checked.as_ref().unwrap());
}
#[test]
fn pep_proved_rsk() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let n = ScalarNonZero::random(&mut rng);
    let k = ScalarNonZero::random(&mut rng);

    let (verifiers_n, _) = PEPFactorVerifiers::new(&n, &mut rng);
    let (verifiers_k, _) = PEPFactorVerifiers::new(&k, &mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedRSK::new(&msg, &n, &k, &mut rng);

    let checked = proved.verified_reconstruct(&msg, &verifiers_n, &verifiers_k);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(n * gm, decrypt(checked.as_ref().unwrap(), &(k * y)));
    assert_eq!(&rsk(&msg, &n, &k), checked.as_ref().unwrap());
}
#[test]
fn pep_proved_rsk_from_to() {
    let mut rng = OsRng;
    // secret key of system
    let y = ScalarNonZero::random(&mut rng);
    // public key of system
    let gy = y * G;

    let gm = GroupElement::random(&mut rng);
    let n_from = ScalarNonZero::random(&mut rng);
    let n_to = ScalarNonZero::random(&mut rng);
    let k = ScalarNonZero::random(&mut rng);

    let (verifiers_from, _) = PEPFactorVerifiers::new(&n_from, &mut rng);
    let (verifiers_to, _) = PEPFactorVerifiers::new(&n_to, &mut rng);
    let (verifiers_k, _) = PEPFactorVerifiers::new(&k, &mut rng);

    let msg = encrypt(&gm, &gy, &mut rng);

    let proved = ProvedRSKFromTo::new(&msg, &n_from, &n_to, &k, &mut rng);

    let checked = proved.verified_reconstruct(&msg, &verifiers_from, &verifiers_to, &verifiers_k);

    assert!(checked.is_some());
    assert_ne!(&msg, checked.as_ref().unwrap());
    assert_eq!(n_from.invert() * n_to * gm, decrypt(checked.as_ref().unwrap(), &(k * y)));
    assert_eq!(&rsk_from_to(&msg, &n_from, &n_to, &k), checked.as_ref().unwrap());
}

#[test]
fn pep_high_level_api() {
    let mut rng = OsRng;
    let (public_key, secret_key) = generate_global_keys(&mut rng);

    let id = "foobar";
    let mut gep = generate_pseudonym(id, &public_key, &mut rng);
    gep = rerandomize_global(&gep, &mut rng);
    let mut lep = convert_to_local_pseudonym(&gep, "very_secret_on_server", "login_session_of_user", "access_group_of_user");
    lep = rerandomize_local(&lep, &mut rng);

    let decryption_key = make_local_decryption_key(&secret_key, "very_secret_on_server", "login_session_of_user");
    let lp = decrypt_local_pseudonym(&lep, &decryption_key);
    let hex = "be26a708fcf722db8d19f6d8c8443794156af30b17c44bcf4bb41791c0708945";
    let expected = hex::decode(hex).unwrap();
    assert_eq!(&lp.encode()[..], &expected);

    let gep = convert_from_local_pseudonym(&lep, "very_secret_on_server", "login_session_of_user", "access_group_of_user");
    let mut lep = convert_to_local_pseudonym(&gep, "very_secret_on_server", "login_session_of_user", "access_group_of_user");
    lep = rerandomize_local(&lep, &mut rng);

    let decryption_key = make_local_decryption_key(&secret_key, "very_secret_on_server", "login_session_of_user");
    let lp = decrypt_local_pseudonym(&lep, &decryption_key);
    let hex = "be26a708fcf722db8d19f6d8c8443794156af30b17c44bcf4bb41791c0708945";
    let expected = hex::decode(hex).unwrap();
    assert_eq!(&lp.encode()[..], &expected);
}

#[test]
fn distributed_pep_api() {
    let n = 5;
    let mut rng = OsRng;

    fn setup_network(n: usize, rng: &mut OsRng) -> (PEPNetworkConfig, Vec<PEPSystem>, Vec<String>, Vec<String>, Vec<(ScalarNonZero, GroupElement)>) {
        let (global_public_key, global_secret_key) = generate_global_keys(rng);

        let mut blinding_factors = Vec::new();
        for _ in 0..n {
            let blinding_factor = ScalarNonZero::random(rng);
            let blinding_inv_group_element = blinding_factor.invert() * G;
            blinding_factors.push((blinding_factor, blinding_inv_group_element));
        }
        let blinded_global_secret_key = blinding_factors.iter().fold(global_secret_key, |acc, s| acc * s.0);
        let blinding_inv_group_elements: Vec<GroupElement> = blinding_factors.iter().map(|x| x.1).collect();
        // TODO: we can add proofs that the blinding factors are correct to get even more trust during system setup
        // TODO: we could even hide them with secondary blinding factor, only used for constructing blinded_global_secret_key

        let network_config = PEPNetworkConfig::new(global_public_key, blinded_global_secret_key, (0..n).map(|i| format!("system-{}", i)).collect(), blinding_inv_group_elements.clone());

        let mut pseudonymisation_secrets = Vec::new();
        let mut rekeying_secrets = Vec::new();
        let mut systems = Vec::new();
        for i in 0..n {
            let system_id: SystemId = format!("system-{}", i);
            let pseudonymisation_secret = hex::encode(&ScalarNonZero::random(rng).encode());
            pseudonymisation_secrets.push(pseudonymisation_secret.clone());
            let rekeying_secret = hex::encode(&ScalarNonZero::random(rng).encode());
            rekeying_secrets.push(rekeying_secret.clone());
            let system = PEPSystem::new(system_id, network_config.clone(), pseudonymisation_secret, rekeying_secret, blinding_factors[i].0);
            systems.push(system);
        }

        (network_config, systems, pseudonymisation_secrets, rekeying_secrets, blinding_factors) // secrets are only returned for testing
    }


    fn retrieve_factor_verifiers(systems: &mut Vec<PEPSystem>, user: &mut PEPClient, pc_from: &Context, pc_to: &Context, dc: &Context, rng: &mut OsRng) {
        for i in 0..systems.len() {
            let system_id = &systems[i].system_id.clone();
            let (v_pc_from, p_pc_from) = systems[i].pseudonymisation_factor_verifiers_proof(&pc_from, rng);
            let (v_pc_to, p_pc_to) = systems[i].pseudonymisation_factor_verifiers_proof(&pc_to, rng);
            let (v_dc, p_dc) = systems[i].rekeying_factor_verifiers_proof(&dc, rng);

            for j in 0..systems.len() {
                let system = &mut systems[j];
                if i == j {
                    continue;
                }
                system.client.trust_pseudonymisation_factor_verifiers(&system_id, &pc_from, &v_pc_from, &p_pc_from);
                system.client.trust_pseudonymisation_factor_verifiers(system_id, &pc_to, &v_pc_to, &p_pc_to);
                system.client.trust_rekeying_factor_verifiers(&system_id, &dc, &v_dc, &p_dc);
            }
            user.trust_pseudonymisation_factor_verifiers(&system_id, &pc_from, &v_pc_from, &p_pc_from);
            user.trust_pseudonymisation_factor_verifiers(system_id, &pc_to, &v_pc_to, &p_pc_to);
            user.trust_rekeying_factor_verifiers(&system_id, &dc, &v_dc, &p_dc);
        }
    }

    fn pseudonymize_through_network(data_in: &GroupElement, pc_from: &Context, pc_to: &Context, dc: &Context, systems: &mut Vec<PEPSystem>, sender: &mut PEPClient, receiver: &mut PEPClient, rng: &mut OsRng) -> GroupElement {
        let mut network = Vec::new();

        let msg_in = sender.encrypt(&data_in, rng);
        // TODO: rerandomize?

        // First system
        let proven = systems[0].pseudonymize(&msg_in, pc_from, pc_to, dc, rng);
        network.push((systems[0].system_id.clone(), msg_in.clone(), proven));

        // All other systems
        for i in 1..systems.len() {
            let system = &mut systems[i];
            let msg_in = system.client.verify_pseudonymize(&network, &pc_from, &pc_to, &dc).unwrap();
            let proven = system.pseudonymize(&msg_in, pc_from, pc_to, dc, rng);
            network.push((system.system_id.clone(), msg_in.clone(), proven));
        }

        // Recipient
        let msg_out = receiver.verify_pseudonymize(&network, pc_from, pc_to, dc).unwrap(); // can be done by client
        let decryption_key_parts = systems.iter().map(|s| (s.system_id.clone(), s.decryption_key_part(dc, rng))).collect::<Vec<_>>();
        let data_out = receiver.decrypt(&msg_out, &decryption_key_parts, dc);
        data_out
    }

    fn transcrypt_through_network(data_in: &GroupElement, dc: &Context, systems: &mut Vec<PEPSystem>, sender: &mut PEPClient, receiver: &mut PEPClient, rng: &mut OsRng) -> GroupElement {
        let mut network = Vec::new();

        let msg_in = sender.encrypt(&data_in, rng);
        // TODO: rerandomize?

        let msg_in = rerandomize(&msg_in, &ScalarNonZero::random(rng));

        // First system
        let proven = systems[0].transcrypt(&msg_in, dc, rng);
        network.push((systems[0].system_id.clone(), msg_in.clone(), proven));

        // All other systems
        for i in 1..systems.len() {
            let system = &mut systems[i];
            let msg_in = system.client.verify_transcrypt(&network, &dc).unwrap();
            let proven = system.transcrypt(&msg_in, dc, rng);
            network.push((system.system_id.clone(), msg_in.clone(), proven));
        }

        // Recipient
        let msg_out = receiver.verify_transcrypt(&network, dc).unwrap(); // can be done by client
        let decryption_key_parts = systems.iter().map(|s| (s.system_id.clone(), s.decryption_key_part(dc, rng))).collect::<Vec<_>>();
        let data_out = receiver.decrypt(&msg_out, &decryption_key_parts, dc);
        data_out
    }

    let (network_config, mut systems, pseudonymisation_secrets, rekeying_secrets, blinding_factors) = setup_network(n, &mut rng);

    let mut user_a = PEPClient::new(network_config.clone());
    let mut user_b = PEPClient::new(network_config.clone());
    let mut user_c = PEPClient::new(network_config.clone());

    let pc_a: Context = Context::from("pc-user-a");
    let dc_a1: Context = Context::from("dc-user-a1");
    let pc_b: Context = Context::from("pc-user-b");
    let dc_b1: Context = Context::from("dc-user-b1");
    let dc_b2: Context = Context::from("dc-user-b2");
    let pc_c: Context = Context::from("pc-user-c");
    let dc_c1: Context = Context::from("dc-user-c1");

    let lp_a = GroupElement::random(&mut rng);
    retrieve_factor_verifiers(&mut systems, &mut user_b, &pc_a, &pc_b, &dc_b1, &mut rng);
    let lp_b = pseudonymize_through_network(&lp_a, &pc_a, &pc_b, &dc_b1, &mut systems, &mut user_a, &mut user_b, &mut rng);
    let expected = decrypt(&(0..n).fold(encrypt(&lp_a, &network_config.global_public_key, &mut rng), |acc, i| rsk(&acc, &(make_pseudonymisation_factor(&pseudonymisation_secrets[i], &pc_a).invert() * make_pseudonymisation_factor(&pseudonymisation_secrets[i], &pc_b)), &make_decryption_factor(&rekeying_secrets[i], &dc_b1))), &(0..n).fold(network_config.blinded_global_private_key, |acc, i| acc * make_decryption_factor(&rekeying_secrets[i], &dc_b1) * &blinding_factors[i].0.invert()));
    assert_eq!(expected, lp_b);

    // Pseudonymization is invertible
    retrieve_factor_verifiers(&mut systems, &mut user_a, &pc_b, &pc_a, &dc_a1, &mut rng);
    let lp_a_return = pseudonymize_through_network(&lp_b, &pc_b, &pc_a, &dc_a1, &mut systems, &mut user_b, &mut user_a, &mut rng);
    assert_eq!(lp_a, lp_a_return);

    // Pseudonymization is transitive
    retrieve_factor_verifiers(&mut systems, &mut user_c, &pc_a, &pc_c, &dc_c1, &mut rng);
    let lp_c = pseudonymize_through_network(&lp_a, &pc_a, &pc_c, &dc_c1, &mut systems, &mut user_a, &mut user_c, &mut rng);
    retrieve_factor_verifiers(&mut systems, &mut user_c, &pc_b, &pc_c, &dc_c1, &mut rng);
    let lp_c_via_b = pseudonymize_through_network(&lp_b, &pc_b, &pc_c, &dc_c1, &mut systems, &mut user_b, &mut user_c, &mut rng);
    assert_eq!(lp_c, lp_c_via_b);

    // Pseudonymization is deterministic for user
    retrieve_factor_verifiers(&mut systems, &mut user_b, &pc_a, &pc_b, &dc_b2, &mut rng);
    let lp_b_2 = pseudonymize_through_network(&lp_a, &pc_a, &pc_b, &dc_b2, &mut systems, &mut user_a, &mut user_b, &mut rng);
    assert_eq!(lp_b, lp_b_2);
    assert_ne!(lp_b, lp_c);

    let plaintext_a = GroupElement::random(&mut rng);
    let plaintext_b = transcrypt_through_network(&plaintext_a, &dc_b1, &mut systems, &mut user_a, &mut user_b, &mut rng);
    assert_eq!(plaintext_a, plaintext_b);

    // Network is commutative
    systems.reverse();
    let lp_b_reversed = pseudonymize_through_network(&lp_a, &pc_a, &pc_b, &dc_b1, &mut systems, &mut user_a, &mut user_b, &mut rng);
    assert_eq!(lp_b, lp_b_reversed);
}
