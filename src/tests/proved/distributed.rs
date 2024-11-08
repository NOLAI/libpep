use rand_core::OsRng;
use crate::distributed::{make_blinded_global_secret_key, BlindingFactor, PEPClient, PEPSystem};
use crate::high_level::contexts::{EncryptionContext, PseudonymizationContext};
use crate::high_level::data_types::{DataPoint, Pseudonym};
use crate::high_level::keys::{make_global_keys, EncryptionSecret, PseudonymizationSecret};
use crate::proved::distributed::{PEPVerifier, ProvedPEPClient, ProvedPEPSystem};
use crate::proved::primitives::{PseudonymizationFactorVerifiers, RekeyFactorVerifiers};
use crate::proved::verifiers_cache::InMemoryVerifiersCache;

#[test]
fn n_pep_proved() {
    let n = 3;
    let rng = &mut OsRng;

    let (_global_public, global_secret) = make_global_keys(rng);
    let blinding_factors = (0..n)
        .map(|_| BlindingFactor::random(rng))
        .collect::<Vec<_>>();
    let blinded_global_secret_key =
        make_blinded_global_secret_key(&global_secret, &blinding_factors.clone()).unwrap();

    // Create systems
    let mut systems = (0..n)
        .map(|i| {
            let system_id = format!("system-{}", i);
            let pseudonymization_secret =
                PseudonymizationSecret::from(format!("ps-secret-{}", i).as_bytes().into());
            let encryption_secret =
                EncryptionSecret::from(format!("es-secret-{}", i).as_bytes().into());
            let blinding_factor = blinding_factors[i].clone();
            let pseudo_cache = InMemoryVerifiersCache::<
                PseudonymizationContext,
                PseudonymizationFactorVerifiers,
            >::new();
            let rekey_cache =
                InMemoryVerifiersCache::<EncryptionContext, RekeyFactorVerifiers>::new();
            ProvedPEPSystem::new(
                system_id,
                PEPSystem::new(pseudonymization_secret, encryption_secret, blinding_factor),
                PEPVerifier::new(Box::new(pseudo_cache), Box::new(rekey_cache)),
            )
        })
        .collect::<Vec<_>>();

    // Setup demo contexts
    let pc_a = PseudonymizationContext::from("user-a");
    let pc_b = PseudonymizationContext::from("user-b");

    let ec_a1 = EncryptionContext::from("session-a1");
    let ec_b1 = EncryptionContext::from("session-b1");


    // Get client session key shares
    let sks_a1 = systems
        .iter()
        .map(|system| system.session_key_share(&ec_a1))
        .collect::<Vec<_>>();
    let sks_b1 = systems
        .iter()
        .map(|system| system.session_key_share(&ec_b1))
        .collect::<Vec<_>>();

    // Create clients
    let client_pseudo_cache_a = InMemoryVerifiersCache::new();
    let client_rekey_cache_a = InMemoryVerifiersCache::new();
    let client_pseudo_cache_b = InMemoryVerifiersCache::new();
    let client_rekey_cache_b = InMemoryVerifiersCache::new();

    let mut client_a = ProvedPEPClient::new(
        PEPClient::new(blinded_global_secret_key.clone(), &sks_a1),
        PEPVerifier::new(
            Box::new(client_pseudo_cache_a),
            Box::new(client_rekey_cache_a),
        ),
    );
    let mut client_b = ProvedPEPClient::new(
        PEPClient::new(blinded_global_secret_key.clone(), &sks_b1),
        PEPVerifier::new(
            Box::new(client_pseudo_cache_b),
            Box::new(client_rekey_cache_b),
        ),
    );

    // Distribute verifiers (once per context)
    let pseudo_verifiers_a = systems
        .iter()
        .map(|system| {
            (
                system.system_id.clone(),
                system.pseudo_context_verifiers(&pc_a, rng),
            )
        })
        .collect::<Vec<_>>();
    let pseudo_verifiers_b = systems
        .iter()
        .map(|system| {
            (
                system.system_id.clone(),
                system.pseudo_context_verifiers(&pc_b, rng),
            )
        })
        .collect::<Vec<_>>();
    let rekey_verifiers_a1 = systems
        .iter()
        .map(|system| {
            (
                system.system_id.clone(),
                system.enc_context_verifiers(&ec_a1, rng),
            )
        })
        .collect::<Vec<_>>();
    let rekey_verifiers_b1 = systems
        .iter()
        .map(|system| {
            (
                system.system_id.clone(),
                system.enc_context_verifiers(&ec_b1, rng),
            )
        })
        .collect::<Vec<_>>();

    for system in systems.iter_mut() {
        pseudo_verifiers_a
            .iter()
            .for_each(|(system_id, (verifiers, proof))| {
                if !system.verifier.has_pseudo_verifiers(system_id, &pc_a) {
                    system.verifier.store_pseudo_verifiers(
                        system_id.clone(),
                        pc_a.clone(),
                        verifiers,
                        proof,
                    );
                }
            });
        pseudo_verifiers_b
            .iter()
            .for_each(|(system_id, (verifiers, proof))| {
                if !system.verifier.has_pseudo_verifiers(system_id, &pc_b) {
                    system.verifier.store_pseudo_verifiers(
                        system_id.clone(),
                        pc_b.clone(),
                        verifiers,
                        proof,
                    );
                }
            });
        rekey_verifiers_a1
            .iter()
            .for_each(|(system_id, (verifiers, proof))| {
                if !system.verifier.has_rekey_verifiers(system_id, &ec_a1) {
                    system.verifier.store_rekey_verifiers(
                        system_id.clone(),
                        ec_a1.clone(),
                        verifiers,
                        proof,
                    );
                }
            });
        rekey_verifiers_b1
            .iter()
            .for_each(|(system_id, (verifiers, proof))| {
                if !system.verifier.has_rekey_verifiers(system_id, &ec_b1) {
                    system.verifier.store_rekey_verifiers(
                        system_id.clone(),
                        ec_b1.clone(),
                        verifiers,
                        proof,
                    );
                }
            });
    }
    pseudo_verifiers_a
        .iter()
        .for_each(|(system_id, (verifiers, proof))| {
            if !client_a.verifier.has_pseudo_verifiers(system_id, &pc_a) {
                client_a.verifier.store_pseudo_verifiers(
                    system_id.clone(),
                    pc_a.clone(),
                    verifiers,
                    proof,
                );
            }
        });
    pseudo_verifiers_b
        .iter()
        .for_each(|(system_id, (verifiers, proof))| {
            if !client_a.verifier.has_pseudo_verifiers(system_id, &pc_b) {
                client_a.verifier.store_pseudo_verifiers(
                    system_id.clone(),
                    pc_b.clone(),
                    verifiers,
                    proof,
                );
            }
        });
    rekey_verifiers_a1
        .iter()
        .for_each(|(system_id, (verifiers, proof))| {
            if !client_a.verifier.has_rekey_verifiers(system_id, &ec_a1) {
                client_a.verifier.store_rekey_verifiers(
                    system_id.clone(),
                    ec_a1.clone(),
                    verifiers,
                    proof,
                );
            }
        });
    rekey_verifiers_b1
        .iter()
        .for_each(|(system_id, (verifiers, proof))| {
            if !client_a.verifier.has_rekey_verifiers(system_id, &ec_b1) {
                client_a.verifier.store_rekey_verifiers(
                    system_id.clone(),
                    ec_b1.clone(),
                    verifiers,
                    proof,
                );
            }
        });

    pseudo_verifiers_a
        .iter()
        .for_each(|(system_id, (verifiers, proof))| {
            if !client_b.verifier.has_pseudo_verifiers(system_id, &pc_a) {
                client_b.verifier.store_pseudo_verifiers(
                    system_id.clone(),
                    pc_a.clone(),
                    verifiers,
                    proof,
                );
            }
        });
    pseudo_verifiers_b
        .iter()
        .for_each(|(system_id, (verifiers, proof))| {
            if !client_b.verifier.has_pseudo_verifiers(system_id, &pc_b) {
                client_b.verifier.store_pseudo_verifiers(
                    system_id.clone(),
                    pc_b.clone(),
                    verifiers,
                    proof,
                );
            }
        });
    rekey_verifiers_a1
        .iter()
        .for_each(|(system_id, (verifiers, proof))| {
            if !client_b.verifier.has_rekey_verifiers(system_id, &ec_a1) {
                client_b.verifier.store_rekey_verifiers(
                    system_id.clone(),
                    ec_a1.clone(),
                    verifiers,
                    proof,
                );
            }
        });
    rekey_verifiers_b1
        .iter()
        .for_each(|(system_id, (verifiers, proof))| {
            if !client_b.verifier.has_rekey_verifiers(system_id, &ec_b1) {
                client_b.verifier.store_rekey_verifiers(
                    system_id.clone(),
                    ec_b1.clone(),
                    verifiers,
                    proof,
                );
            }
        });

    // Distribute verifiers (once per session)
    let pseudo_infos = systems
        .iter()
        .map(|system| {
            let info = system.pseudonymization_info(&pc_a, &pc_b, &ec_a1, &ec_b1);
            let proof = system.pseudo_info_proof(&info, rng);
            (system.system_id.clone(), info.clone(), proof.clone())
        })
        .collect::<Vec<_>>();
    let rekey_infos = systems
        .iter()
        .map(|system| {
            let info = system.rekey_info(&ec_a1, &ec_b1);
            let proof = system.rekey_info_proof(&info, rng);
            (system.system_id.clone(), info.clone(), proof.clone())
        })
        .collect::<Vec<_>>();

    for system in systems.iter_mut() {
        pseudo_infos.iter().for_each(|(system_id, _info, proof)| {
            assert!(system.verifier.verify_pseudonymization_info_proof(
                proof, system_id, &pc_a, &pc_b, &ec_a1, &ec_b1
            ));
        });
        rekey_infos.iter().for_each(|(system_id, _info, proof)| {
            assert!(system
                .verifier
                .verify_rekey_info_proof(proof, system_id, &ec_a1, &ec_b1));
        });
    }

    // Session walkthrough
    let pseudonym = Pseudonym::random(rng);
    let data = DataPoint::random(rng);

    let enc_pseudo = client_a.encrypt(&pseudonym, rng);
    let enc_data = client_a.encrypt(&data, rng);

    let mut messages_pseudo = Vec::new();
    let mut messages_pseudo_infos = Vec::new();
    for system in systems.iter() {
        let (_, pseudo_info, pseudo_info_proof) = pseudo_infos
            .iter()
            .find(|(system_id, _, _)| system_id == &system.system_id)
            .unwrap();
        let result = system.proved_distributed_pseudonymize(
            &messages_pseudo,
            &messages_pseudo_infos,
            &enc_pseudo,
            &pseudo_info,
            rng,
        );
        messages_pseudo.push((system.system_id.clone(), result.unwrap()));
        messages_pseudo_infos.push((system.system_id.clone(), *pseudo_info_proof));
    }

    let mut messages_data = Vec::new();
    let mut messages_rekey_infos = Vec::new();
    for system in systems.iter() {
        let (_, rekey_info, rekey_info_proof) = rekey_infos
            .iter()
            .find(|(system_id, _, _)| system_id == &system.system_id)
            .unwrap();
        let result = system.proved_distributed_rekey(
            &messages_data,
            &messages_rekey_infos,
            &enc_data,
            &rekey_info,
            rng,
        );
        messages_data.push((system.system_id.clone(), result.unwrap()));
        messages_rekey_infos.push((system.system_id.clone(), *rekey_info_proof));
    }

    let (dec_pseudo_2, enc_pseudo_2) = client_b
        .verified_decrypt_pseudonym(&messages_pseudo, &messages_pseudo_infos, &enc_pseudo)
        .unwrap();
    let (dec_data, _enc_data_2) = client_b
        .verified_decrypt_data(&messages_data, &messages_rekey_infos, &enc_data)
        .unwrap();

    assert_eq!(data, dec_data);
    assert_ne!(pseudonym, dec_pseudo_2);

    let rev_pseudo_infos = systems
        .iter()
        .map(|system| {
            let info = system.pseudonymization_info(&pc_b, &pc_a, &ec_b1, &ec_a1);
            let proof = system.pseudo_info_proof(&info, rng);
            (system.system_id.clone(), info, proof)
        })
        .collect::<Vec<_>>();

    let mut messages_rev_pseudo = Vec::new();
    let mut messages_rev_pseudo_infos = Vec::new();
    for system in systems.iter() {
        let (_, pseudo_info, pseudo_info_proof) = rev_pseudo_infos
            .iter()
            .find(|(system_id, _, _)| system_id == &system.system_id)
            .unwrap();
        let result = system.proved_distributed_pseudonymize(
            &messages_rev_pseudo,
            &messages_rev_pseudo_infos,
            &enc_pseudo_2,
            &pseudo_info,
            rng,
        );
        messages_rev_pseudo.push((system.system_id.clone(), result.unwrap()));
        messages_rev_pseudo_infos.push((system.system_id.clone(), *pseudo_info_proof));
    }
    let (rev_pseudo, _rev_enc_pseudo) = client_a
        .verified_decrypt_pseudonym(
            &messages_rev_pseudo,
            &messages_rev_pseudo_infos,
            &enc_pseudo_2,
        )
        .unwrap();
    assert_eq!(pseudonym, rev_pseudo);
}
