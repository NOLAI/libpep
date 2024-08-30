use rand_core::OsRng;
use libpep::arithmetic::{GroupElement};
use libpep::distributed::{BlindingFactor, make_blinded_global_secret_key, PEPClient, PEPSystem};
use libpep::high_level::{DataPoint, EncryptionContext, EncryptionSecret, make_global_keys, Pseudonym, PseudonymizationContext, PseudonymizationSecret};

#[test]
fn n_pep() {
    let n = 3;

    let (_global_public, global_secret) = make_global_keys();
    let blinding_factors = (0..n).map(|_| {BlindingFactor::random()}).collect::<Vec<_>>();
    let blinded_global_secret_key = make_blinded_global_secret_key(&global_secret, &blinding_factors.clone());

    let systems = (0..n).map(|i| {
        let pseudonymization_secret = PseudonymizationSecret(format!("secret-{}", i));
        let encryption_secret = EncryptionSecret(format!("secret-{}", i));
        let blinding_factor = blinding_factors[i].clone();
        PEPSystem::new(pseudonymization_secret, encryption_secret, blinding_factor)
    }).collect::<Vec<_>>();

    let pc_a = PseudonymizationContext("user-a".to_string());
    let pc_b = PseudonymizationContext("user-b".to_string());

    let ec_a1 = EncryptionContext("session-a1".to_string());
    let ec_b1 = EncryptionContext("session-b1".to_string());

    let sks_a1 = systems.iter().map(|system| system.session_key_share(&ec_a1)).collect::<Vec<_>>();
    let sks_b1 = systems.iter().map(|system| system.session_key_share(&ec_b1)).collect::<Vec<_>>();

    let client_a = PEPClient::new(blinded_global_secret_key.clone(), sks_a1);
    let client_b = PEPClient::new(blinded_global_secret_key.clone(), sks_b1);

    let pseudonym = Pseudonym::random();
    let data = DataPoint { value: GroupElement::random(&mut OsRng) };

    let enc_pseudo = client_a.encrypt_pseudonym(&pseudonym);
    let enc_data = client_a.encrypt_data(&data);

    let transcrypted_pseudo= systems.iter().fold(enc_pseudo.clone(), |acc, system| {
        system.pseudonymize(&acc, &pc_a, &pc_b, &ec_a1, &ec_b1)
    });

    let transcrypted_data= systems.iter().fold(enc_data.clone(), |acc, system| {
        system.rekey(&acc, &ec_a1, &ec_b1)
    });

    let dec_pseudo = client_b.decrypt_pseudonym(&transcrypted_pseudo);
    let dec_data = client_b.decrypt_data(&transcrypted_data);

    assert_eq!(data, dec_data);
    assert_ne!(pseudonym, dec_pseudo);

    let rev_pseudonymized = systems.iter().fold(transcrypted_pseudo.clone(), |acc, system| {
        system.pseudonymize(&acc, &pc_b, &pc_a, &ec_b1, &ec_a1)
    });

    let rev_dec_pseudo = client_a.decrypt_pseudonym(&rev_pseudonymized);
    assert_eq!(pseudonym, rev_dec_pseudo);
}

#[test]
fn n_pep_proved() {
    let n = 3;

    let (_global_public, global_secret) = make_global_keys();
    let blinding_factors = (0..n).map(|_| {BlindingFactor::random()}).collect::<Vec<_>>();
    let blinded_global_secret_key = make_blinded_global_secret_key(&global_secret, &blinding_factors.clone());

    let systems = (0..n).map(|i| {
        let pseudonymization_secret = PseudonymizationSecret(format!("secret-{}", i));
        let encryption_secret = EncryptionSecret(format!("secret-{}", i));
        let blinding_factor = blinding_factors[i].clone();
        PEPSystem::new(pseudonymization_secret, encryption_secret, blinding_factor)
    }).collect::<Vec<_>>();

    let pc_a = PseudonymizationContext("user-a".to_string());
    let pc_b = PseudonymizationContext("user-b".to_string());

    let ec_a1 = EncryptionContext("session-a1".to_string());
    let ec_b1 = EncryptionContext("session-b1".to_string());

    let sks_a1 = systems.iter().map(|system| system.session_key_share(&ec_a1)).collect::<Vec<_>>();
    let sks_b1 = systems.iter().map(|system| system.session_key_share(&ec_b1)).collect::<Vec<_>>();

    let client_a = PEPClient::new(blinded_global_secret_key.clone(), sks_a1);
    let client_b = PEPClient::new(blinded_global_secret_key.clone(), sks_b1);

    let pseudo_verifiers_a = systems.iter().map(|system| system.pseudo_verifiers(&pc_a).0).collect::<Vec<_>>();
    let rekey_verifiers_a1 = systems.iter().map(|system| system.rekey_verifiers(&ec_a1).0).collect::<Vec<_>>();
    let pseudo_verifiers_b = systems.iter().map(|system| system.pseudo_verifiers(&pc_b).0).collect::<Vec<_>>();
    let rekey_verifiers_b1 = systems.iter().map(|system| system.rekey_verifiers(&ec_b1).0).collect::<Vec<_>>();

    let pseudonym = Pseudonym::random();
    let data = DataPoint { value: GroupElement::random(&mut OsRng) };

    let enc_pseudo = client_a.encrypt_pseudonym(&pseudonym);
    let enc_data = client_a.encrypt_data(&data);

    let mut messages_pseudo = Vec::new();
    for system in systems.iter() {
        let result = system.proved_distributed_pseudonymize(&messages_pseudo, &enc_pseudo, &pseudo_verifiers_a, &pseudo_verifiers_b, &rekey_verifiers_a1, &rekey_verifiers_b1, &pc_a, &pc_b, &ec_a1, &ec_b1);
        messages_pseudo.push(result.unwrap());
    }

    let mut messages_data = Vec::new();
    for system in systems.iter() {
        let result = system.proved_distributed_rekey(&messages_data, &enc_data, &rekey_verifiers_a1, &rekey_verifiers_b1, &ec_a1, &ec_b1);
        messages_data.push(result.unwrap());
    }

    let dec_pseudo = client_b.verified_decrypt_pseudonym(&messages_pseudo, &enc_pseudo, &pseudo_verifiers_a, &pseudo_verifiers_b, &rekey_verifiers_a1, &rekey_verifiers_b1);
    let dec_data = client_b.verified_decrypt_data(&messages_data, &enc_data, &rekey_verifiers_a1, &rekey_verifiers_b1);

    assert!(dec_data.is_some());
    assert!(dec_pseudo.is_some());
    assert_eq!(data, dec_data.unwrap());
    assert_ne!(pseudonym, dec_pseudo.unwrap());
}
