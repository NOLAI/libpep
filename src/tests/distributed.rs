use crate::distributed::key_blinding::{make_blinded_global_secret_key, BlindingFactor};
use crate::distributed::systems::{PEPClient, PEPSystem};
use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::internal::arithmetic::ScalarNonZero;
use rand_core::OsRng;

#[test]
fn n_pep() {
    let n = 3;
    let rng = &mut OsRng;

    // Global config
    let (_global_public, global_secret) = make_global_encryption_keys(rng);
    let blinding_factors = (0..n)
        .map(|_| BlindingFactor::random(rng))
        .collect::<Vec<_>>();
    let blinded_global_secret_key =
        make_blinded_global_secret_key(&global_secret, &blinding_factors.clone()).unwrap();

    assert_eq!(
        blinded_global_secret_key.0,
        global_secret.0
            * blinding_factors
                .iter()
                .fold(ScalarNonZero::one(), |acc, x| acc * x.0.invert())
    );

    // Create systems
    let systems = (0..n)
        .map(|i| {
            let pseudonymization_secret =
                PseudonymizationSecret::from(format!("ps-secret-{}", i).as_bytes().into());
            let encryption_secret =
                EncryptionSecret::from(format!("es-secret-{}", i).as_bytes().into());
            let blinding_factor = blinding_factors[i].clone();
            PEPSystem::new(pseudonymization_secret, encryption_secret, blinding_factor)
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
    let client_a = PEPClient::new(blinded_global_secret_key.clone(), &sks_a1);
    let client_b = PEPClient::new(blinded_global_secret_key.clone(), &sks_b1);

    // Session walkthrough
    let pseudonym = Pseudonym::random(rng);
    let data = DataPoint::random(rng);

    let enc_pseudo = client_a.encrypt(&pseudonym, rng);
    let enc_data = client_a.encrypt(&data, rng);

    let transcrypted_pseudo = systems.iter().fold(enc_pseudo.clone(), |acc, system| {
        let pseudo_info = system.pseudonymization_info(&pc_a, &pc_b, &ec_a1, &ec_b1);
        system.transcrypt(&acc, &pseudo_info)
    });

    let transcrypted_data = systems.iter().fold(enc_data.clone(), |acc, system| {
        let rekey_info = system.rekey_info(&ec_a1, &ec_b1);
        system.rekey(&acc, &rekey_info)
    });

    let dec_pseudo = client_b.decrypt(&transcrypted_pseudo);
    let dec_data = client_b.decrypt(&transcrypted_data);

    assert_eq!(data, dec_data);
    assert_ne!(pseudonym, dec_pseudo);

    let rev_pseudonymized = systems
        .iter()
        .fold(transcrypted_pseudo.clone(), |acc, system| {
            let pseudo_info = system.pseudonymization_info(&pc_a, &pc_b, &ec_a1, &ec_b1);
            system.pseudonymize(&acc, &pseudo_info.reverse())
        });

    let rev_dec_pseudo = client_a.decrypt(&rev_pseudonymized);
    assert_eq!(pseudonym, rev_dec_pseudo);
}
