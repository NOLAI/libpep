use libpep::distributed::key_blinding::{
    make_blinded_attribute_global_secret_key, make_blinded_pseudonym_global_secret_key,
    BlindingFactor, SafeScalar,
};
use libpep::distributed::systems::{PEPClient, PEPSystem};
use libpep::high_level::contexts::*;
use libpep::high_level::data_types::*;
use libpep::high_level::keys::*;
use libpep::high_level::secrets::{EncryptionSecret, PseudonymizationSecret};
use libpep::internal::arithmetic::ScalarNonZero;
use rand_core::OsRng;

#[test]
fn n_pep() {
    let n = 3;
    let rng = &mut OsRng;

    // Global config
    let (_pseudonym_global_public, pseudonym_global_secret) = make_pseudonym_global_keys(rng);
    let (_attribute_global_public, attribute_global_secret) = make_attribute_global_keys(rng);
    let blinding_factors = (0..n)
        .map(|_| BlindingFactor::random(rng))
        .collect::<Vec<_>>();
    let blinded_pseudonym_global_secret_key = make_blinded_pseudonym_global_secret_key(
        &pseudonym_global_secret,
        &blinding_factors.clone(),
    )
    .unwrap();
    let blinded_attribute_global_secret_key = make_blinded_attribute_global_secret_key(
        &attribute_global_secret,
        &blinding_factors.clone(),
    )
    .unwrap();

    assert_eq!(
        *blinded_pseudonym_global_secret_key.value(),
        pseudonym_global_secret.value()
            * blinding_factors
                .iter()
                .fold(ScalarNonZero::one(), |acc, x| acc * x.value().invert())
    );
    assert_eq!(
        *blinded_attribute_global_secret_key.value(),
        attribute_global_secret.value()
            * blinding_factors
                .iter()
                .fold(ScalarNonZero::one(), |acc, x| acc * x.value().invert())
    );

    // Create systems
    let systems = (0..n)
        .map(|i| {
            let pseudonymization_secret =
                PseudonymizationSecret::from(format!("ps-secret-{i}").as_bytes().into());
            let encryption_secret =
                EncryptionSecret::from(format!("es-secret-{i}").as_bytes().into());
            let blinding_factor = blinding_factors[i];
            PEPSystem::new(pseudonymization_secret, encryption_secret, blinding_factor)
        })
        .collect::<Vec<_>>();

    // Setup demo contexts
    let domain_a = PseudonymizationDomain::from("user-a");
    let domain_b = PseudonymizationDomain::from("user-b");

    let session_a1 = EncryptionContext::from("session-a1");
    let session_b1 = EncryptionContext::from("session-b1");

    // Get client session key shares using the new convenience method
    let sks_a1 = systems
        .iter()
        .map(|system| system.session_key_shares(&session_a1))
        .collect::<Vec<_>>();
    let sks_b1 = systems
        .iter()
        .map(|system| system.session_key_shares(&session_b1))
        .collect::<Vec<_>>();

    // Create clients using the new convenience constructor
    let client_a = PEPClient::from_session_key_shares(
        blinded_pseudonym_global_secret_key,
        blinded_attribute_global_secret_key,
        &sks_a1,
    );
    let client_b = PEPClient::from_session_key_shares(
        blinded_pseudonym_global_secret_key,
        blinded_attribute_global_secret_key,
        &sks_b1,
    );

    // Session walkthrough
    let pseudonym = Pseudonym::random(rng);
    let data = Attribute::random(rng);

    let enc_pseudo = client_a.encrypt_pseudonym(&pseudonym, rng);
    let enc_data = client_a.encrypt_attribute(&data, rng);

    let transcrypted_pseudo = systems.iter().fold(enc_pseudo, |acc, system| {
        let transcryption_info =
            system.transcryption_info(&domain_a, &domain_b, Some(&session_a1), Some(&session_b1));
        system.transcrypt(&acc, &transcryption_info)
    });

    let transcrypted_data = systems.iter().fold(enc_data, |acc, system| {
        let rekey_info = system.attribute_rekey_info(Some(&session_a1), Some(&session_b1));
        system.rekey(&acc, &rekey_info)
    });

    let dec_pseudo = client_b.decrypt_pseudonym(&transcrypted_pseudo);
    let dec_data = client_b.decrypt_attribute(&transcrypted_data);

    assert_eq!(data, dec_data);

    if domain_a == domain_b {
        assert_eq!(pseudonym, dec_pseudo);
    } else {
        assert_ne!(pseudonym, dec_pseudo);
    }

    let rev_pseudonymized = systems.iter().fold(transcrypted_pseudo, |acc, system| {
        let pseudo_info = system.pseudonymization_info(
            &domain_a,
            &domain_b,
            Some(&session_a1),
            Some(&session_b1),
        );
        system.pseudonymize(&acc, &pseudo_info.reverse())
    });

    let rev_dec_pseudo = client_a.decrypt_pseudonym(&rev_pseudonymized);
    assert_eq!(pseudonym, rev_dec_pseudo);
}
