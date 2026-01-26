#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::client::{Client, Distributed};
use libpep::data::simple::*;
use libpep::factors::contexts::*;
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use libpep::transcryptor::DistributedTranscryptor;

#[test]
fn n_pep() {
    let n = 3;
    let rng = &mut rand::rng();

    // Global config - using the combined convenience method
    let (_global_public_keys, blinded_global_keys, blinding_factors) =
        libpep::keys::distribution::make_distributed_global_keys(n, rng);

    // Create systems
    let systems = (0..n)
        .map(|i| {
            let pseudonymization_secret =
                PseudonymizationSecret::from(format!("ps-secret-{i}").as_bytes().into());
            let encryption_secret =
                EncryptionSecret::from(format!("es-secret-{i}").as_bytes().into());
            let blinding_factor = blinding_factors[i];
            DistributedTranscryptor::new(
                pseudonymization_secret,
                encryption_secret,
                blinding_factor,
            )
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

    // Create clients using the distributed constructor
    let client_a = Client::from_shares(blinded_global_keys, &sks_a1);
    let client_b = Client::from_shares(blinded_global_keys, &sks_b1);

    // Session walkthrough
    let pseudonym = Pseudonym::random(rng);
    let data = Attribute::random(rng);

    let enc_pseudo = client_a.encrypt(&pseudonym, rng);
    let enc_data = client_a.encrypt(&data, rng);

    let transcrypted_pseudo = systems.iter().fold(enc_pseudo, |acc, system| {
        let transcryption_info =
            system.transcryption_info(&domain_a, &domain_b, &session_a1, &session_b1);
        system.transcrypt(&acc, &transcryption_info)
    });

    let transcrypted_data = systems.iter().fold(enc_data, |acc, system| {
        let rekey_info = system.attribute_rekey_info(&session_a1, &session_b1);
        system.rekey(&acc, &rekey_info)
    });

    #[cfg(feature = "elgamal3")]
    let dec_pseudo = client_b
        .decrypt(&transcrypted_pseudo)
        .expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let dec_pseudo = client_b.decrypt(&transcrypted_pseudo);
    #[cfg(feature = "elgamal3")]
    let dec_data = client_b
        .decrypt(&transcrypted_data)
        .expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let dec_data = client_b.decrypt(&transcrypted_data);

    assert_eq!(data, dec_data);

    if domain_a == domain_b {
        assert_eq!(pseudonym, dec_pseudo);
    } else {
        assert_ne!(pseudonym, dec_pseudo);
    }

    let rev_pseudonymized = systems.iter().fold(transcrypted_pseudo, |acc, system| {
        let pseudo_info =
            system.pseudonymization_info(&domain_a, &domain_b, &session_a1, &session_b1);
        system.pseudonymize(&acc, &pseudo_info.reverse())
    });

    #[cfg(feature = "elgamal3")]
    let rev_dec_pseudo = client_a
        .decrypt(&rev_pseudonymized)
        .expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let rev_dec_pseudo = client_a.decrypt(&rev_pseudonymized);
    assert_eq!(pseudonym, rev_dec_pseudo);
}
