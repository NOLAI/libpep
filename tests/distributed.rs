#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::client::{Client, Distributed};
use libpep::data::simple::*;
use libpep::factors::contexts::*;
#[cfg(not(feature = "elgamal3"))]
use libpep::factors::RekeyFactor;
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
#[cfg(not(feature = "elgamal3"))]
use libpep::keys::PublicKey;
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

    #[cfg(feature = "elgamal3")]
    let transcrypted_pseudo = systems.iter().fold(enc_pseudo, |acc, system| {
        let transcryption_info =
            system.transcryption_info(&domain_a, &domain_b, &session_a1, &session_b1);
        system.transcrypt(&acc, &transcryption_info, rng)
    });
    #[cfg(not(feature = "elgamal3"))]
    let transcrypted_pseudo = {
        // For each system step, the rerandomize sub-step needs the recipient public key
        // the ciphertext is currently encrypted under. After rekey by k_i the pk is k_i * pk.
        let initial_pk = *client_a.dump().pseudonym.public.value();
        let (transcrypted, _final_pk) =
            systems
                .iter()
                .fold((enc_pseudo, initial_pk), |(acc, current_pk), system| {
                    let transcryption_info =
                        system.transcryption_info(&domain_a, &domain_b, &session_a1, &session_b1);
                    let k = transcryption_info.pseudonym.k.scalar();
                    let pseudonym_pk = libpep::keys::PseudonymSessionPublicKey::from(current_pk);
                    let next = system.transcrypt(&acc, &transcryption_info, &pseudonym_pk, rng);
                    let next_pk = k * current_pk;
                    (next, next_pk)
                });
        transcrypted
    };

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

    #[cfg(feature = "elgamal3")]
    let rev_pseudonymized = systems.iter().fold(transcrypted_pseudo, |acc, system| {
        let pseudo_info =
            system.pseudonymization_info(&domain_a, &domain_b, &session_a1, &session_b1);
        system.pseudonymize(&acc, &pseudo_info.reverse(), rng)
    });
    #[cfg(not(feature = "elgamal3"))]
    let rev_pseudonymized = {
        // After the forward chain the pseudonym is now encrypted under client_b's pk.
        let initial_pk = *client_b.dump().pseudonym.public.value();
        let (rev, _final_pk) = systems.iter().fold(
            (transcrypted_pseudo, initial_pk),
            |(acc, current_pk), system| {
                let pseudo_info =
                    system.pseudonymization_info(&domain_a, &domain_b, &session_a1, &session_b1);
                let reversed = pseudo_info.reverse();
                let k = reversed.k.scalar();
                let pseudonym_pk = libpep::keys::PseudonymSessionPublicKey::from(current_pk);
                let next = system.pseudonymize(&acc, &reversed, &pseudonym_pk, rng);
                let next_pk = k * current_pk;
                (next, next_pk)
            },
        );
        rev
    };

    #[cfg(feature = "elgamal3")]
    let rev_dec_pseudo = client_a
        .decrypt(&rev_pseudonymized)
        .expect("decryption should succeed");
    #[cfg(not(feature = "elgamal3"))]
    let rev_dec_pseudo = client_a.decrypt(&rev_pseudonymized);
    assert_eq!(pseudonym, rev_dec_pseudo);
}

/// Confirm that distributed batch transcryption works end-to-end through
/// [`EncryptedBatch`], with the batch-level `Y` (the recipient session
/// public key) updated in lockstep with each transcryptor's rekey factor in
/// elgamal2 mode.
#[test]
#[cfg(all(feature = "batch", feature = "batch-pk"))]
fn n_pep_batch_distributed() {
    use libpep::data::batch::EncryptedBatch;

    let n = 3;
    let rng = &mut rand::rng();

    let (_global_public_keys, blinded_global_keys, blinding_factors) =
        libpep::keys::distribution::make_distributed_global_keys(n, rng);

    let systems = (0..n)
        .map(|i| {
            DistributedTranscryptor::new(
                PseudonymizationSecret::from(format!("ps-{i}").as_bytes().into()),
                EncryptionSecret::from(format!("es-{i}").as_bytes().into()),
                blinding_factors[i],
            )
        })
        .collect::<Vec<_>>();

    let domain_a = PseudonymizationDomain::from("a");
    let domain_b = PseudonymizationDomain::from("b");
    let session_a = EncryptionContext::from("sa");
    let session_b = EncryptionContext::from("sb");

    let sks_a = systems
        .iter()
        .map(|s| s.session_key_shares(&session_a))
        .collect::<Vec<_>>();
    let sks_b = systems
        .iter()
        .map(|s| s.session_key_shares(&session_b))
        .collect::<Vec<_>>();

    let client_a = Client::from_shares(blinded_global_keys, &sks_a);
    let client_b = Client::from_shares(blinded_global_keys, &sks_b);

    let pseudonyms: Vec<Pseudonym> = (0..5).map(|_| Pseudonym::random(rng)).collect();
    let mut batch: EncryptedBatch<EncryptedPseudonym> = client_a
        .encrypt_batch(&pseudonyms, rng)
        .expect("encrypt batch");

    // The new API: per-message `current_pk` tracking is gone, the batch
    // updates its `public_key` field in lockstep with the rekey factor.
    for system in &systems {
        let info = system.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
        batch.transcrypt(&info, rng).expect("transcrypt batch");
    }

    let decrypted = client_b
        .decrypt_batch(batch.as_items())
        .expect("decrypt batch");
    assert_eq!(decrypted.len(), pseudonyms.len());
}
