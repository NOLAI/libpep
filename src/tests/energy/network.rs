use crate::high_level::contexts::{
    EncryptionContext, PseudonymizationContext, PseudonymizationInfo,
};
use crate::high_level::data_types::{Encrypted, EncryptedPseudonym, Pseudonym};
use crate::high_level::keys::{
    make_global_keys, make_session_keys, EncryptionSecret, PseudonymizationSecret,
};
use crate::high_level::ops::{decrypt, encrypt, transcrypt};
use crate::internal::arithmetic::{ScalarNonZero, G};
use crate::tests::energy::utils::ina::get_ina;
use crate::tests::energy::utils::tls::*;
use hyper::Response;
use rand_core::OsRng;
use std::cell::RefCell;
use std::rc::Rc;
use std::thread::sleep;
use std::time::SystemTime;

fn transcryptor_handle(
    bytes: Vec<u8>,
    server_state: Rc<RefCell<PseudonymizationInfo>>,
) -> Result<Response<BoxedBody>, hyper::http::Error> {
    let value = EncryptedPseudonym::decode_from_slice(&bytes).unwrap();

    let state = server_state.borrow();

    let result = transcrypt(&value, &state);
    let result = result.encode().to_vec();
    Ok(Response::new(box_body(BodyVec::from(result))))
}

fn start_transcryptor(
    i: usize,
    pseudonymization_info: PseudonymizationInfo,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .thread_name("background")
            .worker_threads(
                std::thread::available_parallelism()
                    .map(|x| x.get())
                    .unwrap_or(4),
            )
            .enable_all()
            .build()
            .expect("build runtime");

        let local = Box::new(tokio::task::LocalSet::new());
        let local: &'static tokio::task::LocalSet = Box::leak(local);

        local.block_on(
            &rt,
            webserver(
                (3330 + i) as u16,
                transcryptor_handle,
                pseudonymization_info,
            ),
        );
    })
}

#[test]
fn energy_transcrypt() {
    let iterations = 1000;
    let rest_before_measure = 2;
    let n_max = 4; // number of tiers
    let m_exp_max = 2;

    let mut rng = OsRng;

    // system params
    let y = ScalarNonZero::random(&mut rng); // global private
    let _gy = y * G; // global public

    // random message
    let data = Pseudonym::random(&mut rng);

    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let pseudo_context1 = PseudonymizationContext::from("context1");
    let enc_context1 = EncryptionContext::from("session1");
    let pseudo_context2 = PseudonymizationContext::from("context2");
    let enc_context2 = EncryptionContext::from("session2");

    let (session1_public, _session1_secret) =
        make_session_keys(&global_secret, &enc_context1, &enc_secret);
    let (_session2_public, session2_secret) =
        make_session_keys(&global_secret, &enc_context2, &enc_secret);

    let pseudo_info = PseudonymizationInfo::new(
        &pseudo_context1,
        &pseudo_context2,
        &enc_context1,
        &enc_context2,
        &pseudo_secret,
        &enc_secret,
    );

    let _transcryptors =
        Vec::from_iter((0..n_max).map(|x| start_transcryptor(x, pseudo_info.clone())));

    // wait for webserver to start
    sleep(std::time::Duration::from_secs(1));

    let sender = get_agent();

    // FIRST TEST IDLE
    let idle_test_seconds = 30;
    let millis = std::time::Duration::from_millis(idle_test_seconds * 1000);

    sleep(std::time::Duration::from_secs(rest_before_measure));

    let before = get_ina();
    sleep(millis);
    let after = get_ina();

    let mut idle_energy = 0.0;
    let mut idle_energy_per_second = 0.0;

    if !(before.is_none() || after.is_none()) {
        idle_energy = after.unwrap() - before.unwrap();
        idle_energy_per_second = idle_energy / idle_test_seconds as f64;
    }

    // START BENCHMARK
    for n in 1..=n_max {
        for exp in 0..m_exp_max {
            let m = 10u64.pow(exp as u32) as usize;

            eprintln!(
                "\nBenchmarking PEP with {} tiers and {} messages, {} iterations",
                n, m, iterations
            );

            sleep(std::time::Duration::from_secs(rest_before_measure));
            let t_before = SystemTime::now();
            let before = get_ina();

            for _ in 0..iterations {
                for _ in 0..m {
                    let mut value = encrypt(&data, &session1_public, &mut OsRng); // initial encryption

                    // transcryption
                    for i in 0..n {
                        let bytes = value.encode();
                        let response = sender
                            .post(&format!("https://127.0.0.1:{}", 3330 + i))
                            .send_bytes(&bytes[..])
                            .unwrap();
                        let mut body = Vec::new();
                        response.into_reader().read_to_end(&mut body).unwrap();
                        value = EncryptedPseudonym::decode_from_slice(&body).unwrap();
                    }

                    let _decrypted = decrypt(&value, &session2_secret); // final decryption
                                                                        // debug_assert_eq!(s * data, decrypted); This doesnt hold anymore
                }
            }
            // END BENCHMARK
            let after = get_ina();

            let t_after = SystemTime::now();

            let time_elapsed = t_after.duration_since(t_before).unwrap().as_secs_f64();
            if before.is_none() || after.is_none() {
                continue;
            }
            let energy_used = after.unwrap() - before.unwrap();

            eprintln!("Time elapsed: {} s", time_elapsed);
            eprintln!(
                "Energy used: {} J, or {} per iteration",
                energy_used,
                energy_used / iterations as f64
            );

            let net_energy_used = energy_used - time_elapsed * idle_energy_per_second;
            eprintln!(
                "Energy used (net): {} J or {} per iteration",
                net_energy_used,
                net_energy_used / iterations as f64
            );
        }
    }
}

fn tunnel_handle(
    bytes: Vec<u8>,
    server_state: Rc<RefCell<PseudonymizationInfo>>,
) -> Result<Response<BoxedBody>, hyper::http::Error> {
    let value = EncryptedPseudonym::decode_from_slice(&bytes).unwrap();

    let _state = server_state.borrow();

    let result = value.encode().to_vec();
    Ok(Response::new(box_body(BodyVec::from(result))))
}

fn start_tunnel(
    i: usize,
    pseudonymization_info: PseudonymizationInfo,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .thread_name("background")
            .worker_threads(
                std::thread::available_parallelism()
                    .map(|x| x.get())
                    .unwrap_or(4),
            )
            .enable_all()
            .build()
            .expect("build runtime");

        let local = Box::new(tokio::task::LocalSet::new());
        let local: &'static tokio::task::LocalSet = Box::leak(local);

        local.block_on(
            &rt,
            webserver((4440 + i) as u16, tunnel_handle, pseudonymization_info),
        );
    })
}

#[test]
fn energy_tunnel() {
    let iterations = 1000;
    let rest_before_measure = 2;
    let n_max = 4; // number of tiers
    let m_exp_max = 2;

    let mut rng = OsRng;

    // system params
    let y = ScalarNonZero::random(&mut rng); // global private
    let _gy = y * G; // global public

    // random message
    let data = Pseudonym::random(&mut rng);

    // factors
    let (_global_public, global_secret) = make_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("secret".into());
    let enc_secret = EncryptionSecret::from("secret".into());

    let pseudo_context1 = PseudonymizationContext::from("context1");
    let enc_context1 = EncryptionContext::from("session1");
    let pseudo_context2 = PseudonymizationContext::from("context2");
    let enc_context2 = EncryptionContext::from("session2");

    let (session1_public, _session1_secret) =
        make_session_keys(&global_secret, &enc_context1, &enc_secret);
    let (_session2_public, session2_secret) =
        make_session_keys(&global_secret, &enc_context2, &enc_secret);

    let pseudo_info = PseudonymizationInfo::new(
        &pseudo_context1,
        &pseudo_context2,
        &enc_context1,
        &enc_context2,
        &pseudo_secret,
        &enc_secret,
    );

    let _transcryptors = Vec::from_iter((0..n_max).map(|x| start_tunnel(x, pseudo_info)));

    // wait for webserver to start
    sleep(std::time::Duration::from_secs(1));

    let sender = get_agent();

    // FIRST TEST IDLE
    let idle_test_seconds = 30;
    let millis = std::time::Duration::from_millis(idle_test_seconds * 1000);

    sleep(std::time::Duration::from_secs(rest_before_measure));

    let before = get_ina();
    sleep(millis);
    let after = get_ina();

    let mut idle_energy = 0.0;
    let mut idle_energy_per_second = 0.0;

    if !(before.is_none() || after.is_none()) {
        idle_energy = after.unwrap() - before.unwrap();
        idle_energy_per_second = idle_energy / idle_test_seconds as f64;
    }

    // START BENCHMARK
    for n in 1..=n_max {
        for exp in 0..m_exp_max {
            let m = 10u64.pow(exp as u32) as usize;

            eprintln!(
                "\nBenchmarking NO PEP with {} tiers and {} messages, {} iterations",
                n, m, iterations
            );

            sleep(std::time::Duration::from_secs(rest_before_measure));
            let t_before = SystemTime::now();
            let before = get_ina();

            for _ in 0..iterations {
                for _ in 0..m {
                    let mut value = encrypt(&data, &session1_public, &mut OsRng); // initial encryption

                    // transcryption
                    for i in 0..n {
                        let bytes = value.encode();
                        let response = sender
                            .post(&format!("https://127.0.0.1:{}", 4440 + i))
                            .send_bytes(&bytes[..])
                            .unwrap();
                        let mut body = Vec::new();
                        response.into_reader().read_to_end(&mut body).unwrap();
                        value = EncryptedPseudonym::decode_from_slice(&body).unwrap();
                    }

                    let _decrypted = decrypt(&value, &session2_secret); // final decryption
                                                                        // debug_assert_eq!(s * data, decrypted); This doesnt hold anymore
                }
            }
            // END BENCHMARK
            let after = get_ina();

            let t_after = SystemTime::now();

            let time_elapsed = t_after.duration_since(t_before).unwrap().as_secs_f64();
            if before.is_none() || after.is_none() {
                continue;
            }
            let energy_used = after.unwrap() - before.unwrap();

            eprintln!("Time elapsed: {} s", time_elapsed);
            eprintln!(
                "Energy used: {} J, or {} per iteration",
                energy_used,
                energy_used / iterations as f64
            );

            let net_energy_used = energy_used - time_elapsed * idle_energy_per_second;
            eprintln!(
                "Energy used (net): {} J or {} per iteration",
                net_energy_used,
                net_energy_used / iterations as f64
            );
        }
    }
}
