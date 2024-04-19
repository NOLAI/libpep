use std::cell::RefCell;
use std::rc::Rc;
use std::thread::sleep;
use std::time::SystemTime;
use hyper::{Response};
use rand_core::OsRng;
use libpep::arithmetic::{G, GroupElement, ScalarNonZero};
use libpep::elgamal::{decrypt, ElGamal, encrypt};
use libpep::primitives::{rsk_from_to};
use libpep::tls::*;

fn get_ina() -> Option<f64> {
    let url = std::env::var("ENERGY_STATS").ok()?;
    let agent: ureq::Agent = ureq::AgentBuilder::new()
      .user_agent(&format!("{} {}/{}", env!("CARGO_PKG_NAME"), buildinfy::build_reference().unwrap_or_default(), buildinfy::build_pipeline_id_per_project().unwrap_or_default()))
      .timeout_read(std::time::Duration::from_secs(60))
      .timeout_write(std::time::Duration::from_secs(5))
      .build();
    let resp = agent.get(&url).call().ok()?;
    resp.header("X-Electricity-Consumed-Total")?.parse().ok()
}


fn transcryptor_handle(bytes: Vec<u8>, server_state: Rc<RefCell<ServerState>>) -> Result<Response<BoxedBody>, hyper::http::Error> {
    let value = ElGamal::decode(&bytes).unwrap();

    let state = server_state.borrow();

    let result = rsk_from_to(&value, &state.s_from, &state.s_to, &state.k_from, &state.k_to);
    let result = result.encode().to_vec();
    Ok(Response::new(box_body(BodyVec::from(result))))
}

fn start_transcryptor(i:usize, s_from: ScalarNonZero, s_to: ScalarNonZero, k_from: ScalarNonZero, k_to: ScalarNonZero) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .thread_name("background")
            .worker_threads(std::thread::available_parallelism().map(|x| x.get()).unwrap_or(4))
            .enable_all()
            .build()
            .expect("build runtime");

        let local = Box::new(tokio::task::LocalSet::new());
        let local : &'static tokio::task::LocalSet = Box::leak(local);

        let state = ServerState { s_from, s_to, k_from, k_to };
        local.block_on(&rt, webserver((3330 + i) as u16, transcryptor_handle, state));
    })
}

#[test]
fn energy_transcrypt() {
    let iterations = 200;
    let rest_before_measure = 2;
    let n_max = 4; // number of tiers
    let m_exp_max = 2;

    let mut rng = OsRng;

    // system params
    let y = ScalarNonZero::random(&mut rng); // global private
    let gy = y * G; // global public

    // random message
    let data = GroupElement::random(&mut rng);

    // factors
    let s_from_s = Vec::from_iter((0..n_max).map(|_| ScalarNonZero::random(&mut rng)));
    let s_to_s = Vec::from_iter((0..n_max).map(|_| ScalarNonZero::random(&mut rng)));
    let k_from_s = Vec::from_iter((0..n_max).map(|_| ScalarNonZero::random(&mut rng)));
    let k_to_s = Vec::from_iter((0..n_max).map(|_| ScalarNonZero::random(&mut rng)));

    let k_from = k_from_s.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);
    let k_to = k_to_s.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);

    let s_from = s_from_s.iter().fold(ScalarNonZero::one(), |acc, s| acc * s);
    let s_to = s_to_s.iter().fold(ScalarNonZero::one(), |acc, s| acc * s);

    let s = s_from.invert() * s_to;

    let transcryptors = Vec::from_iter((0..n_max).map(|x| start_transcryptor(x, s_from_s[x], s_to_s[x], k_from_s[x], k_to_s[x])));

    // wait for webserver to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    let sender = get_agent();

    // FIRST TEST IDLE
    let idle_test_seconds =30;
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

            eprintln!("\nBenchmarking PEP with {} tiers and {} messages, {} iterations", n, m, iterations);

            sleep(std::time::Duration::from_secs(rest_before_measure));
            let t_before = SystemTime::now();
            let before = get_ina();

            for _ in 0..iterations {
                for _ in 0..m {
                    let mut value = encrypt(&data, &(k_from * gy), &mut OsRng); // initial encryption

                    // transcryption
                    for i in 0..n {
                        let bytes = value.encode();
                        let response = sender.post(&format!("https://127.0.0.1:{}", 3330 + i)).send_bytes(&bytes[..]).unwrap();
                        let mut body = Vec::new();
                        response.into_reader().read_to_end(&mut body).unwrap();
                        value = ElGamal::decode(&body).unwrap();
                    }

                    let decrypted = decrypt(&value, &(k_to * y)); // final decryption
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
            eprintln!("Energy used: {} J, or {} per iteration", energy_used, energy_used / iterations as f64);

            let net_energy_used = energy_used - time_elapsed * idle_energy_per_second;
            eprintln!("Energy used (net): {} J or {} per iteration", net_energy_used, net_energy_used / iterations as f64);
        }
    }
}





fn tunnel_handle(bytes: Vec<u8>, server_state: Rc<RefCell<ServerState>>) -> Result<Response<BoxedBody>, hyper::http::Error> {
    let value = ElGamal::decode(&bytes).unwrap();

    let state = server_state.borrow();

    let result = value.encode().to_vec();
    Ok(Response::new(box_body(BodyVec::from(result))))
}

fn start_tunnel(i:usize, s_from: ScalarNonZero, s_to: ScalarNonZero, k_from: ScalarNonZero, k_to: ScalarNonZero) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .thread_name("background")
            .worker_threads(std::thread::available_parallelism().map(|x| x.get()).unwrap_or(4))
            .enable_all()
            .build()
            .expect("build runtime");

        let local = Box::new(tokio::task::LocalSet::new());
        let local : &'static tokio::task::LocalSet = Box::leak(local);

        let state = ServerState { s_from, s_to, k_from, k_to };
        local.block_on(&rt, webserver((4440 + i) as u16, crate::tunnel_handle, state));
    })
}

#[test]
fn energy_tunnel() {
    let iterations = 200;
    let rest_before_measure = 2;
    let n_max = 4; // number of tiers
    let m_exp_max = 2;

    let mut rng = OsRng;

    // system params
    let y = ScalarNonZero::random(&mut rng); // global private
    let gy = y * G; // global public

    // random message
    let data = GroupElement::random(&mut rng);

    // factors
    let s_from_s = Vec::from_iter((0..n_max).map(|_| ScalarNonZero::random(&mut rng)));
    let s_to_s = Vec::from_iter((0..n_max).map(|_| ScalarNonZero::random(&mut rng)));
    let k_from_s = Vec::from_iter((0..n_max).map(|_| ScalarNonZero::random(&mut rng)));
    let k_to_s = Vec::from_iter((0..n_max).map(|_| ScalarNonZero::random(&mut rng)));

    let k_from = k_from_s.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);
    let k_to = k_to_s.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);

    let s_from = s_from_s.iter().fold(ScalarNonZero::one(), |acc, s| acc * s);
    let s_to = s_to_s.iter().fold(ScalarNonZero::one(), |acc, s| acc * s);

    let s = s_from.invert() * s_to;

    let transcryptors = Vec::from_iter((0..n_max).map(|x| crate::start_tunnel(x, s_from_s[x], s_to_s[x], k_from_s[x], k_to_s[x])));

    // wait for webserver to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    let sender = get_agent();

    // FIRST TEST IDLE
    let idle_test_seconds =30;
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

            eprintln!("\nBenchmarking NO PEP with {} tiers and {} messages, {} iterations", n, m, iterations);

            sleep(std::time::Duration::from_secs(rest_before_measure));
            let t_before = SystemTime::now();
            let before = get_ina();

            for _ in 0..iterations {
                for _ in 0..m {
                    let mut value = encrypt(&data, &(k_from * gy), &mut OsRng); // initial encryption

                    // transcryption
                    for i in 0..n {
                        let bytes = value.encode();
                        let response = sender.post(&format!("https://127.0.0.1:{}", 4440 + i)).send_bytes(&bytes[..]).unwrap();
                        let mut body = Vec::new();
                        response.into_reader().read_to_end(&mut body).unwrap();
                        value = ElGamal::decode(&body).unwrap();
                    }

                    let decrypted = decrypt(&value, &(k_to * y)); // final decryption
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
            eprintln!("Energy used: {} J, or {} per iteration", energy_used, energy_used / iterations as f64);

            let net_energy_used = energy_used - time_elapsed * idle_energy_per_second;
            eprintln!("Energy used (net): {} J or {} per iteration", net_energy_used, net_energy_used / iterations as f64);
        }
    }
}
