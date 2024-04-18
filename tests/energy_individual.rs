use std::thread::sleep;
use std::time::SystemTime;
use rand_core::OsRng;
use libpep::arithmetic::{G, GroupElement, ScalarNonZero};
use libpep::elgamal::encrypt;
use libpep::primitives::{rekey, rekey_from_to, rerandomize, reshuffle, reshuffle_from_to, rsk, rsk_from_to};

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

fn energy_idle(seconds:u64, rest_before_measure:u64) -> f64 {
    let millis = std::time::Duration::from_millis(seconds * 1000);

    sleep(std::time::Duration::from_secs(rest_before_measure));
    let before = get_ina();
    sleep(millis);
    let after = get_ina();

    if before.is_none() || after.is_none() {
        return 0.0;
    }
    return after.unwrap() - before.unwrap();
}

fn energy_pep_rerandomize(iterations: i32, rest_before_measure:u64) -> (f64, f64) {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let r = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &gy, &mut OsRng);

    sleep(std::time::Duration::from_secs(rest_before_measure));
    let t_before = SystemTime::now();
    let before = get_ina();
    for _ in 0..iterations {
        let _ = rerandomize(&encrypted, &r);
    }

    let after = get_ina();
    let t_after = SystemTime::now();

    let time_elapsed = t_after.duration_since(t_before).unwrap().as_secs_f64();
    if before.is_none() || after.is_none() {
        return (0.0, 0.0);
    }
    let energy_used = after.unwrap() - before.unwrap();
    (energy_used, time_elapsed)
}

fn energy_pep_rekey(iterations: i32, rest_before_measure:u64) -> (f64, f64) {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let k = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &gy, &mut OsRng);

    sleep(std::time::Duration::from_secs(rest_before_measure));
    let t_before = SystemTime::now();
    let before = get_ina();
    for _ in 0..iterations {
        let _ = rekey(&encrypted, &k);
    }

    let after = get_ina();
    let t_after = SystemTime::now();

    let time_elapsed = t_after.duration_since(t_before).unwrap().as_secs_f64();
    if before.is_none() || after.is_none() {
        return (0.0, 0.0);
    }
    let energy_used = after.unwrap() - before.unwrap();
    (energy_used, time_elapsed)
}


fn energy_pep_reshuffle(iterations: i32, rest_before_measure:u64) -> (f64,f64) {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let s = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &gy, &mut OsRng);

    sleep(std::time::Duration::from_secs(rest_before_measure));
    let t_before = SystemTime::now();
    let before = get_ina();

    for _ in 0..iterations {
        let _ = reshuffle(&encrypted, &s);
    }

    let after = get_ina();
    let t_after = SystemTime::now();

    let time_elapsed = t_after.duration_since(t_before).unwrap().as_secs_f64();
    if before.is_none() || after.is_none() {
        return (0.0, 0.0);
    }
    let energy_used = after.unwrap() - before.unwrap();
    (energy_used, time_elapsed)
}

fn energy_pep_rsk(iterations: i32, rest_before_measure:u64) -> (f64,f64) {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let k = ScalarNonZero::random(&mut rng);
    let s = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &gy, &mut OsRng);

    sleep(std::time::Duration::from_secs(rest_before_measure));
    let t_before = SystemTime::now();
    let before = get_ina();

    for _ in 0..iterations {
        let _ = rsk(&encrypted, &s, &k);
    }

    let after = get_ina();
    let t_after = SystemTime::now();

    let time_elapsed = t_after.duration_since(t_before).unwrap().as_secs_f64();
    if before.is_none() || after.is_none() {
        return (0.0, 0.0);
    }
    let energy_used = after.unwrap() - before.unwrap();
    (energy_used, time_elapsed)
}

fn energy_pep_rekey_from_to(iterations: i32, rest_before_measure:u64) -> (f64,f64) {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let k_from = ScalarNonZero::random(&mut rng);
    let k_to = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &(k_from*gy), &mut OsRng);

    sleep(std::time::Duration::from_secs(rest_before_measure));
    let t_before = SystemTime::now();
    let before = get_ina();

    for _ in 0..iterations {
        let _ = rekey_from_to(&encrypted, &k_from, &k_to);
    }

    let after = get_ina();
    let t_after = SystemTime::now();

    let time_elapsed = t_after.duration_since(t_before).unwrap().as_secs_f64();
    if before.is_none() || after.is_none() {
        return (0.0, 0.0);
    }
    let energy_used = after.unwrap() - before.unwrap();
    (energy_used, time_elapsed)
}

fn energy_pep_reshuffle_from_to(iterations: i32, rest_before_measure:u64) -> (f64,f64) {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let s_from = ScalarNonZero::random(&mut rng);
    let s_to = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &gy, &mut OsRng);

    sleep(std::time::Duration::from_secs(rest_before_measure));
    let t_before = SystemTime::now();
    let before = get_ina();

    for _ in 0..iterations {
        let _ = reshuffle_from_to(&encrypted, &s_from, &s_to);
    }

    let after = get_ina();
    let t_after = SystemTime::now();

    let time_elapsed = t_after.duration_since(t_before).unwrap().as_secs_f64();
    if before.is_none() || after.is_none() {
        return (0.0, 0.0);
    }
    let energy_used = after.unwrap() - before.unwrap();
    (energy_used, time_elapsed)
}

fn energy_pep_rsk_from_to(iterations: i32, rest_before_measure:u64) -> (f64,f64) {
    let mut rng = OsRng;

    // secret key
    let y = ScalarNonZero::random(&mut rng);
    // public key
    let gy = y * G;

    let s_from = ScalarNonZero::random(&mut rng);
    let s_to = ScalarNonZero::random(&mut rng);
    let k_from = ScalarNonZero::random(&mut rng);
    let k_to = ScalarNonZero::random(&mut rng);

    // choose a random value to encrypt
    let m = GroupElement::random(&mut rng);

    // encrypt/decrypt this value
    let encrypted = encrypt(&m, &(k_from*gy), &mut OsRng);

    sleep(std::time::Duration::from_secs(rest_before_measure));
    let t_before = SystemTime::now();
    let before = get_ina();


    for _ in 0..iterations {
        let _ = rsk_from_to(&encrypted, &s_from, &s_to, &k_from, &k_to);
    }

    let after = get_ina();
    let t_after = SystemTime::now();

    let time_elapsed = t_after.duration_since(t_before).unwrap().as_secs_f64();
    if before.is_none() || after.is_none() {
        return (0.0, 0.0);
    }
    let energy_used = after.unwrap() - before.unwrap();
    (energy_used, time_elapsed)
}

#[test]
fn energy_individual_operations() {
    let iterations = 100000;
    let time_per_iteration_estimate = 0.0003; // 100000 is approx 30 seconds
    let rest_before_measure = 2;

    eprintln!("Running individual energy measurements for {} iterations", iterations);
    eprintln!("Resting for {} seconds before each measurement", rest_before_measure);

    let approx_time_seconds = iterations as f64 * time_per_iteration_estimate;
    eprintln!("Approximate time per measurement: {} seconds", approx_time_seconds);

    let idle_energy = energy_idle(approx_time_seconds as u64, rest_before_measure);
    let idle_energy_per_second = idle_energy / approx_time_seconds;
    eprintln!("Idle energy: {} J or {} J/s", idle_energy, idle_energy_per_second);

    let (energy_rekey, time_rekey) = energy_pep_rekey(iterations, rest_before_measure);
    let energy_rekey_net = energy_rekey - (idle_energy_per_second * time_rekey);
    eprintln!("Rekey energy: {} J total in {} seconds", energy_rekey, time_rekey);
    eprintln!("Rekey energy net: {} J", energy_rekey_net);
    eprintln!("Rekey energy net per iteration: {} J", energy_rekey_net / iterations as f64);

    let (energy_reshuffle, time_reshuffle) = energy_pep_reshuffle(iterations, rest_before_measure);
    let energy_reshuffle_net = energy_reshuffle - (idle_energy_per_second * time_reshuffle);
    eprintln!("Reshuffle energy: {} J total in {} seconds", energy_reshuffle, time_reshuffle);
    eprintln!("Reshuffle energy net: {} J", energy_reshuffle_net);
    eprintln!("Reshuffle energy net per iteration: {} J", energy_reshuffle_net / iterations as f64);

    let (energy_rerandomize, time_rerandomize) = energy_pep_rerandomize(iterations, rest_before_measure);
    let energy_rerandomize_net = energy_rerandomize - (idle_energy_per_second * time_rerandomize);
    eprintln!("Rerandomize energy: {} J total in {} seconds", energy_rerandomize, time_rerandomize);
    eprintln!("Rerandomize energy net: {} J", energy_rerandomize_net);
    eprintln!("Rerandomize energy net per iteration: {} J", energy_rerandomize_net / iterations as f64);

    let (energy_rsk, time_rsk) = energy_pep_rsk(iterations, rest_before_measure);
    let energy_rsk_net = energy_rsk - (idle_energy_per_second * time_rsk);
    eprintln!("RSK energy: {} J total in {} seconds", energy_rsk, time_rsk);
    eprintln!("RSK energy net: {} J", energy_rsk_net);
    eprintln!("RSK energy net per iteration: {} J", energy_rsk_net / iterations as f64);

    let (energy_rekey_from_to, time_rekey_from_to) = energy_pep_rekey_from_to(iterations, rest_before_measure);
    let energy_rk2_net = energy_rekey_from_to - (idle_energy_per_second * time_rekey_from_to);
    eprintln!("RK2 energy: {} J total in {} seconds", energy_rekey_from_to, time_rekey_from_to);
    eprintln!("RK2 energy net: {} J", energy_rk2_net);
    eprintln!("RK2 energy net per iteration: {} J", energy_rk2_net / iterations as f64);

    let (energy_reshuffle_from_to, time_reshuffle_from_to) = energy_pep_reshuffle_from_to(iterations, rest_before_measure);
    let energy_rs2_net = energy_reshuffle_from_to - (idle_energy_per_second * time_reshuffle_from_to);
    eprintln!("RS2 energy: {} J total in {} seconds", energy_reshuffle_from_to, time_reshuffle_from_to);
    eprintln!("RS2 energy net: {} J", energy_rs2_net);
    eprintln!("RS2 energy net per iteration: {} J", energy_rs2_net / iterations as f64);

    let (energy_rsk_from_to, time_rsk_from_to) = energy_pep_rsk_from_to(iterations, rest_before_measure);
    let energy_rsk2_net = energy_rsk_from_to - (idle_energy_per_second * time_rsk_from_to);
    eprintln!("RSK2 energy: {} J total in {} seconds", energy_rsk_from_to, time_rsk_from_to);
    eprintln!("RSK2 energy net: {} J", energy_rsk2_net);
    eprintln!("RSK2 energy net per iteration: {} J", energy_rsk2_net / iterations as f64);
}