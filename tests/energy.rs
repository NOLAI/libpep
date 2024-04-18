use std::cell::RefCell;
use std::net::IpAddr;
use std::ops::Deref;
use std::rc::Rc;
use hyper::body::Incoming;
use hyper::{Request, Response};
use rand_core::OsRng;
use libpep::arithmetic::{G, GroupElement, ScalarNonZero};
use libpep::elgamal::{decrypt, ElGamal, encrypt};
use libpep::primitives::{rekey_from_to, rsk_from_to};
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

fn transcrypt(n: usize, l: usize, m: usize) {
    let mut rng = OsRng;

    // system params
    let y = ScalarNonZero::random(&mut rng); // global private
    let gy = y * G; // global public

    // random message
    let data = GroupElement::random(&mut rng);

    // factors
    let s_from_s = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));
    let s_to_s = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));
    let k_from_s = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));
    let k_to_s = Vec::from_iter((0..n).map(|_| ScalarNonZero::random(&mut rng)));

    let k_from = k_from_s.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);
    let k_to = k_to_s.iter().fold(ScalarNonZero::one(), |acc, k| acc * k);

    let s_from = s_from_s.iter().fold(ScalarNonZero::one(), |acc, s| acc * s);
    let s_to = s_to_s.iter().fold(ScalarNonZero::one(), |acc, s| acc * s);

    let s = s_from.invert() * s_to;

    let transcryptors = Vec::from_iter((0..n).map(|x| start_transcryptor(x, s_from_s[x], s_to_s[x], k_from_s[x], k_to_s[x])));

    // wait for webserver to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    let sender = get_agent();

    // START BENCHMARK
    let before = get_ina();

    for _ in 0.. l {
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
            debug_assert_eq!(s * data, decrypted);
        }
    }
    // END BENCHMARK
    let after = get_ina();
    if let (Some(before), Some(after)) = (before, after) {
        eprintln!("energy {} J", after - before);
    }
}

#[test]
fn energy_transcrypt() {
    let l = 1; // experiment length iterations
    let n = 3; // number of tiers
    let m = 1; // number of blocks / data length (multiples of 32 bytes)

    transcrypt(n, l, m);
}


