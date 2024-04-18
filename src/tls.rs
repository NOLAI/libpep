use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::net::IpAddr;
use std::path::PathBuf;

use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::BTreeMap;
use hyper::HeaderMap;
use rand_core::{RngCore, OsRng};
use tokio_stream::StreamExt;
use hyper::{Response,Request};

use std::net::SocketAddr;
use std::ops::Deref;

use hyper::body::{Body,Incoming};

use hyper::service::service_fn;

use hyper_util::rt::TokioIo;

pub use bytes::Bytes;

const ACCEPT_TIMEOUT: u64 = 5; // in seconds

pub use http_body_util::{Full,BodyExt,Limited,StreamBody,combinators::BoxBody};
use crate::arithmetic::ScalarNonZero;

pub type BoxedBody = BoxBody<bytes::Bytes,String>;
pub type BodyVec = Full<Bytes>;

pub fn box_body<T,E: std::fmt::Display>(body: T) -> BoxedBody
where T: Body<Data = bytes::Bytes, Error = E> + Send + Sync + 'static,
{
    BoxBody::new(body.map_err(|err| err.to_string()))
}

struct StringBuffer<'a> {
    contents: std::slice::Iter<'a,u8>
}

impl<'a> std::io::Read for StringBuffer<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        for (i, item) in buf.iter_mut().enumerate() {
            if let Some(x) = self.contents.next() {
                *item = *x;
            } else {
                return Ok(i);
            }
        }
        Ok(buf.len())
    }
}

pub fn load_pem_private_key_from_bytes(contents: &[u8]) -> Result<tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let mut reader = std::io::BufReader::new(StringBuffer { contents: contents.iter(), });
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader);
    if let Some(key) = keys.flatten().next() {
        return Ok(tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(key));
    }

    let mut reader = std::io::BufReader::new(StringBuffer { contents: contents.iter(), });
    let keys = rustls_pemfile::rsa_private_keys(&mut reader);
    if let Some(key) = keys.flatten().next() {
        return Ok(tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs1(key));
    }
    Err("Not one PKCS8/RSA-encoded private key found".to_string().into())
}

pub fn load_pem_certs_from_bytes(contents: &[u8]) -> std::io::Result<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>> {
    let contents = StringBuffer { contents: contents.iter(), };
    let mut reader = std::io::BufReader::new(contents);
    let certs = rustls_pemfile::certs(&mut reader);
    certs.collect()
}

pub struct ServerState {
    pub s_from: ScalarNonZero,
    pub s_to: ScalarNonZero,
    pub k_from: ScalarNonZero,
    pub k_to: ScalarNonZero,
}

pub async fn webserver(port:u16,
                       handle: fn(u16, bool, IpAddr, Request<Incoming>, Rc<RefCell<ServerState>>) -> Result<Response<BoxedBody>, hyper::http::Error>,
                       server_state: ServerState
){
    let key = load_pem_private_key_from_bytes(include_bytes!("../certs/cert.key")).unwrap();
    let certs = load_pem_certs_from_bytes(include_bytes!("../certs/cert.crt")).unwrap();
    let server_state = Rc::new(RefCell::new(server_state));
    let mut http1 = hyper::server::conn::http1::Builder::new();
    http1.title_case_headers(true);

    let mut servers = Vec::new();
    eprintln!("listening for HTTPS on port {}", port);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_nodelay(true).unwrap();
    socket.set_reuseaddr(true).unwrap();
    socket.bind(addr).unwrap();
    let listener = socket.listen(1024);
    let (port,listener) = match listener {
        Ok(listener) => (port,listener),
        Err(err) => {
            eprintln!("can not listen on port {}: {err}", port);
            return;
        },
    };
    let server_state = server_state.clone();
    let http1 = http1.clone();
    let http2 = hyper::server::conn::http2::Builder::new(LocalExec);
    let mut tls_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_config = Arc::new(tls_config);
    let server = tokio::task::spawn_local(async move {
        let (tx_closer, rx_closer) = tokio::sync::oneshot::channel();
        let counter = Rc::new(RefCell::new((0usize,None)));
        loop {
            tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                drop(listener);
                if counter.borrow().0 > 0 {
                    counter.borrow_mut().1 = Some(tx_closer);
                    let _ = rx_closer.await;
                }
                break;
            },
            r = listener.accept() => {
                match r {
                    Ok((conn,addr)) => {
                        let http1 = http1.clone();
                        let http2 = http2.clone();
                        let server_state = server_state.clone();
                        let counter = counter.clone();
                        let tls_config = tls_config.clone();
                        tokio::task::spawn_local(async move {
                            let acceptor = tokio_rustls::LazyConfigAcceptor::new(tokio_rustls::rustls::server::Acceptor::default(), conn);
                            //futures_util::pin_mut!(acceptor);

                            match tokio::time::timeout(Duration::from_secs(ACCEPT_TIMEOUT),acceptor).await {
                                Ok(Ok(start)) => {
                                    let client_hello = start.client_hello();
                                    let sni = client_hello.server_name().map(|x| x.to_string());
                                    let is_http2 = client_hello.alpn().map(|mut x| x.any(|x| x == &b"h2"[..])).unwrap_or_default();
                                    let conn = tokio::time::timeout(Duration::from_secs(ACCEPT_TIMEOUT), start.into_stream(tls_config)).await;
                                    match conn {
                                        Ok(Ok(conn)) => {
                                            let conn_ip = addr.ip();
                                            let service = service_fn(move |req| {
                                                handle(port, true, conn_ip, req, server_state.clone())
                                            });
                                            let conn = TokioIo::new(conn);
                                            counter.borrow_mut().0 += 1;
                                            if is_http2 {
                                                if let Err(err) = http2.serve_connection(conn, service).await {
                                                    if cfg!(debug_assertions) || (!err.is_canceled() && !err.is_parse_status() && !err.is_closed()) {
                                                        crashy::log::error!("Application error: {}", err);
                                                    }
                                                }
                                            } else if let Err(err) = http1.serve_connection(conn, service).with_upgrades().await {
                                                if cfg!(debug_assertions) || (!err.is_canceled() && !err.is_parse_status() && !err.is_closed()) {
                                                    crashy::log::error!("Application error: {}", err);
                                                }
                                            }
                                            let mut counter = counter.borrow_mut();
                                            let count = &mut counter.0;
                                            *count -= 1;
                                            if *count == 0 {
                                                if let Some(tx) = std::mem::take(&mut counter.1) {
                                                    tx.send(()).unwrap();
                                                }
                                            }
                                        },
                                        Ok(Err(err)) => {
                                            crashy::log::info!("TLS secondary handshake error {err} for SNI '{}'", sni.unwrap_or_default());
                                        },
                                        Err(_) => {
                                            // time out
                                        },
                                    }
                                },
                                Ok(Err(err)) => {
                                    crashy::log::info!("TLS primary handshake error {err}");
                                },
                                Err(_err) => {
                                    // time out
                                },
                            }
                        });
                    },
                    Err(err) => {
                        return std::io::Result::Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{}", err)));
                    }
                }
            },
            }
        }
        Ok(())
    });
    servers.push(futures::stream::once(server));

    let mut servers = futures::stream::select_all(servers);
    // for ungraceful exit: exit on first error by design
    // for graceful exit: loop and wait for all
    if !cfg!(debug_assertions) {
        while let Some(result) = servers.next().await {
            let result : Result<std::io::Result<()>,tokio::task::JoinError> = result;
            if let Ok(Err(e)) = result {
                eprintln!("server error: {}", e);
            }
        }
    } else if let Some(result) = servers.next().await {
        let result : Result<std::io::Result<()>,tokio::task::JoinError> = result;
        if let Ok(Err(e)) = result {
            eprintln!("server error: {}", e);
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LocalExec;

impl<F> hyper::rt::Executor<F> for LocalExec
where
    F: std::future::Future + 'static,
{
    fn execute(&self, fut: F) {
        tokio::task::spawn_local(fut);
    }
}

pub fn error_page(status: u16, message: &str, filename: &str, error_trace: Option<&str>, link: Option<(&str,&str)>, version: u64) -> Result<Response<BoxedBody>,hyper::http::Error> {
    let link = if let Some((href, text)) = link {
        format!(r#"<a class="btn" href="{href}">{text}</a>"#)
    } else {
        "".to_string()
    };
    let script = format!("<html>
<style>
html {{
    font-family: sans-serif;
}}
body {{
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    height: 100%;
    overflow: hidden;
}}
h3 {{
    margin-bottom: 0;
    font-weight: 300;
}}
h2 {{
    margin-top: 0.25em;
}}
.btn {{
    padding: 1rem;
    background-color: #00466f;
    color: white;
    border-radius: 0.5rem;
    text-decoration: none;

}}
@media (prefers-color-scheme: dark) {{
    html {{
        background-color: black;
        color: white;
    }}
}}
</style>
<h3>{message}</h3>
<h2>{filename}</h2>
{link}
<pre>
</pre>
</html>
");
    if status == 500 {
        crashy::log::error!("internal error for {}: {}\n{}", filename, message, error_trace.unwrap_or_default());
    }
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=UTF-8")
        .body(box_body(BodyVec::from(script)))
}


pub fn get_agent() -> ureq::Agent {
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    let certs = load_pem_certs_from_bytes(include_bytes!("../certs/CA.pem")).unwrap();
    root_store.add(certs.last().unwrap().clone()).unwrap();
    let tls_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    ureq::AgentBuilder::new()
        .user_agent(&format!("{} {}/{}", env!("CARGO_PKG_NAME"), buildinfy::build_reference().unwrap_or_default(), buildinfy::build_pipeline_id_per_project().unwrap_or_default()))
        .timeout_read(std::time::Duration::from_secs(60))
        .timeout_write(std::time::Duration::from_secs(5))
        .tls_config(std::sync::Arc::new(tls_config))
        .build()
}


// fn start_server(port:u16, handle: fn(port: u16, encrypted: bool, conn: IpAddr, req: Request<Incoming>, server_state: Rc<RefCell<ServerState>>) -> Result<Response<BoxedBody>, hyper::http::Error>){
//     std::thread::spawn(|| {
//         let rt = tokio::runtime::Builder::new_current_thread()
//             .enable_all()
//             .build()
//             .expect("build runtime");
//
//         let local = Box::new(tokio::task::LocalSet::new());
//         let local : &'static tokio::task::LocalSet = Box::leak(local);
//
//         local.block_on(&rt, async {
//             eprintln!("server starting");
//             let _ = webserver(port, handle).await;
//             eprintln!("server stopped");
//         });
//     });
//     let agent = get_agent(1);
//
//     eprintln!("waiting for server to start");
//     std::thread::sleep(std::time::Duration::from_secs(1));
//     eprintln!("server started");
//     let response = request(&agent);
//     eprintln!("response: {:?}", response);
// }
