//! `peppy batch`: the batch protocol of draft-doesburg-cfrg-coprf over its wire formats.
//!
//! A request is read as raw bytes from a file or standard input and the response written as raw
//! bytes to a file or standard output; with `--json` the response is printed base64-encoded
//! instead, together with the public key the items are now encrypted under.

use crate::io::{self, Output, Result};
use base64::engine::general_purpose;
use base64::Engine;
use clap::{Args, Subcommand};
use libpep::transcryptor::Transcryptor;
use libpep::wire::BatchRequest;
use rand_core::{CryptoRng, Rng};
use std::io::{Read, Write};

#[derive(Subcommand)]
pub enum Batch {
    /// Transcrypt a wire-format batch request into a response, as a transcryptor with the given
    /// secrets. The items are rerandomized, reshuffled (pseudonyms) or rekeyed, and shuffled.
    Transcrypt(TranscryptArgs),
}

#[derive(Args)]
pub struct TranscryptArgs {
    /// The transcryptor's pseudonymization secret.
    #[arg(long)]
    pseudonymization_secret: String,
    /// The transcryptor's encryption secret.
    #[arg(long)]
    encryption_secret: String,
    /// The file holding the request bytes; `-` reads standard input.
    #[arg(long, default_value = "-")]
    input: String,
    /// The file to write the response bytes to; `-` writes standard output (unless --json).
    #[arg(long, default_value = "-")]
    output: String,
}

fn read_input(path: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    if path == "-" {
        std::io::stdin().read_to_end(&mut buf)?;
    } else {
        buf = std::fs::read(path)
            .map_err(|e| io::Error::input(format!("cannot read {path}: {e}")))?;
    }
    Ok(buf)
}

fn write_output(path: &str, bytes: &[u8]) -> Result<()> {
    if path == "-" {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(bytes)?;
        stdout.flush()?;
    } else {
        std::fs::write(path, bytes)
            .map_err(|e| io::Error::input(format!("cannot write {path}: {e}")))?;
    }
    Ok(())
}

pub fn run<R: Rng + CryptoRng>(command: Batch, rng: &mut R, out: &mut Output) -> Result<()> {
    match command {
        Batch::Transcrypt(args) => transcrypt(args, rng, out),
    }
}

fn transcrypt<R: Rng + CryptoRng>(
    args: TranscryptArgs,
    rng: &mut R,
    out: &mut Output,
) -> Result<()> {
    let transcryptor = Transcryptor::new(
        io::pseudonymization_secret(&args.pseudonymization_secret)?,
        io::encryption_secret(&args.encryption_secret)?,
    );
    let request = BatchRequest::from_bytes(&read_input(&args.input)?)
        .map_err(|e| io::Error::input(format!("request: {e}")))?;
    let response = transcryptor
        .transcrypt_wire(&request, rng)
        .map_err(|e| io::Error::input(format!("request: {e}")))?;
    let bytes = response.to_bytes();
    if out.json() {
        out.value("response", general_purpose::URL_SAFE.encode(&bytes));
        out.value("key", response.y_to().to_hex());
        if args.output != "-" {
            write_output(&args.output, &bytes)?;
        }
    } else {
        write_output(&args.output, &bytes)?;
        out.note(&format!("key: {}", response.y_to().to_hex()));
    }
    Ok(())
}
