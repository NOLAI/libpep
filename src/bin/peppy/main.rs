//! `peppy`: command-line interface to libpep.
//!
//! The first word of a command is the kind of thing operated on (`keys`, `factors`,
//! `pseudonym`, `attribute`, `json`, `elgamal`, `scalar`, `point`), the second the operation.
//! See `peppy --help` and the README for a worked session.

// The CLI reports errors through `io::Error`; the two remaining `expect`s are on
// infallible serialization.
#![allow(clippy::expect_used)]

mod arith;
mod data;
mod elgamal;
mod factors;
mod io;
#[cfg(feature = "json")]
mod json;
mod keys;

use clap::{CommandFactory, Parser, Subcommand};
use io::Output;
use libpep::protocol::{Context, RISTRETTO255_SHA512};

#[derive(Parser)]
#[command(
    name = "peppy",
    version,
    about = "Polymorphic encryption and pseudonymization from the command line",
    long_about = "Operations on PEP pseudonyms and attributes: key setup, encryption, \
                  transcryption between domains and sessions, and the underlying ElGamal \
                  primitives.\n\nAny value argument may be `-` to read it from standard input \
                  or `@path` to read it from a file. Scalars and group elements are hex, \
                  ciphertexts base64; long values are space-separated (plain) or `|`-separated \
                  (encrypted) blocks.\n\nAll parties of a deployment must use the same protocol \
                  context (`--protocol`): it domain-separates every derived factor and hashed \
                  pseudonym."
)]
struct Cli {
    /// Print all output values as one JSON object instead of labelled lines.
    #[arg(long, global = true)]
    json: bool,
    /// The protocol context identifier (ciphersuite) that factors and hashed pseudonyms are
    /// domain-separated with.
    #[arg(long, global = true, value_name = "IDENTIFIER", default_value = RISTRETTO255_SHA512)]
    protocol: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Global, session and distributed key material.
    #[command(subcommand)]
    Keys(keys::Keys),
    /// Reshuffle and rekey factors and the info for a transcryption.
    #[command(subcommand)]
    Factors(factors::Factors),
    /// Pseudonyms: identifiers that are reshuffled between domains.
    #[command(subcommand)]
    Pseudonym(data::PseudonymCommand),
    /// Attributes: data that is only rekeyed, never reshuffled.
    #[command(subcommand)]
    Attribute(data::AttributeCommand),
    /// JSON documents with nested pseudonyms and attributes.
    #[cfg(feature = "json")]
    #[command(subcommand)]
    Json(json::Json),
    /// The raw ElGamal primitives on ciphertexts and scalar factors.
    #[command(subcommand)]
    Elgamal(elgamal::Elgamal),
    /// Scalar arithmetic.
    #[command(subcommand)]
    Scalar(arith::Scalar),
    /// Group element arithmetic.
    #[command(subcommand)]
    Point(arith::Point),
    /// Print a shell completion script.
    Completions { shell: clap_complete::Shell },
    /// Print the man page in roff format.
    Man,
}

fn run(command: Command, protocol: &Context, out: &mut Output) -> io::Result<()> {
    let mut rng = rand::rng();
    match command {
        Command::Keys(cmd) => keys::run(cmd, protocol, &mut rng, out),
        Command::Factors(cmd) => factors::run(cmd, protocol, out),
        Command::Pseudonym(cmd) => data::run_pseudonym(cmd, protocol, &mut rng, out),
        Command::Attribute(cmd) => data::run_attribute(cmd, protocol, &mut rng, out),
        #[cfg(feature = "json")]
        Command::Json(cmd) => json::run(cmd, protocol, &mut rng, out),
        Command::Elgamal(cmd) => elgamal::run(cmd, &mut rng, out),
        Command::Scalar(cmd) => arith::run_scalar(cmd, &mut rng, out),
        Command::Point(cmd) => arith::run_point(cmd, protocol, &mut rng, out),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "peppy", &mut std::io::stdout());
            Ok(())
        }
        Command::Man => {
            let mut buf = Vec::new();
            clap_mangen::Man::new(Cli::command()).render(&mut buf)?;
            std::io::Write::write_all(&mut std::io::stdout(), &buf)?;
            Ok(())
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let mut out = Output::new(cli.json);
    let protocol = Context::from_identifier(cli.protocol);
    match run(cli.command, &protocol, &mut out) {
        Ok(()) => out.finish(),
        Err(e) => {
            eprintln!("peppy: {e}");
            std::process::exit(e.code);
        }
    }
}
