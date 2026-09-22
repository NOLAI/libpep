//! `peppy scalar` and `peppy point`: arithmetic on the group's scalars and elements.

use crate::io::{self, Output, Result};
use clap::Subcommand;
use libpep::elgamal::arithmetic::group_elements::{GroupElement, G};
use libpep::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
use libpep::encodings::hash_to_group;
use libpep::protocol::Context;
use rand_core::{CryptoRng, Rng};
use sha2::{Digest, Sha512};

#[derive(Subcommand)]
pub enum Scalar {
    /// A random non-zero scalar.
    Random,
    /// The multiplicative inverse of a scalar.
    Invert { value: String },
    /// The product of two or more scalars.
    Mul {
        #[arg(num_args = 2..)]
        values: Vec<String>,
    },
    /// A scalar derived from text with SHA-512.
    FromHash { text: String },
}

#[derive(Subcommand)]
pub enum Point {
    /// A random group element.
    Random,
    /// The group element `s * G` for a scalar `s`.
    Base { scalar: String },
    /// A group element derived from text with SHA-512 (the raw one-way map, no domain
    /// separation).
    FromHash { text: String },
    /// The hash_to_group encoding of an identifier: hash_to_ristretto255 domain-separated with
    /// the protocol context. This is how an identifier becomes an origin pseudonym.
    HashToGroup { identifier: String },
}

pub fn run_scalar<R: Rng + CryptoRng>(cmd: Scalar, rng: &mut R, out: &mut Output) -> Result<()> {
    match cmd {
        Scalar::Random => out.value("scalar", ScalarNonZero::random(rng).to_hex()),
        Scalar::Invert { value } => {
            out.value("scalar", io::scalar(&value, "value")?.invert().to_hex())
        }
        Scalar::Mul { values } => {
            let mut product = ScalarNonZero::one();
            for v in &values {
                product = product * io::scalar(v, "value")?;
            }
            out.value("scalar", product.to_hex());
        }
        Scalar::FromHash { text } => {
            let digest: [u8; 64] = Sha512::digest(io::read_arg(&text)?.as_bytes()).into();
            out.value("scalar", ScalarNonZero::from_hash(&digest).to_hex());
        }
    }
    Ok(())
}

pub fn run_point<R: Rng + CryptoRng>(
    cmd: Point,
    protocol: &Context,
    rng: &mut R,
    out: &mut Output,
) -> Result<()> {
    match cmd {
        Point::Random => out.value("point", GroupElement::random(rng).to_hex()),
        Point::Base { scalar } => out.value("point", (io::scalar(&scalar, "scalar")? * G).to_hex()),
        Point::FromHash { text } => {
            let digest: [u8; 64] = Sha512::digest(io::read_arg(&text)?.as_bytes()).into();
            out.value("point", GroupElement::from_hash(&digest).to_hex());
        }
        Point::HashToGroup { identifier } => {
            let identifier = io::read_arg(&identifier)?;
            out.value(
                "point",
                hash_to_group(identifier.as_bytes(), protocol).to_hex(),
            );
        }
    }
    Ok(())
}
