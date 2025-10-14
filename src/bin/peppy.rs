use commandy_macros::*;
use libpep::distributed::key_blinding::{make_distributed_global_keys, SafeScalar};
use libpep::high_level::contexts::{EncryptionContext, PseudonymizationDomain, TranscryptionInfo};
use libpep::high_level::data_types::{Encryptable, Encrypted, EncryptedPseudonym, Pseudonym};
use libpep::high_level::keys::{
    make_pseudonym_global_keys, make_pseudonym_session_keys, PseudonymGlobalPublicKey,
    PseudonymGlobalSecretKey, PseudonymSessionPublicKey, PseudonymSessionSecretKey, PublicKey,
    SecretKey,
};
use libpep::high_level::ops::{
    decrypt_pseudonym, encrypt_pseudonym, encrypt_pseudonym_global, rerandomize, transcrypt,
};
use libpep::high_level::padding::LongPseudonym;
use libpep::high_level::secrets::{EncryptionSecret, PseudonymizationSecret};
use libpep::internal::arithmetic::{ScalarNonZero, ScalarTraits};
use rand_core::OsRng;
use std::cmp::Ordering;

#[derive(Command, Debug, Default)]
#[command("generate-global-keys")]
#[description("Outputs a public global key and a secret global key (use once).")]
struct GenerateGlobalKeys {}

#[derive(Command, Debug, Default)]
#[command("generate-session-keys")]
#[description("Outputs a public session key and a secret session key, derived from a global secret key with an encryption secret and session context.")]
struct GenerateSessionKeys {
    #[positional("global-secret-key encryption-secret session-context", 3, 3)]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("random-pseudonym")]
#[description("Create a random new pseudonym.")]
struct RandomPseudonym {}

#[derive(Command, Debug, Default)]
#[command("pseudonym-encode")]
#[description("Encode an identifier into a pseudonym (or long pseudonym if > 16 bytes).")]
struct PseudonymEncode {
    #[positional("identifier", 1, 1)]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("pseudonym-decode")]
#[description("Decode a pseudonym (or long pseudonym) back to its origin identifier.")]
struct PseudonymDecode {
    #[positional("pseudonym-hex...", 1, 100)]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("encrypt")]
#[description("Encrypt a pseudonym with a session public key.")]
struct Encrypt {
    #[positional("session-public-key pseudonym", 2, 2)]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("encrypt-global")]
#[description("Encrypt a pseudonym with a global public key.")]
struct EncryptGlobal {
    #[positional("global-public-key pseudonym", 1, 1)]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("decrypt")]
#[description("Decrypt a pseudonym with a session secret key.")]
struct Decrypt {
    #[positional("session-secret-key ciphertext", 2, 2)]
    args: Vec<String>,
}

#[cfg(not(feature = "elgamal3"))]
#[derive(Command, Debug, Default)]
#[command("rerandomize")]
#[description("Rerandomize a ciphertext.")]
struct Rerandomize {
    #[positional("ciphertext public-key", 2, 2)]
    args: Vec<String>,
}

#[cfg(feature = "elgamal3")]
#[derive(Command, Debug, Default)]
#[command("rerandomize")]
#[description("Rerandomize a ciphertext.")]
struct Rerandomize {
    #[positional("ciphertext", 1, 1)]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("transcrypt")]
#[description("Transcrypt a ciphertext from one domain and session to another.")]
struct Transcrypt {
    #[positional("pseudonymization-secret encryption-secret domain-from domain-to session-from session-to ciphertext",7,7)]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("transcrypt-from-global")]
#[description("Transcrypt a ciphertext from global to a session encryption context.")]
struct TranscryptFromGlobal {
    #[positional(
        "pseudonymization-secret encryption-secret domain-from domain-to session-to ciphertext",
        6,
        6
    )]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("transcrypt-to-global")]
#[description("Transcrypt a ciphertext from a session to a global encryption context.")]
struct TranscryptToGlobal {
    #[positional(
        "pseudonymization-secret encryption-secret domain-from domain-to session-from ciphertext",
        6,
        6
    )]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("setup-distributed")]
#[description("Creates the secrets needed for distributed systems.")]
struct SetupDistributedSystems {
    #[positional("n", 1, 1)]
    args: Vec<String>,
}

#[derive(Command, Debug)]
enum Sub {
    GenerateGlobalKeys(GenerateGlobalKeys),
    GenerateSessionKeys(GenerateSessionKeys),
    RandomPseudonym(RandomPseudonym),
    PseudonymEncode(PseudonymEncode),
    PseudonymDecode(PseudonymDecode),
    Encrypt(Encrypt),
    EncryptGlobal(EncryptGlobal),
    Decrypt(Decrypt),
    Rerandomize(Rerandomize),
    Transcrypt(Transcrypt),
    TranscryptFromGlobal(TranscryptFromGlobal),
    TranscryptToGlobal(TranscryptToGlobal),
    SetupDistributedSystems(SetupDistributedSystems),
}

#[derive(Command, Debug, Default)]
#[description("operations on PEP pseudonyms")]
#[program("peppy")] // can have an argument, outputs man-page + shell completion
struct Options {
    #[subcommands()]
    subcommand: Option<Sub>,
}

fn main() {
    let mut rng = OsRng;
    let options: Options = commandy::parse_args();
    match options.subcommand {
        Some(Sub::GenerateGlobalKeys(_)) => {
            let (pk, sk) = make_pseudonym_global_keys(&mut rng);
            eprint!("Public global key: ");
            println!("{}", &pk.encode_as_hex());
            eprint!("Secret global key: ");
            println!("{}", &sk.value().encode_as_hex());
        }
        Some(Sub::GenerateSessionKeys(arg)) => {
            let global_secret_key = PseudonymGlobalSecretKey::from(
                ScalarNonZero::decode_from_hex(&arg.args[0]).expect("Invalid global secret key."),
            );
            let encryption_secret = EncryptionSecret::from(arg.args[1].as_bytes().to_vec());
            let session_context = EncryptionContext::from(arg.args[2].as_str());

            let (session_pk, session_sk) = make_pseudonym_session_keys(
                &global_secret_key,
                &session_context,
                &encryption_secret,
            );
            eprint!("Public session key: ");
            println!("{}", &session_pk.encode_as_hex());
            eprint!("Secret session key: ");
            println!("{}", &session_sk.value().encode_as_hex());
        }
        Some(Sub::RandomPseudonym(_)) => {
            let pseudonym = Pseudonym::random(&mut rng);
            eprint!("Random pseudonym: ");
            println!("{}", &pseudonym.encode_as_hex());
        }
        Some(Sub::PseudonymEncode(arg)) => {
            let origin = arg.args[0].as_bytes();
            match origin.len().cmp(&16) {
                Ordering::Greater => {
                    eprintln!("Warning: Identifier is longer than 16 bytes, using long pseudonym with PKCS#7 padding. This comes with privacy risks, as blocks can highlight subgroups and the number of blocks is visible.");
                    let long_pseudonym = LongPseudonym::from_bytes_padded(origin)
                        .expect("Failed to create long pseudonym");
                    eprint!("Long pseudonym ({} blocks): ", long_pseudonym.0.len());
                    let hex_blocks: Vec<String> =
                        long_pseudonym.0.iter().map(|p| p.encode_as_hex()).collect();
                    println!("{}", hex_blocks.join(" "));
                }
                Ordering::Less => {
                    let mut padded = [0u8; 16];
                    padded[..origin.len()].copy_from_slice(origin);
                    let pseudonym = Pseudonym::from_bytes(&padded);
                    eprint!("Pseudonym: ");
                    println!("{}", &pseudonym.encode_as_hex());
                }
                Ordering::Equal => {
                    let pseudonym = Pseudonym::from_bytes(origin.try_into().unwrap());
                    eprint!("Pseudonym: ");
                    println!("{}", &pseudonym.encode_as_hex());
                }
            };
        }
        Some(Sub::PseudonymDecode(arg)) => {
            if arg.args.len() == 1 {
                // Single pseudonym - try lizard decoding
                let pseudonym =
                    Pseudonym::decode_from_hex(&arg.args[0]).expect("Invalid pseudonym.");
                let origin = pseudonym.as_bytes();
                if origin.is_none() {
                    eprintln!("Pseudonym does not have a lizard representation.");
                    std::process::exit(1);
                }
                eprint!("Value: ");
                println!(
                    "{}",
                    String::from_utf8_lossy(
                        &origin.expect("Lizard representation cannot be displayed.")
                    )
                );
            } else {
                // Multiple pseudonyms - decode as long pseudonym
                let pseudonyms: Vec<Pseudonym> = arg
                    .args
                    .iter()
                    .map(|hex| Pseudonym::decode_from_hex(hex).expect("Invalid pseudonym"))
                    .collect();
                let long_pseudonym = LongPseudonym(pseudonyms);
                let text = long_pseudonym
                    .to_string_padded()
                    .expect("Failed to decode long pseudonym");
                eprint!("Value: ");
                println!("{}", text);
            }
        }
        Some(Sub::Encrypt(arg)) => {
            let public_key =
                PseudonymSessionPublicKey::from_hex(&arg.args[0]).expect("Invalid public key.");
            let pseudonym = Pseudonym::decode_from_hex(&arg.args[1]).expect("Invalid pseudonym.");
            let ciphertext = encrypt_pseudonym(&pseudonym, &public_key, &mut rng);
            eprint!("Ciphertext: ");
            println!("{}", &ciphertext.encode_as_base64());
        }
        Some(Sub::EncryptGlobal(arg)) => {
            let public_key =
                PseudonymGlobalPublicKey::from_hex(&arg.args[0]).expect("Invalid public key.");
            let pseudonym = Pseudonym::decode_from_hex(&arg.args[1]).expect("Invalid pseudonym.");
            let ciphertext = encrypt_pseudonym_global(&pseudonym, &public_key, &mut rng);
            eprint!("Ciphertext: ");
            println!("{}", &ciphertext.encode_as_base64());
        }
        Some(Sub::Decrypt(arg)) => {
            let secret_key = PseudonymSessionSecretKey::from(
                ScalarNonZero::decode_from_hex(&arg.args[0]).expect("Invalid secret key."),
            );
            let ciphertext =
                EncryptedPseudonym::from_base64(&arg.args[1]).expect("Invalid ciphertext.");
            let plaintext = decrypt_pseudonym(&ciphertext, &secret_key);
            eprint!("Plaintext: ");
            println!("{}", &plaintext.encode_as_hex());
        }
        Some(Sub::Rerandomize(arg)) => {
            let ciphertext =
                EncryptedPseudonym::from_base64(&arg.args[0]).expect("Invalid ciphertext.");
            let rerandomized;
            #[cfg(not(feature = "elgamal3"))]
            {
                let public_key =
                    PseudonymSessionPublicKey::from_hex(&arg.args[1]).expect("Invalid public key.");
                rerandomized = rerandomize(&ciphertext, &public_key, &mut rng);
            }
            #[cfg(feature = "elgamal3")]
            {
                rerandomized = rerandomize(&ciphertext, &mut rng);
            }
            eprint!("Rerandomized ciphertext: ");
            println!("{}", &rerandomized.encode_as_base64());
        }
        Some(Sub::Transcrypt(arg)) => {
            let pseudonymization_secret =
                PseudonymizationSecret::from(arg.args[0].as_bytes().to_vec());
            let encryption_secret = EncryptionSecret::from(arg.args[1].as_bytes().to_vec());
            let domain_from = PseudonymizationDomain::from(arg.args[2].as_str());
            let domain_to = PseudonymizationDomain::from(arg.args[3].as_str());
            let session_from = EncryptionContext::from(arg.args[4].as_str());
            let session_to = EncryptionContext::from(arg.args[5].as_str());
            let ciphertext =
                EncryptedPseudonym::from_base64(&arg.args[6]).expect("Invalid ciphertext.");
            let transcryption_info = TranscryptionInfo::new(
                &domain_from,
                &domain_to,
                Some(&session_from),
                Some(&session_to),
                &pseudonymization_secret,
                &encryption_secret,
            );
            let transcrypted = transcrypt(&ciphertext, &transcryption_info);
            eprint!("Transcrypted ciphertext: ");
            println!("{}", &transcrypted.encode_as_base64());
        }
        Some(Sub::TranscryptFromGlobal(arg)) => {
            let pseudonymization_secret =
                PseudonymizationSecret::from(arg.args[0].as_bytes().to_vec());
            let encryption_secret = EncryptionSecret::from(arg.args[1].as_bytes().to_vec());
            let domain_from = PseudonymizationDomain::from(arg.args[2].as_str());
            let domain_to = PseudonymizationDomain::from(arg.args[3].as_str());
            let session_to = EncryptionContext::from(arg.args[5].as_str());
            let ciphertext =
                EncryptedPseudonym::from_base64(&arg.args[6]).expect("Invalid ciphertext.");
            let transcryption_info = TranscryptionInfo::new(
                &domain_from,
                &domain_to,
                None,
                Some(&session_to),
                &pseudonymization_secret,
                &encryption_secret,
            );
            let transcrypted = transcrypt(&ciphertext, &transcryption_info);
            eprint!("Transcrypted ciphertext: ");
            println!("{}", &transcrypted.encode_as_base64());
        }
        Some(Sub::TranscryptToGlobal(arg)) => {
            let pseudonymization_secret =
                PseudonymizationSecret::from(arg.args[0].as_bytes().to_vec());
            let encryption_secret = EncryptionSecret::from(arg.args[1].as_bytes().to_vec());
            let domain_from = PseudonymizationDomain::from(arg.args[2].as_str());
            let domain_to = PseudonymizationDomain::from(arg.args[3].as_str());
            let session_from = EncryptionContext::from(arg.args[5].as_str());
            let ciphertext =
                EncryptedPseudonym::from_base64(&arg.args[6]).expect("Invalid ciphertext.");
            let transcryption_info = TranscryptionInfo::new(
                &domain_from,
                &domain_to,
                Some(&session_from),
                None,
                &pseudonymization_secret,
                &encryption_secret,
            );
            let transcrypted = transcrypt(&ciphertext, &transcryption_info);
            eprint!("Transcrypted ciphertext: ");
            println!("{}", &transcrypted.encode_as_base64());
        }
        Some(Sub::SetupDistributedSystems(arg)) => {
            let n = arg.args[0]
                .parse::<usize>()
                .expect("Invalid number of nodes.");
            let (global_public_keys, blinded_global_keys, blinding_factors) =
                make_distributed_global_keys(n, &mut rng);
            eprintln!("Public global keys:");
            eprintln!(
                "  - Attributes: {}",
                &global_public_keys.attribute.encode_as_hex()
            );
            eprintln!(
                "  - Pseudonyms: {}",
                &global_public_keys.pseudonym.encode_as_hex()
            );
            eprintln!("Blinded secret keys:");
            eprintln!(
                "  - Attributes: {}",
                &blinded_global_keys.attribute.encode_as_hex()
            );
            eprintln!(
                "  - Pseudonyms: {}",
                &blinded_global_keys.pseudonym.encode_as_hex()
            );
            eprintln!("Blinding factors (keep secret):");
            for factor in blinding_factors.iter() {
                eprintln!("  - {}", factor.encode_as_hex());
            }
        }
        None => {
            eprintln!("No subcommand given.");
            std::process::exit(1);
        }
    }
}
