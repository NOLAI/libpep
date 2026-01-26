// CLI tool uses expect/unwrap for user-facing error messages
#![allow(clippy::unwrap_used, clippy::expect_used)]

use commandy_macros::*;
use libpep::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
#[cfg(feature = "json")]
use libpep::data::json::{EncryptedPEPJSONValue, PEPJSONBuilder};
use libpep::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use libpep::data::simple::{
    Attribute, ElGamalEncryptable, ElGamalEncrypted, EncryptedAttribute, EncryptedPseudonym,
    Pseudonym,
};
use libpep::data::traits::{Encryptable, Encrypted};
use libpep::factors::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::factors::TranscryptionInfo;
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use libpep::keys::distribution::{make_distributed_global_keys, BlindingFactor};
#[cfg(feature = "json")]
use libpep::keys::make_session_keys;
use libpep::keys::{
    make_pseudonym_global_keys, make_pseudonym_session_keys, AttributeGlobalPublicKey,
    AttributeGlobalSecretKey, AttributeSessionPublicKey, AttributeSessionSecretKey,
    GlobalSecretKeys, PseudonymGlobalPublicKey, PseudonymGlobalSecretKey,
    PseudonymSessionPublicKey, PseudonymSessionSecretKey, PublicKey, SecretKey,
};
use libpep::transcryptor::transcrypt;
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
#[command("random")]
#[description("Create a random new pseudonym or attribute.")]
struct Random {}

#[derive(Command, Debug, Default)]
#[command("encode")]
#[description("Encode an identifier into a pseudonym/attribute (or long version if > 16 bytes).")]
struct Encode {
    #[positional("identifier", 1, 1)]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("decode")]
#[description("Decode a pseudonym/attribute (or long version) back to its origin identifier.")]
struct Decode {
    #[positional("hex...", 1, 100)]
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

#[derive(Command, Debug, Default)]
#[command("encrypt-attribute")]
#[description("Encrypt an attribute with a session public key.")]
struct EncryptAttribute {
    #[positional("session-public-key attribute", 2, 2)]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("encrypt-attribute-global")]
#[description("Encrypt an attribute with a global public key.")]
struct EncryptAttributeGlobal {
    #[positional("global-public-key attribute", 2, 2)]
    args: Vec<String>,
}

#[derive(Command, Debug, Default)]
#[command("decrypt-attribute")]
#[description("Decrypt an attribute with a session secret key.")]
struct DecryptAttribute {
    #[positional("session-secret-key ciphertext", 2, 2)]
    args: Vec<String>,
}

#[cfg(feature = "long")]
#[derive(Command, Debug, Default)]
#[command("encrypt-long-pseudonym")]
#[description("Encrypt a long pseudonym with a session public key.")]
struct EncryptLongPseudonym {
    #[positional("session-public-key pseudonym-hex...", 2, 100)]
    args: Vec<String>,
}

#[cfg(feature = "long")]
#[derive(Command, Debug, Default)]
#[command("decrypt-long-pseudonym")]
#[description("Decrypt a long pseudonym with a session secret key.")]
struct DecryptLongPseudonym {
    #[positional("session-secret-key ciphertext-serialized", 2, 2)]
    args: Vec<String>,
}

#[cfg(feature = "long")]
#[derive(Command, Debug, Default)]
#[command("transcrypt-long-pseudonym")]
#[description("Transcrypt a long pseudonym from one domain and session to another.")]
struct TranscryptLongPseudonym {
    #[positional("pseudonymization-secret encryption-secret domain-from domain-to session-from session-to ciphertext-serialized",7,7)]
    args: Vec<String>,
}

#[cfg(feature = "long")]
#[derive(Command, Debug, Default)]
#[command("encrypt-long-attribute")]
#[description("Encrypt a long attribute with a session public key.")]
struct EncryptLongAttribute {
    #[positional("session-public-key attribute-hex...", 2, 100)]
    args: Vec<String>,
}

#[cfg(feature = "long")]
#[derive(Command, Debug, Default)]
#[command("decrypt-long-attribute")]
#[description("Decrypt a long attribute with a session secret key.")]
struct DecryptLongAttribute {
    #[positional("session-secret-key ciphertext-serialized", 2, 2)]
    args: Vec<String>,
}

#[cfg(feature = "long")]
#[derive(Command, Debug, Default)]
#[command("transcrypt-long-attribute")]
#[description("Transcrypt a long attribute from one domain and session to another.")]
struct TranscryptLongAttribute {
    #[positional("pseudonymization-secret encryption-secret domain-from domain-to session-from session-to ciphertext-serialized",7,7)]
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
#[command("transcrypt-attribute")]
#[description("Transcrypt an attribute from one domain and session to another.")]
struct TranscryptAttribute {
    #[positional("pseudonymization-secret encryption-secret domain-from domain-to session-from session-to ciphertext",7,7)]
    args: Vec<String>,
}

#[cfg(feature = "json")]
#[derive(Command, Debug, Default)]
#[command("json-encrypt")]
#[description("Encrypt a JSON object with session keys. Pseudonym fields are specified as comma-separated: field1,field2 (or empty string for none).")]
struct JsonEncrypt {
    #[positional("pseudonym-global-secret attribute-global-secret encryption-secret session-context pseudonym-fields json-string", 6, 6)]
    args: Vec<String>,
}

#[cfg(feature = "json")]
#[derive(Command, Debug, Default)]
#[command("json-decrypt")]
#[description("Decrypt a JSON object with session keys.")]
struct JsonDecrypt {
    #[positional("pseudonym-global-secret attribute-global-secret encryption-secret session-context encrypted-json-string", 5, 5)]
    args: Vec<String>,
}

#[cfg(feature = "json")]
#[derive(Command, Debug, Default)]
#[command("json-transcrypt")]
#[description("Transcrypt a JSON object from one domain and session to another.")]
struct JsonTranscrypt {
    #[positional("pseudonymization-secret encryption-secret domain-from domain-to session-from session-to encrypted-json-string", 7, 7)]
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
    Random(Random),
    Encode(Encode),
    Decode(Decode),
    Encrypt(Encrypt),
    EncryptGlobal(EncryptGlobal),
    Decrypt(Decrypt),
    EncryptAttribute(EncryptAttribute),
    EncryptAttributeGlobal(EncryptAttributeGlobal),
    DecryptAttribute(DecryptAttribute),
    #[cfg(feature = "long")]
    EncryptLongPseudonym(EncryptLongPseudonym),
    #[cfg(feature = "long")]
    DecryptLongPseudonym(DecryptLongPseudonym),
    #[cfg(feature = "long")]
    TranscryptLongPseudonym(TranscryptLongPseudonym),
    #[cfg(feature = "long")]
    EncryptLongAttribute(EncryptLongAttribute),
    #[cfg(feature = "long")]
    DecryptLongAttribute(DecryptLongAttribute),
    #[cfg(feature = "long")]
    TranscryptLongAttribute(TranscryptLongAttribute),
    Rerandomize(Rerandomize),
    Transcrypt(Transcrypt),
    TranscryptFromGlobal(TranscryptFromGlobal),
    TranscryptToGlobal(TranscryptToGlobal),
    TranscryptAttribute(TranscryptAttribute),
    #[cfg(feature = "json")]
    JsonEncrypt(JsonEncrypt),
    #[cfg(feature = "json")]
    JsonDecrypt(JsonDecrypt),
    #[cfg(feature = "json")]
    JsonTranscrypt(JsonTranscrypt),
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
    let mut rng = rand::rng();
    let options: Options = commandy::parse_args();
    match options.subcommand {
        Some(Sub::GenerateGlobalKeys(_)) => {
            let (pk, sk) = make_pseudonym_global_keys(&mut rng);
            eprint!("Public global key: ");
            println!("{}", &pk.to_hex());
            eprint!("Secret global key: ");
            println!("{}", &sk.value().to_hex());
        }
        Some(Sub::GenerateSessionKeys(arg)) => {
            let global_secret_key = PseudonymGlobalSecretKey::from(
                ScalarNonZero::from_hex(&arg.args[0]).expect("Invalid global secret key."),
            );
            let encryption_secret = EncryptionSecret::from(arg.args[1].as_bytes().to_vec());
            let session_context = EncryptionContext::from(arg.args[2].as_str());

            let (session_pk, session_sk) = make_pseudonym_session_keys(
                &global_secret_key,
                &session_context,
                &encryption_secret,
            );
            eprint!("Public session key: ");
            println!("{}", &session_pk.to_hex());
            eprint!("Secret session key: ");
            println!("{}", &session_sk.value().to_hex());
        }
        Some(Sub::Random(_)) => {
            let pseudonym = Pseudonym::random(&mut rng);
            eprint!("Random: ");
            println!("{}", &pseudonym.to_hex());
        }
        Some(Sub::Encode(arg)) => {
            let origin = arg.args[0].as_bytes();
            match origin.len().cmp(&16) {
                Ordering::Greater => {
                    eprintln!("Warning: Identifier is longer than 16 bytes, using long encoding with PKCS#7 padding. This comes with privacy risks, as blocks can highlight subgroups and the number of blocks is visible.");
                    let long_pseudonym = LongPseudonym::from_bytes_padded(origin);
                    eprint!("Long ({} blocks): ", long_pseudonym.0.len());
                    let hex_blocks: Vec<String> =
                        long_pseudonym.0.iter().map(|p| p.to_hex()).collect();
                    println!("{}", hex_blocks.join(" "));
                }
                Ordering::Less => {
                    let mut padded = [0u8; 16];
                    padded[..origin.len()].copy_from_slice(origin);
                    let pseudonym = Pseudonym::from_lizard(&padded);
                    eprint!("Encoded: ");
                    println!("{}", &pseudonym.to_hex());
                }
                Ordering::Equal => {
                    let pseudonym = Pseudonym::from_lizard(origin.try_into().unwrap());
                    eprint!("Encoded: ");
                    println!("{}", &pseudonym.to_hex());
                }
            };
        }
        Some(Sub::Decode(arg)) => {
            if arg.args.len() == 1 {
                // Single block - try lizard decoding
                let pseudonym = Pseudonym::from_hex(&arg.args[0]).expect("Invalid hex value.");
                let origin = pseudonym.to_lizard();
                if origin.is_none() {
                    eprintln!("Value does not have a lizard representation.");
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
                // Multiple blocks - decode as long
                let pseudonyms: Vec<Pseudonym> = arg
                    .args
                    .iter()
                    .map(|hex| Pseudonym::from_hex(hex).expect("Invalid hex value"))
                    .collect();
                let long_pseudonym = LongPseudonym(pseudonyms);
                let text = long_pseudonym
                    .to_string_padded()
                    .expect("Failed to decode long value");
                eprint!("Value: ");
                println!("{}", text);
            }
        }
        Some(Sub::Encrypt(arg)) => {
            let public_key =
                PseudonymSessionPublicKey::from_hex(&arg.args[0]).expect("Invalid public key.");
            let pseudonym = Pseudonym::from_hex(&arg.args[1]).expect("Invalid pseudonym.");
            let ciphertext = pseudonym.encrypt(&public_key, &mut rng);
            eprint!("Ciphertext: ");
            println!("{}", &ciphertext.to_base64());
        }
        Some(Sub::EncryptGlobal(arg)) => {
            let public_key =
                PseudonymGlobalPublicKey::from_hex(&arg.args[0]).expect("Invalid public key.");
            let pseudonym = Pseudonym::from_hex(&arg.args[1]).expect("Invalid pseudonym.");
            let ciphertext = pseudonym.encrypt_global(&public_key, &mut rng);
            eprint!("Ciphertext: ");
            println!("{}", &ciphertext.to_base64());
        }
        Some(Sub::Decrypt(arg)) => {
            let secret_key = PseudonymSessionSecretKey::from(
                ScalarNonZero::from_hex(&arg.args[0]).expect("Invalid secret key."),
            );
            let ciphertext =
                EncryptedPseudonym::from_base64(&arg.args[1]).expect("Invalid ciphertext.");
            #[cfg(feature = "elgamal3")]
            let plaintext = ciphertext
                .decrypt(&secret_key)
                .expect("Decryption failed: key mismatch");
            #[cfg(not(feature = "elgamal3"))]
            let plaintext = ciphertext.decrypt(&secret_key);
            eprint!("Plaintext: ");
            println!("{}", &plaintext.to_hex());
        }
        Some(Sub::EncryptAttribute(arg)) => {
            let public_key =
                AttributeSessionPublicKey::from_hex(&arg.args[0]).expect("Invalid public key.");
            let attribute = Attribute::from_hex(&arg.args[1]).expect("Invalid attribute.");
            let ciphertext = attribute.encrypt(&public_key, &mut rng);
            eprint!("Ciphertext: ");
            println!("{}", &ciphertext.to_base64());
        }
        Some(Sub::EncryptAttributeGlobal(arg)) => {
            let public_key =
                AttributeGlobalPublicKey::from_hex(&arg.args[0]).expect("Invalid public key.");
            let attribute = Attribute::from_hex(&arg.args[1]).expect("Invalid attribute.");
            let ciphertext = attribute.encrypt_global(&public_key, &mut rng);
            eprint!("Ciphertext: ");
            println!("{}", &ciphertext.to_base64());
        }
        Some(Sub::DecryptAttribute(arg)) => {
            let secret_key = AttributeSessionSecretKey::from(
                ScalarNonZero::from_hex(&arg.args[0]).expect("Invalid secret key."),
            );
            let ciphertext =
                EncryptedAttribute::from_base64(&arg.args[1]).expect("Invalid ciphertext.");
            #[cfg(feature = "elgamal3")]
            let plaintext = ciphertext
                .decrypt(&secret_key)
                .expect("Decryption failed: key mismatch");
            #[cfg(not(feature = "elgamal3"))]
            let plaintext = ciphertext.decrypt(&secret_key);
            eprint!("Plaintext: ");
            println!("{}", &plaintext.to_hex());
        }
        #[cfg(feature = "long")]
        Some(Sub::EncryptLongPseudonym(arg)) => {
            let public_key =
                PseudonymSessionPublicKey::from_hex(&arg.args[0]).expect("Invalid public key.");
            let pseudonyms: Vec<Pseudonym> = arg.args[1..]
                .iter()
                .map(|hex| Pseudonym::from_hex(hex).expect("Invalid pseudonym"))
                .collect();
            let long_pseudonym = LongPseudonym(pseudonyms);
            let ciphertext = long_pseudonym.encrypt(&public_key, &mut rng);
            eprint!("Ciphertext (serialized): ");
            println!("{}", ciphertext.serialize());
        }
        #[cfg(feature = "long")]
        Some(Sub::DecryptLongPseudonym(arg)) => {
            let secret_key = PseudonymSessionSecretKey::from(
                ScalarNonZero::from_hex(&arg.args[0]).expect("Invalid secret key."),
            );
            let ciphertext =
                LongEncryptedPseudonym::deserialize(&arg.args[1]).expect("Invalid ciphertext.");
            #[cfg(feature = "elgamal3")]
            let plaintext = ciphertext
                .decrypt(&secret_key)
                .expect("Decryption failed: key mismatch");
            #[cfg(not(feature = "elgamal3"))]
            let plaintext = ciphertext.decrypt(&secret_key);
            let hex_blocks: Vec<String> = plaintext.0.iter().map(|p| p.to_hex()).collect();
            eprint!("Plaintext ({} blocks): ", plaintext.0.len());
            println!("{}", hex_blocks.join(" "));
        }
        #[cfg(feature = "long")]
        Some(Sub::TranscryptLongPseudonym(arg)) => {
            let pseudonymization_secret =
                PseudonymizationSecret::from(arg.args[0].as_bytes().to_vec());
            let encryption_secret = EncryptionSecret::from(arg.args[1].as_bytes().to_vec());
            let domain_from = PseudonymizationDomain::from(arg.args[2].as_str());
            let domain_to = PseudonymizationDomain::from(arg.args[3].as_str());
            let session_from = EncryptionContext::from(arg.args[4].as_str());
            let session_to = EncryptionContext::from(arg.args[5].as_str());
            let ciphertext =
                LongEncryptedPseudonym::deserialize(&arg.args[6]).expect("Invalid ciphertext.");
            let transcryption_info = TranscryptionInfo::new(
                &domain_from,
                &domain_to,
                &session_from,
                &session_to,
                &pseudonymization_secret,
                &encryption_secret,
            );
            let transcrypted = transcrypt(&ciphertext, &transcryption_info);
            eprint!("Transcrypted ciphertext (serialized): ");
            println!("{}", transcrypted.serialize());
        }
        #[cfg(feature = "long")]
        Some(Sub::EncryptLongAttribute(arg)) => {
            let public_key =
                AttributeSessionPublicKey::from_hex(&arg.args[0]).expect("Invalid public key.");
            let attributes: Vec<Attribute> = arg.args[1..]
                .iter()
                .map(|hex| Attribute::from_hex(hex).expect("Invalid attribute"))
                .collect();
            let long_attribute = LongAttribute(attributes);
            let ciphertext = long_attribute.encrypt(&public_key, &mut rng);
            eprint!("Ciphertext (serialized): ");
            println!("{}", ciphertext.serialize());
        }
        #[cfg(feature = "long")]
        Some(Sub::DecryptLongAttribute(arg)) => {
            let secret_key = AttributeSessionSecretKey::from(
                ScalarNonZero::from_hex(&arg.args[0]).expect("Invalid secret key."),
            );
            let ciphertext =
                LongEncryptedAttribute::deserialize(&arg.args[1]).expect("Invalid ciphertext.");
            #[cfg(feature = "elgamal3")]
            let plaintext = ciphertext
                .decrypt(&secret_key)
                .expect("Decryption failed: key mismatch");
            #[cfg(not(feature = "elgamal3"))]
            let plaintext = ciphertext.decrypt(&secret_key);
            let hex_blocks: Vec<String> = plaintext.0.iter().map(|a| a.to_hex()).collect();
            eprint!("Plaintext ({} blocks): ", plaintext.0.len());
            println!("{}", hex_blocks.join(" "));
        }
        #[cfg(feature = "long")]
        Some(Sub::TranscryptLongAttribute(arg)) => {
            let pseudonymization_secret =
                PseudonymizationSecret::from(arg.args[0].as_bytes().to_vec());
            let encryption_secret = EncryptionSecret::from(arg.args[1].as_bytes().to_vec());
            let domain_from = PseudonymizationDomain::from(arg.args[2].as_str());
            let domain_to = PseudonymizationDomain::from(arg.args[3].as_str());
            let session_from = EncryptionContext::from(arg.args[4].as_str());
            let session_to = EncryptionContext::from(arg.args[5].as_str());
            let ciphertext =
                LongEncryptedAttribute::deserialize(&arg.args[6]).expect("Invalid ciphertext.");
            let transcryption_info = TranscryptionInfo::new(
                &domain_from,
                &domain_to,
                &session_from,
                &session_to,
                &pseudonymization_secret,
                &encryption_secret,
            );
            let transcrypted = transcrypt(&ciphertext, &transcryption_info);
            eprint!("Transcrypted ciphertext (serialized): ");
            println!("{}", transcrypted.serialize());
        }
        Some(Sub::Rerandomize(arg)) => {
            let ciphertext =
                EncryptedPseudonym::from_base64(&arg.args[0]).expect("Invalid ciphertext.");
            let rerandomized;
            #[cfg(not(feature = "elgamal3"))]
            {
                let public_key =
                    PseudonymSessionPublicKey::from_hex(&arg.args[1]).expect("Invalid public key.");
                rerandomized = ciphertext.rerandomize(&public_key, &mut rng);
            }
            #[cfg(feature = "elgamal3")]
            {
                rerandomized = ciphertext.rerandomize(&mut rng);
            }
            eprint!("Rerandomized ciphertext: ");
            println!("{}", &rerandomized.to_base64());
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
                &session_from,
                &session_to,
                &pseudonymization_secret,
                &encryption_secret,
            );
            let transcrypted = transcrypt(&ciphertext, &transcryption_info);
            eprint!("Transcrypted ciphertext: ");
            println!("{}", &transcrypted.to_base64());
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
                &EncryptionContext::global(),
                &session_to,
                &pseudonymization_secret,
                &encryption_secret,
            );
            let transcrypted = transcrypt(&ciphertext, &transcryption_info);
            eprint!("Transcrypted ciphertext: ");
            println!("{}", &transcrypted.to_base64());
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
                &session_from,
                &EncryptionContext::global(),
                &pseudonymization_secret,
                &encryption_secret,
            );
            let transcrypted = transcrypt(&ciphertext, &transcryption_info);
            eprint!("Transcrypted ciphertext: ");
            println!("{}", &transcrypted.to_base64());
        }
        Some(Sub::TranscryptAttribute(arg)) => {
            let pseudonymization_secret =
                PseudonymizationSecret::from(arg.args[0].as_bytes().to_vec());
            let encryption_secret = EncryptionSecret::from(arg.args[1].as_bytes().to_vec());
            let domain_from = PseudonymizationDomain::from(arg.args[2].as_str());
            let domain_to = PseudonymizationDomain::from(arg.args[3].as_str());
            let session_from = EncryptionContext::from(arg.args[4].as_str());
            let session_to = EncryptionContext::from(arg.args[5].as_str());
            let ciphertext =
                EncryptedAttribute::from_base64(&arg.args[6]).expect("Invalid ciphertext.");
            let transcryption_info = TranscryptionInfo::new(
                &domain_from,
                &domain_to,
                &session_from,
                &session_to,
                &pseudonymization_secret,
                &encryption_secret,
            );
            let transcrypted = transcrypt(&ciphertext, &transcryption_info);
            eprint!("Transcrypted ciphertext: ");
            println!("{}", &transcrypted.to_base64());
        }
        #[cfg(feature = "json")]
        Some(Sub::JsonEncrypt(arg)) => {
            let pseudonym_global_secret = PseudonymGlobalSecretKey::from(
                ScalarNonZero::from_hex(&arg.args[0])
                    .expect("Invalid pseudonym global secret key."),
            );
            let attribute_global_secret = AttributeGlobalSecretKey::from(
                ScalarNonZero::from_hex(&arg.args[1])
                    .expect("Invalid attribute global secret key."),
            );
            let encryption_secret = EncryptionSecret::from(arg.args[2].as_bytes().to_vec());
            let session_context = EncryptionContext::from(arg.args[3].as_str());
            let pseudonym_fields_str = &arg.args[4];
            let json_string = &arg.args[5];

            let global_secrets = GlobalSecretKeys {
                pseudonym: pseudonym_global_secret,
                attribute: attribute_global_secret,
            };
            let session_keys =
                make_session_keys(&global_secrets, &session_context, &encryption_secret);

            // Parse pseudonym fields
            let pseudonym_fields: Vec<&str> = if pseudonym_fields_str.is_empty() {
                vec![]
            } else {
                pseudonym_fields_str.split(',').collect()
            };

            // Parse JSON
            let json: serde_json::Value = serde_json::from_str(json_string).expect("Invalid JSON");

            // Build PEP JSON
            let pep_json = PEPJSONBuilder::from_json(&json, &pseudonym_fields)
                .expect("Failed to build PEP JSON")
                .build();

            // Encrypt
            let encrypted = pep_json.encrypt(&session_keys, &mut rng);

            // Serialize to JSON
            let encrypted_json = serde_json::to_string(&encrypted).expect("Failed to serialize");
            eprint!("Encrypted JSON: ");
            println!("{}", encrypted_json);
        }
        #[cfg(feature = "json")]
        Some(Sub::JsonDecrypt(arg)) => {
            let pseudonym_global_secret = PseudonymGlobalSecretKey::from(
                ScalarNonZero::from_hex(&arg.args[0])
                    .expect("Invalid pseudonym global secret key."),
            );
            let attribute_global_secret = AttributeGlobalSecretKey::from(
                ScalarNonZero::from_hex(&arg.args[1])
                    .expect("Invalid attribute global secret key."),
            );
            let encryption_secret = EncryptionSecret::from(arg.args[2].as_bytes().to_vec());
            let session_context = EncryptionContext::from(arg.args[3].as_str());
            let encrypted_json_string = &arg.args[4];

            let global_secrets = GlobalSecretKeys {
                pseudonym: pseudonym_global_secret,
                attribute: attribute_global_secret,
            };
            let session_keys =
                make_session_keys(&global_secrets, &session_context, &encryption_secret);

            // Parse encrypted JSON
            let encrypted: EncryptedPEPJSONValue =
                serde_json::from_str(encrypted_json_string).expect("Invalid encrypted JSON");

            // Decrypt
            #[cfg(feature = "elgamal3")]
            let decrypted = encrypted
                .decrypt(&session_keys)
                .expect("Decryption failed: key mismatch");
            #[cfg(not(feature = "elgamal3"))]
            let decrypted = encrypted.decrypt(&session_keys);

            // Convert to JSON value
            let json = decrypted.to_value().expect("Failed to convert to JSON");
            let json_string = serde_json::to_string_pretty(&json).expect("Failed to serialize");
            eprint!("Decrypted JSON: ");
            println!("{}", json_string);
        }
        #[cfg(feature = "json")]
        Some(Sub::JsonTranscrypt(arg)) => {
            let pseudonymization_secret =
                PseudonymizationSecret::from(arg.args[0].as_bytes().to_vec());
            let encryption_secret = EncryptionSecret::from(arg.args[1].as_bytes().to_vec());
            let domain_from = PseudonymizationDomain::from(arg.args[2].as_str());
            let domain_to = PseudonymizationDomain::from(arg.args[3].as_str());
            let session_from = EncryptionContext::from(arg.args[4].as_str());
            let session_to = EncryptionContext::from(arg.args[5].as_str());
            let encrypted_json_string = &arg.args[6];

            // Parse encrypted JSON
            let encrypted: EncryptedPEPJSONValue =
                serde_json::from_str(encrypted_json_string).expect("Invalid encrypted JSON");

            let transcryption_info = TranscryptionInfo::new(
                &domain_from,
                &domain_to,
                &session_from,
                &session_to,
                &pseudonymization_secret,
                &encryption_secret,
            );

            // Transcrypt
            let transcrypted = transcrypt(&encrypted, &transcryption_info);

            // Serialize to JSON
            let transcrypted_json =
                serde_json::to_string(&transcrypted).expect("Failed to serialize");
            eprint!("Transcrypted JSON: ");
            println!("{}", transcrypted_json);
        }
        Some(Sub::SetupDistributedSystems(arg)) => {
            let n = arg.args[0]
                .parse::<usize>()
                .expect("Invalid number of nodes.");
            let (global_public_keys, blinded_global_keys, blinding_factors): (
                _,
                _,
                Vec<BlindingFactor>,
            ) = make_distributed_global_keys(n, &mut rng);
            eprintln!("Public global keys:");
            eprintln!("  - Attributes: {}", &global_public_keys.attribute.to_hex());
            eprintln!("  - Pseudonyms: {}", &global_public_keys.pseudonym.to_hex());
            eprintln!("Blinded secret keys:");
            eprintln!(
                "  - Attributes: {}",
                &blinded_global_keys.attribute.to_hex()
            );
            eprintln!(
                "  - Pseudonyms: {}",
                &blinded_global_keys.pseudonym.to_hex()
            );
            eprintln!("Blinding factors (keep secret):");
            for factor in &blinding_factors {
                eprintln!("  - {}", factor.to_hex());
            }
        }
        None => {
            eprintln!("No subcommand given.");
            std::process::exit(1);
        }
    }
}
