//! End-to-end tests of the `peppy` command-line tool, run against the built binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;
use std::io::Write;
use std::process::{Command, Stdio};

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

fn peppy_with_stdin(args: &[&str], stdin: Option<&str>) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_peppy"))
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("peppy starts");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    Run {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

/// Run peppy and return its single output line.
fn peppy(args: &[&str]) -> String {
    let run = peppy_with_stdin(args, None);
    assert_eq!(run.status, 0, "peppy {args:?} failed: {}", run.stderr);
    run.stdout.trim().to_string()
}

/// Run peppy with `--json` and return the output object.
fn peppy_json(args: &[&str]) -> serde_json::Value {
    let mut full = vec!["--json"];
    full.extend_from_slice(args);
    let run = peppy_with_stdin(&full, None);
    assert_eq!(run.status, 0, "peppy {args:?} failed: {}", run.stderr);
    serde_json::from_str(&run.stdout).expect("JSON output")
}

fn field<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing {key} in {v}"))
}

struct Session {
    keys: serde_json::Value,
}

impl Session {
    fn public(&self) -> &str {
        field(&self.keys, "pseudonym_public_key")
    }
    fn secret(&self) -> &str {
        field(&self.keys, "pseudonym_secret_key")
    }
}

/// Global keys and session keys for two contexts, derived through the CLI.
fn setup() -> (serde_json::Value, Session, Session) {
    let global = peppy_json(&["keys", "global", "generate"]);
    let derive = |context: &str| Session {
        keys: peppy_json(&[
            "keys",
            "session",
            "derive",
            "--pseudonym-global-secret",
            field(&global, "pseudonym_secret_key"),
            "--attribute-global-secret",
            field(&global, "attribute_secret_key"),
            "--encryption-secret",
            "encryption secret",
            "--context",
            context,
        ]),
    };
    (global.clone(), derive("session-a"), derive("session-b"))
}

/// The `--key` argument of transcryption commands: the public key the ciphertext is encrypted
/// under. With `elgamal3` the ciphertext carries it and the argument does not exist.
fn key_arg(public_key: &str) -> Vec<&str> {
    #[cfg(feature = "elgamal3")]
    {
        let _ = public_key;
        vec![]
    }
    #[cfg(not(feature = "elgamal3"))]
    {
        vec!["--key", public_key]
    }
}

/// Run a transcryption command with `--json` and return the ciphertext and, without `elgamal3`,
/// the public key it is now encrypted under (empty otherwise).
fn transcrypt(args: &[&str]) -> (String, String) {
    let out = peppy_json(args);
    let key = out
        .get("key")
        .and_then(|k| k.as_str())
        .unwrap_or("")
        .to_string();
    (field(&out, "ciphertext").to_string(), key)
}

const TRANSCRYPT: [&str; 4] = [
    "--pseudonymization-secret",
    "pseudonymization secret",
    "--encryption-secret",
    "encryption secret",
];

#[test]
fn pseudonym_round_trip_through_transcryption() {
    let (_, a, b) = setup();
    let value = peppy(&["pseudonym", "encode", "patient-42"]);
    let encrypted = peppy(&["pseudonym", "encrypt", "--key", a.public(), &value]);
    let mut args = vec!["pseudonym", "transcrypt"];
    args.extend_from_slice(&TRANSCRYPT);
    args.extend_from_slice(&key_arg(a.public()));
    args.extend_from_slice(&[
        "--from-domain",
        "hospital",
        "--to-domain",
        "research",
        "--from-context",
        "session-a",
        "--to-context",
        "session-b",
        &encrypted,
    ]);
    let (transcrypted, _key) = transcrypt(&args);
    #[cfg(not(feature = "elgamal3"))]
    assert_eq!(_key, b.public(), "transcryption outputs the receiver's key");
    let in_b = peppy(&["pseudonym", "decrypt", "--key", b.secret(), &transcrypted]);
    assert_ne!(in_b, value, "pseudonym must differ between domains");

    let mut back = vec!["pseudonym", "transcrypt"];
    back.extend_from_slice(&TRANSCRYPT);
    back.extend_from_slice(&key_arg(b.public()));
    back.extend_from_slice(&[
        "--from-domain",
        "research",
        "--to-domain",
        "hospital",
        "--from-context",
        "session-b",
        "--to-context",
        "session-a",
        &transcrypted,
    ]);
    let (returned, _) = transcrypt(&back);
    let in_a = peppy(&["pseudonym", "decrypt", "--key", a.secret(), &returned]);
    assert_eq!(in_a, value);
    assert_eq!(peppy(&["pseudonym", "decode", &in_a]), "patient-42");
}

#[test]
fn attribute_is_rekeyed_not_reshuffled() {
    let (_, a, b) = setup();
    let value = peppy(&["attribute", "encode", "blood type O"]);
    let encrypted = peppy(&[
        "attribute",
        "encrypt",
        "--key",
        field(&a.keys, "attribute_public_key"),
        &value,
    ]);
    let mut args = vec!["attribute", "transcrypt"];
    args.extend_from_slice(&key_arg(field(&a.keys, "attribute_public_key")));
    args.extend_from_slice(&[
        "--encryption-secret",
        "encryption secret",
        "--from-context",
        "session-a",
        "--to-context",
        "session-b",
        &encrypted,
    ]);
    let (transcrypted, _) = transcrypt(&args);
    let decrypted = peppy(&[
        "attribute",
        "decrypt",
        "--key",
        field(&b.keys, "attribute_secret_key"),
        &transcrypted,
    ]);
    assert_eq!(decrypted, value);
    assert_eq!(peppy(&["attribute", "decode", &decrypted]), "blood type O");
}

#[test]
fn long_values_round_trip() {
    let (_, a, _) = setup();
    let text = "an identifier that is much longer than sixteen bytes";
    let value = peppy(&["pseudonym", "encode", text]);
    assert!(
        value.split(' ').count() > 1,
        "long value has several blocks"
    );
    let encrypted = peppy(&["pseudonym", "encrypt", "--key", a.public(), &value]);
    assert!(
        encrypted.contains('|'),
        "long ciphertext has several blocks"
    );
    let decrypted = peppy(&["pseudonym", "decrypt", "--key", a.secret(), &encrypted]);
    assert_eq!(decrypted, value);
    assert_eq!(peppy(&["pseudonym", "decode", &decrypted]), text);
    // The blocks may also be given concatenated.
    let joined = value.replace(' ', "");
    assert_eq!(peppy(&["pseudonym", "decode", &joined]), text);
}

#[test]
fn explicit_factors_match_the_transcryptor() {
    let (_, a, b) = setup();
    let info = peppy_json(&[
        "factors",
        "info",
        "--pseudonymization-secret",
        "pseudonymization secret",
        "--encryption-secret",
        "encryption secret",
        "--from-domain",
        "hospital",
        "--to-domain",
        "research",
        "--from-context",
        "session-a",
        "--to-context",
        "session-b",
    ]);
    let value = peppy(&["pseudonym", "random"]);
    let encrypted = peppy(&["pseudonym", "encrypt", "--key", a.public(), &value]);
    let mut args = vec!["pseudonym", "pseudonymize"];
    args.extend_from_slice(&key_arg(a.public()));
    args.extend_from_slice(&[
        "--s",
        field(&info, "reshuffle_factor"),
        "--k",
        field(&info, "pseudonym_rekey_factor"),
        &encrypted,
    ]);
    let (by_factors, _) = transcrypt(&args);
    let mut args = vec!["pseudonym", "transcrypt"];
    args.extend_from_slice(&TRANSCRYPT);
    args.extend_from_slice(&key_arg(a.public()));
    args.extend_from_slice(&[
        "--from-domain",
        "hospital",
        "--to-domain",
        "research",
        "--from-context",
        "session-a",
        "--to-context",
        "session-b",
        &encrypted,
    ]);
    let (by_transcryptor, _) = transcrypt(&args);
    let d1 = peppy(&["pseudonym", "decrypt", "--key", b.secret(), &by_factors]);
    let d2 = peppy(&[
        "pseudonym",
        "decrypt",
        "--key",
        b.secret(),
        &by_transcryptor,
    ]);
    assert_eq!(d1, d2);
}

#[test]
fn primitives_compose() {
    let s = peppy(&["scalar", "random"]);
    let k = peppy(&["scalar", "random"]);
    let y = peppy(&["scalar", "random"]);
    let public = peppy(&["point", "base", &y]);
    let message = peppy(&["point", "random"]);
    let encrypted = peppy(&["elgamal", "encrypt", "--key", &public, &message]);

    // rsk is reshuffle followed by rekey.
    let rsk = peppy(&["elgamal", "rsk", "--s", &s, "--k", &k, &encrypted]);
    let rs = peppy(&["elgamal", "rs", "--s", &s, &encrypted]);
    let rs_rk = peppy(&["elgamal", "rk", "--k", &k, &rs]);
    assert_eq!(rsk, rs_rk);

    // Rekeying with k makes the ciphertext decryptable under k * y.
    let ky = peppy(&["scalar", "mul", &k, &y]);
    let rekeyed = peppy(&["elgamal", "rk", "--k", &k, &encrypted]);
    assert_eq!(
        peppy(&["elgamal", "decrypt", "--key", &ky, &rekeyed]),
        message
    );

    // The transitive variants are reversible.
    let (s_from, s_to) = (peppy(&["scalar", "random"]), peppy(&["scalar", "random"]));
    let forth = peppy(&[
        "elgamal", "rs2", "--from", &s_from, "--to", &s_to, &encrypted,
    ]);
    let back = peppy(&["elgamal", "rs2", "--from", &s_to, "--to", &s_from, &forth]);
    assert_eq!(peppy(&["elgamal", "decrypt", "--key", &y, &back]), message);

    // Rerandomization changes the ciphertext but not the message.
    #[cfg(feature = "elgamal3")]
    let rr = peppy(&["elgamal", "rr", &encrypted]);
    #[cfg(not(feature = "elgamal3"))]
    let rr = peppy(&["elgamal", "rr", "--key", &public, &encrypted]);
    let rr = rr.lines().last().unwrap().to_string();
    assert_ne!(rr, encrypted);
    assert_eq!(peppy(&["elgamal", "decrypt", "--key", &y, &rr]), message);
}

#[test]
fn distributed_setup_shares_and_reconstruction() {
    let n = 3;
    let setup = peppy_json(&["keys", "distributed", "setup", "-n", "3"]);
    let factors: Vec<&str> = setup["blinding_factors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert_eq!(factors.len(), n);

    // Each transcryptor produces its shares for the client's session, with a proof of each.
    let secrets: Vec<String> = (0..n).map(|i| format!("secret-{i}")).collect();
    let shares: Vec<serde_json::Value> = (0..n)
        .map(|i| {
            peppy_json(&[
                "keys",
                "distributed",
                "share",
                "--prove",
                "--blinding",
                factors[i],
                "--encryption-secret",
                &secrets[i],
                "--context",
                "session-1",
            ])
        })
        .collect();
    assert!(shares[0]["pseudonym_share_proof"].is_object());
    assert!(shares[0]["attribute_share_proof"].is_object());
    let mut args = vec![
        "keys",
        "distributed",
        "reconstruct",
        "--blinded-pseudonym",
        field(&setup, "blinded_pseudonym_secret_key"),
        "--blinded-attribute",
        field(&setup, "blinded_attribute_secret_key"),
    ];
    for share in &shares {
        args.extend_from_slice(&["--pseudonym-share", field(share, "pseudonym_share")]);
        args.extend_from_slice(&["--attribute-share", field(share, "attribute_share")]);
    }
    let session = peppy_json(&args);

    // Data encrypted towards the global key and transcrypted by every transcryptor in turn
    // decrypts with the reconstructed session key.
    let value = peppy(&["pseudonym", "random"]);
    let mut current = peppy(&[
        "pseudonym",
        "encrypt",
        "--global",
        "--key",
        field(&setup, "pseudonym_public_key"),
        &value,
    ]);
    // The key the ciphertext is encrypted under travels with it: the global key at first, then
    // whatever each transcryptor outputs.
    let mut current_key = field(&setup, "pseudonym_public_key").to_string();
    for secret in &secrets {
        let mut args = vec!["pseudonym", "transcrypt"];
        args.extend_from_slice(&key_arg(&current_key));
        args.extend_from_slice(&[
            "--pseudonymization-secret",
            secret,
            "--encryption-secret",
            secret,
            "--from-domain",
            "domain",
            "--to-domain",
            "domain",
            "--to-context",
            "session-1",
            &current,
        ]);
        (current, current_key) = transcrypt(&args);
    }
    #[cfg(not(feature = "elgamal3"))]
    assert_eq!(
        current_key,
        field(&session, "pseudonym_public_key"),
        "after all transcryptors the key is the reconstructed session key"
    );
    let decrypted = peppy(&[
        "pseudonym",
        "decrypt",
        "--key",
        field(&session, "pseudonym_secret_key"),
        &current,
    ]);
    assert_eq!(decrypted, value);

    // Moving one transcryptor's share to another session updates the key consistently.
    let new_share = peppy_json(&[
        "keys",
        "distributed",
        "share",
        "--blinding",
        factors[0],
        "--encryption-secret",
        &secrets[0],
        "--context",
        "session-2",
    ]);
    let updated = peppy_json(&[
        "keys",
        "distributed",
        "update",
        "--secret-key",
        field(&session, "pseudonym_secret_key"),
        "--old-share",
        field(&shares[0], "pseudonym_share"),
        "--new-share",
        field(&new_share, "pseudonym_share"),
    ]);
    let mut args = vec!["pseudonym", "transcrypt"];
    args.extend_from_slice(&key_arg(field(&session, "pseudonym_public_key")));
    args.extend_from_slice(&[
        "--pseudonymization-secret",
        &secrets[0],
        "--encryption-secret",
        &secrets[0],
        "--from-domain",
        "domain",
        "--to-domain",
        "domain",
        "--from-context",
        "session-1",
        "--to-context",
        "session-2",
        &current,
    ]);
    let (moved, _) = transcrypt(&args);
    let decrypted = peppy(&[
        "pseudonym",
        "decrypt",
        "--key",
        field(&updated, "pseudonym_secret_key"),
        &moved,
    ]);
    assert_eq!(decrypted, value);
}

#[cfg(feature = "json")]
#[test]
fn json_documents() {
    let (_, a, b) = setup();
    let keys_a = a.keys.to_string();
    let keys_b = b.keys.to_string();
    let encrypted = peppy_json(&[
        "json",
        "encrypt",
        "--keys",
        &keys_a,
        "--pseudonym-field",
        "id",
        r#"{"id":"patient-42","age":41}"#,
    ])["encrypted"]
        .to_string();
    let mut args = vec!["json", "transcrypt"];
    args.extend_from_slice(&TRANSCRYPT);
    #[cfg(not(feature = "elgamal3"))]
    args.extend_from_slice(&["--keys", &keys_a]);
    args.extend_from_slice(&[
        "--from-domain",
        "hospital",
        "--to-domain",
        "research",
        "--from-context",
        "session-a",
        "--to-context",
        "session-b",
        &encrypted,
    ]);
    let transcrypted = peppy_json(&args)["encrypted"].to_string();
    let document = peppy_json(&["json", "decrypt", "--keys", &keys_b, &transcrypted]);
    assert_eq!(document["document"]["age"], 41);
    assert_ne!(document["document"]["id"], "patient-42");
}

/// The commitments of the hospital→research, session-a→session-b transition.
fn commitments() -> serde_json::Value {
    let mut args = vec!["factors", "commitments"];
    args.extend_from_slice(&TRANSCRYPT);
    args.extend_from_slice(&[
        "--from-domain",
        "hospital",
        "--to-domain",
        "research",
        "--from-context",
        "session-a",
        "--to-context",
        "session-b",
    ]);
    peppy_json(&args)
}

#[test]
fn proofs_of_pseudonymization_verify() {
    let (_, a, b) = setup();
    let commitments = commitments();
    for text in [
        "patient-42",
        "an identifier that is much longer than sixteen bytes",
    ] {
        let value = peppy(&["pseudonym", "encode", text]);
        let encrypted = peppy(&["pseudonym", "encrypt", "--key", a.public(), &value]);
        let mut args = vec!["pseudonym", "transcrypt", "--prove"];
        args.extend_from_slice(&TRANSCRYPT);
        args.extend_from_slice(&key_arg(a.public()));
        args.extend_from_slice(&[
            "--from-domain",
            "hospital",
            "--to-domain",
            "research",
            "--from-context",
            "session-a",
            "--to-context",
            "session-b",
            &encrypted,
        ]);
        let proven = peppy_json(&args);
        let proof = proven["proof"].to_string();
        let mut verify = vec!["pseudonym", "verify-pseudonymize"];
        verify.extend_from_slice(&key_arg(a.public()));
        verify.extend_from_slice(&[
            "--reshuffle-commitment",
            field(&commitments, "reshuffle_commitment"),
            "--rekey-commitment",
            field(&commitments, "pseudonym_rekey_commitment"),
            "--proof",
            &proof,
            &encrypted,
        ]);
        let verified = peppy(&verify);
        assert_eq!(verified, field(&proven, "ciphertext"));
        let decrypted = peppy(&["pseudonym", "decrypt", "--key", b.secret(), &verified]);
        assert_ne!(decrypted, value);

        // The proof does not verify against the wrong commitments or the wrong ciphertext.
        let swapped: Vec<&str> = verify
            .iter()
            .map(|arg| {
                if *arg == field(&commitments, "reshuffle_commitment") {
                    field(&commitments, "pseudonym_rekey_commitment")
                } else {
                    arg
                }
            })
            .collect();
        let run = peppy_with_stdin(&swapped, None);
        assert_eq!(run.status, 4, "{}", run.stderr);
        assert!(run.stderr.contains("does not verify"), "{}", run.stderr);
        assert!(run.stdout.is_empty());
        let other = peppy(&["pseudonym", "encrypt", "--key", a.public(), &value]);
        verify.pop();
        verify.push(&other);
        assert_eq!(peppy_with_stdin(&verify, None).status, 4);
    }
}

#[test]
fn proofs_of_rekeying_verify() {
    let (_, a, b) = setup();
    let commitments = commitments();
    let value = peppy(&["attribute", "encode", "blood type O"]);
    let encrypted = peppy(&[
        "attribute",
        "encrypt",
        "--key",
        field(&a.keys, "attribute_public_key"),
        &value,
    ]);
    let mut args = vec!["attribute", "transcrypt", "--prove"];
    args.extend_from_slice(&key_arg(field(&a.keys, "attribute_public_key")));
    args.extend_from_slice(&[
        "--encryption-secret",
        "encryption secret",
        "--from-context",
        "session-a",
        "--to-context",
        "session-b",
        &encrypted,
    ]);
    let proven = peppy_json(&args);
    let verified = peppy(&[
        "attribute",
        "verify-rekey",
        "--rekey-commitment",
        field(&commitments, "attribute_rekey_commitment"),
        "--proof",
        &proven["proof"].to_string(),
        &encrypted,
    ]);
    assert_eq!(verified, field(&proven, "ciphertext"));
    let decrypted = peppy(&[
        "attribute",
        "decrypt",
        "--key",
        field(&b.keys, "attribute_secret_key"),
        &verified,
    ]);
    assert_eq!(decrypted, value);

    // Rekeying a pseudonym with an explicit factor proves against the commitment to that factor.
    let k = peppy(&["scalar", "random"]);
    let commitment = peppy(&["point", "base", &k]);
    let value = peppy(&["pseudonym", "random"]);
    let encrypted = peppy(&["pseudonym", "encrypt", "--key", a.public(), &value]);
    let mut args = vec!["pseudonym", "rekey", "--prove", "--k", &k];
    args.extend_from_slice(&key_arg(a.public()));
    args.push(&encrypted);
    let proven = peppy_json(&args);
    let verified = peppy(&[
        "pseudonym",
        "verify-rekey",
        "--rekey-commitment",
        &commitment,
        "--proof",
        &proven["proof"].to_string(),
        &encrypted,
    ]);
    assert_eq!(verified, field(&proven, "ciphertext"));
}

#[cfg(feature = "json")]
#[test]
fn proofs_of_json_transcryption_verify() {
    let (_, a, b) = setup();
    let commitments = commitments();
    let keys_a = a.keys.to_string();
    let keys_b = b.keys.to_string();
    let encrypted = peppy_json(&[
        "json",
        "encrypt",
        "--keys",
        &keys_a,
        "--pseudonym-field",
        "id",
        r#"{"id":"patient-42","age":41,"notes":["a note that is longer than sixteen bytes"]}"#,
    ])["encrypted"]
        .to_string();
    let mut args = vec!["json", "transcrypt", "--prove"];
    args.extend_from_slice(&TRANSCRYPT);
    #[cfg(not(feature = "elgamal3"))]
    args.extend_from_slice(&["--keys", &keys_a]);
    args.extend_from_slice(&[
        "--from-domain",
        "hospital",
        "--to-domain",
        "research",
        "--from-context",
        "session-a",
        "--to-context",
        "session-b",
        &encrypted,
    ]);
    let proven = peppy_json(&args);
    let proof = proven["proof"].to_string();
    let mut verify = vec!["json", "verify-transcrypt"];
    #[cfg(not(feature = "elgamal3"))]
    verify.extend_from_slice(&["--keys", &keys_a]);
    verify.extend_from_slice(&[
        "--reshuffle-commitment",
        field(&commitments, "reshuffle_commitment"),
        "--pseudonym-rekey-commitment",
        field(&commitments, "pseudonym_rekey_commitment"),
        "--attribute-rekey-commitment",
        field(&commitments, "attribute_rekey_commitment"),
        "--proof",
        &proof,
        &encrypted,
    ]);
    let verified = peppy_json(&verify);
    assert_eq!(verified["encrypted"], proven["encrypted"]);
    let document = peppy_json(&[
        "json",
        "decrypt",
        "--keys",
        &keys_b,
        &verified["encrypted"].to_string(),
    ]);
    assert_eq!(document["document"]["age"], 41);
    assert_eq!(
        document["document"]["notes"][0],
        "a note that is longer than sixteen bytes"
    );
    assert_ne!(document["document"]["id"], "patient-42");

    // Swapping the two rekey commitments breaks the proof.
    let swapped: Vec<&str> = verify
        .iter()
        .map(|arg| {
            if *arg == field(&commitments, "attribute_rekey_commitment") {
                field(&commitments, "pseudonym_rekey_commitment")
            } else {
                arg
            }
        })
        .collect();
    let mut full = vec!["--json"];
    full.extend_from_slice(&swapped);
    assert_eq!(peppy_with_stdin(&full, None).status, 4);
}

#[test]
fn inputs_from_stdin_and_files() {
    let (_, a, _) = setup();
    let value = peppy(&["pseudonym", "random"]);
    let encrypted = peppy(&["pseudonym", "encrypt", "--key", a.public(), &value]);
    let dir = std::env::temp_dir().join(format!("peppy-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = dir.join("key");
    std::fs::write(&key_file, format!("{}\n", a.secret())).unwrap();
    let key_arg = format!("@{}", key_file.display());
    let run = peppy_with_stdin(
        &["pseudonym", "decrypt", "--key", &key_arg, "-"],
        Some(&format!("{encrypted}\n")),
    );
    assert_eq!(run.status, 0, "{}", run.stderr);
    assert_eq!(run.stdout.trim(), value);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn errors_have_messages_and_exit_codes() {
    let run = peppy_with_stdin(&["pseudonym", "decrypt", "--key", "nope", "AAAA"], None);
    assert_eq!(run.status, 1);
    assert!(run.stderr.contains("session secret key"), "{}", run.stderr);
    assert!(run.stdout.is_empty());

    #[cfg(feature = "elgamal3")]
    {
        let (_, a, b) = setup();
        let value = peppy(&["pseudonym", "random"]);
        let encrypted = peppy(&["pseudonym", "encrypt", "--key", a.public(), &value]);
        let run = peppy_with_stdin(
            &["pseudonym", "decrypt", "--key", b.secret(), &encrypted],
            None,
        );
        assert_eq!(run.status, 3, "{}", run.stderr);
        assert!(run.stderr.contains("does not match"));
    }
}

#[test]
fn json_output_holds_every_value() {
    let global = peppy_json(&["keys", "global", "generate"]);
    let keys: HashSet<&str> = global
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    for expected in [
        "pseudonym_public_key",
        "pseudonym_secret_key",
        "attribute_public_key",
        "attribute_secret_key",
    ] {
        assert!(keys.contains(expected), "{expected} missing from {global}");
    }
}
