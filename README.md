# `libpep`: Library for polymorphic encryption and pseudonymization
[![Crates.io](https://img.shields.io/crates/v/libpep.svg)](https://crates.io/crates/libpep)
[![Downloads](https://img.shields.io/crates/d/libpep)](https://crates.io/crates/libpep)
[![PyPI](https://img.shields.io/pypi/v/libpep-py)](https://pypi.org/project/libpep-py/)
[![Downloads](https://img.shields.io/pypi/dm/libpep-py)](https://pypi.org/project/libpep-py/)
[![npm](https://img.shields.io/npm/v/@nolai/libpep-wasm)](https://www.npmjs.com/package/@nolai/libpep-wasm)
[![Downloads](https://img.shields.io/npm/dm/@nolai/libpep-wasm.svg)](https://www.npmjs.com/package/@nolai/libpep-wasm)
[![License](https://img.shields.io/crates/l/libpep.svg)](https://crates.io/crates/libpep)
[![Documentation](https://docs.rs/libpep/badge.svg)](https://docs.rs/libpep)
[![Dependencies](https://deps.rs/repo/github/NOLAI/libpep/status.svg)](https://deps.rs/repo/github/NOLAI/libpep)

`libpep` implements *n-PEP*, a scheme for end-to-end encrypted, pseudonymized data sharing.
Every party knows its data subjects under its own pseudonyms, which cannot be linked to another party's.
Encrypted data is blindly re-encrypted (*transcrypted*) for a receiving party by semi-trusted *transcryptors*, which convert the pseudonyms in it to the receiver's domain without decrypting anything.
Transcryption can be distributed over `n` transcryptors, so that every transcryptor can independently monitor and block data exchanges, while confidentiality and pseudonym unlinkability hold as long as at least one of them remains uncompromised.

The library is the reference implementation of the n-PEP paper (see [Background](#background)).
It ships as a Rust crate with Python and JavaScript/WebAssembly bindings that mirror the Rust API.

## Installation

Rust, in `Cargo.toml`:
```toml
[dependencies]
libpep = "0.13"
```

Python, importable as `libpep`:
```bash
pip install libpep-py
```

JavaScript, for Node.js and browsers:
```bash
npm install @nolai/libpep-wasm
```

The `peppy` command-line tool is installed with `cargo install libpep`.

## Quick start

A transcryptor holds two secrets from which all its factors derive.
Every party works in its own *pseudonymization domain* (typically its role or user group) and *encryption context* (typically a session), and holds session keys for that context.

```rust
use libpep::client::{decrypt, encrypt};
use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::data::simple::{ElGamalEncryptable, Pseudonym};
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use libpep::keys::{make_global_keys, make_session_keys};
use libpep::transcryptor::Transcryptor;

let rng = &mut rand::rng();

// System setup: global keys, and the secrets of the transcryptor.
let (_global_public, global_secret) = make_global_keys(rng);
let transcryptor = Transcryptor::new(
    PseudonymizationSecret::from(b"pseudonymization secret".to_vec()),
    EncryptionSecret::from(b"encryption secret".to_vec()),
);

// Party A and party B each have a pseudonymization domain, an encryption context and session keys.
let (domain_a, session_a) = (PseudonymizationDomain::from("hospital"), EncryptionContext::from("session-a"));
let (domain_b, session_b) = (PseudonymizationDomain::from("research"), EncryptionContext::from("session-b"));
let keys_a = make_session_keys(&global_secret, &session_a, transcryptor.rekeying_secret());
let keys_b = make_session_keys(&global_secret, &session_b, transcryptor.rekeying_secret());

// A encrypts one of its pseudonyms for its own session.
let pseudonym_a = Pseudonym::random(rng);
let encrypted = encrypt(&pseudonym_a, &keys_a.pseudonym.public, rng);

// The transcryptor converts it to B's domain and session, without decrypting it.
let info = transcryptor.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
let transcrypted = transcryptor.transcrypt(&encrypted, &info);

// B decrypts its own pseudonym for the same subject, which is unlinkable to A's.
let pseudonym_b = decrypt(&transcrypted, &keys_b.pseudonym.secret);
assert_ne!(pseudonym_a, pseudonym_b);

// Transcryption is reversible: converting back yields A's pseudonym again.
let back = transcryptor.transcrypt(&transcrypted, &info.reverse());
assert_eq!(pseudonym_a, decrypt(&back, &keys_a.pseudonym.secret));
```

Attributes (`Attribute`, `LongAttribute`) are encrypted and transcrypted the same way, but only rekeyed, never converted between domains.
With the `json` feature, whole JSON documents with nested pseudonyms and attributes are encrypted and transcrypted as one value.

In the distributed setting, `keys::distribution::make_distributed_global_keys` produces a blinded global key and one blinding factor per transcryptor, each `transcryptor::DistributedTranscryptor` hands a client a *session key share*, and `client::Client::from_shares` reconstructs the session keys from the shares.
No party ever holds the global secret key.
[`tests/distributed.rs`](tests/distributed.rs) walks through this flow; the Python and JavaScript test suites under [`bindings/`](bindings/) do the same in those languages.

## How it works

In the ElGamal scheme, a message `M` is encrypted for a receiver with public key `Y`, belonging to secret key `y`.
Encryption is randomized (*polymorphic*): every fresh random `b` gives a different ciphertext for the same message.
We write it as `Enc(b, M, Y)`.

The library provides three homomorphic operations on a ciphertext `in = Enc(b, M, Y)`:

- `rekey(in, k)`: if `in` can be decrypted with `y`, the result can be decrypted with `k*y`, and both decrypt to `M`.
  `Enc(b, M, Y)` becomes `Enc(k^-1*b, M, k*Y)`.
- `reshuffle(in, s)`: changes the message so that decrypting the result yields `s*M`.
  `Enc(b, M, Y)` becomes `Enc(s*b, s*M, Y)`.
- `rerandomize(in, r)`: changes the binary form of the ciphertext only; it still decrypts with `y` to `M`.
  `Enc(b, M, Y)` becomes `Enc(b+r, M, Y)`.

Because these operations work on *encrypted* data, the receiver does not need to be known at encryption time.
Data is encrypted once and later rekeyed, and reshuffled if it is an identifier, for whichever party is granted access: non-interactive, asynchronous end-to-end encryption with built-in pseudonymization.

### Pseudonymization

Every party knows a data subject under its own *local pseudonym*, and reshuffling converts a pseudonym from one party's domain to another's, applying `s = s_from^-1 * s_to`, without a global pseudonym existing in between.
The factor `s` is tied to the *pseudonymization domain* of a party.

Pseudonym unlinkability rests on the fact that `F_s(M) = s*M` is the Diffie–Hellman pseudorandom function (DH-PRF): as long as `s` stays secret, `s*M` is indistinguishable from a random group element under the Decisional Diffie–Hellman (DDH) assumption, so pseudonyms in different domains cannot be linked without knowing the ratio of their domain factors.
Reshuffling an *encrypted* pseudonym is an encryption-based *oblivious evaluation* of this PRF: because the operation is homomorphic, the transcryptor applies its secret factor `s` without ever seeing the pseudonym or the result, and the sender and recipient never learn `s`.

> [!NOTE]
> Strictly, the DH-PRF is `F_s(M) = s*H(M)` for a hash `H` into the group: without `H`, `F_s` is linear (`F_s(a*M) = a*F_s(M)`) and thus not pseudorandom for inputs with known discrete-log relations.
> This library omits `H` because origin identifiers are expected to be uniformly random group elements, either sampled directly or produced by the elligator2-based lizard encoding, which makes it infeasible to construct identifiers with known relations.
> Importing group elements with other distributions (via `from_bytes` or `from_hex`) preserves any discrete-log relation between origin identifiers in every domain (if `M1 = 2*M2`, then also `s*M1 = 2*(s*M2)`).
> Individual pseudonyms remain unlinkable across domains under DDH, so this is acceptable as long as no party knows the relations between origin identifiers.

A reshuffle alone is not enough, as the pseudonym is still encrypted for a key the receiving party does not possess.
A *rekey* with `k` makes it decryptable with `k*y`, in combination with a protocol to hand the party that secret key.
The factor `k` is tied to the *encryption context* of a party, typically its current session.
`rsk(in, s, k)` performs both at once, and `reshuffle2`, `rekey2` and `rsk2` are the transitive and reversible n-PEP variants that convert directly between two domains or sessions, applying `s = s_from^-1 * s_to` and `k = k_from^-1 * k_to`.

When the same encrypted pseudonym is used more than once, it is rerandomized every time, so that comparing ciphertexts byte for byte reveals nothing.
Mixing fresh randomness into a ciphertext before reshuffling also protects against plaintext injection at transcryption.

## Relation to other primitives

`libpep` combines two familiar primitives: `reshuffle` is an OPRF evaluation and `rekey` is a proxy re-encryption, applied to the same ciphertext.

### As a three-party OPRF

[RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html) specifies oblivious pseudorandom functions over prime-order groups as a two-party protocol: a *client* blinds an input, a *server* applies its secret key, and the client unblinds to obtain the PRF output, with the server learning neither input nor output.

`libpep` evaluates the same DH-PRF `F_s(M) = s*M`, but splits the client role over a **sender** and a **recipient**, with the **transcryptor** as evaluator.
ElGamal encryption takes the place of blinding: the sender's encryption randomness `b` blinds the pseudonym, the transcryptor reshuffles with its domain factor `s`, and the recipient's decryption unblinds.
The transcryptor learns neither `M` nor `s*M`, and neither sender nor recipient learns `s`.
Because blinding and unblinding are performed by different parties, evaluation is non-interactive and asynchronous: the sender can encrypt before the recipient is known, and the PRF output appears only in the recipient's domain.

Two differences with the RFC are worth noting.
RFC 9497 hashes the input into the group first; `libpep` omits that hash and relies on origin identifiers being uniformly random group elements, as described above.
And the RFC's VOPRF and POPRF modes provide verifiability, whereas plain PEP transcryption does not: a transcryptor that applies a wrong factor produces an incorrect pseudonym undetectably.

### As proxy re-encryption with built-in pseudonymization

`rekey` is ordinary unidirectional [proxy re-encryption](https://en.wikipedia.org/wiki/Proxy_re-encryption) over ElGamal: it transforms `Enc(b, M, Y)` into `Enc(k^-1*b, M, k*Y)`, decryptable by `k*y`, with the transcryptor acting as the proxy without learning the message or holding either secret key.
`reshuffle` adds the one transformation a plain proxy cannot do, mapping `M` to `s*M`.
Attributes are never reshuffled, so for attributes the scheme is exactly proxy re-encryption; for identifiers, the same homomorphic step that re-encrypts a pseudonym for a new recipient also rewrites it into that recipient's domain, so no global identifier is ever exposed.

This is what the name refers to: *polymorphic* encryption is the proxy re-encryption, and *pseudonymization* is the PRF evaluation carried out in the same step.

## API overview

| Module | Description |
|--------|-------------|
| `client` | Encryption and decryption with session keys, or with global public keys for offline encryption; the `Distributed` extension reconstructs session keys from shares |
| `transcryptor` | Pseudonymization, rekeying and transcryption, single and in batch; `DistributedTranscryptor` produces session key shares |
| `data` | `Pseudonym` and `Attribute`, their long (multi-block) variants, records, and JSON documents with nested pseudonyms and attributes |
| `keys` | Global and session key types and generation, and the distributed key setup with blinding factors and shares |
| `contexts` | `PseudonymizationDomain` and `EncryptionContext`, the identifiers that data is pseudonymized and encrypted for |
| `factors` | Reshuffle, rekey and rerandomize factors, the transcryption info that bundles them for one transcryption, and their derivation from secrets and contexts |
| `elgamal` | The ElGamal ciphertext, the PEP primitives (`rekey`, `reshuffle`, `rerandomize` and their combinations) in `elgamal::primitives`, and the Ristretto scalar and group element arithmetic in `elgamal::arithmetic` |

The `prelude::client` and `prelude::transcryptor` modules re-export what each role needs.
The Python and JavaScript bindings expose the same modules and names.
Full API documentation is on [docs.rs/libpep](https://docs.rs/libpep).

## Features

Default features:
- `long`: pseudonyms and attributes over 15 bytes, using PKCS#7 padding.
- `offline`: encryption towards global public keys, for when no session key is available or using one would leak information.
- `batch`: batch transcryption with shuffling, so that outputs cannot be linked to inputs by position.
- `serde`: serialization and deserialization support via Serde.
- `json`: JSON documents with nested pseudonyms and attributes.
- `build-binary`: the `peppy` command-line tool.

Optional features:
- `elgamal3`: ciphertexts additionally encode the public key they were encrypted for, the `(B, C, Y)` triple encoding of the original PEP framework.
  This makes decryption with a mismatched key detectable, at the cost of larger ciphertexts and slower operations.
  Decryption functions return an `Option` (or an error for batches) instead of a plain value.
  The two modes are not wire-compatible; choose one per deployment.
- `legacy`: compatibility with the legacy PEP repository implementation, which derives scalars from domains, contexts and secrets differently.
  Implies `elgamal3`, `offline` and `global-pseudonyms`.
- `insecure`: methods that use global *secret* keys directly, such as `decrypt_global`.
- `global-pseudonyms`: pseudonyms in a *global* pseudonymization domain, using reshuffle factor 1.

> [!WARNING]
> In the intended security model the global secret key is discarded after distributed setup and never exists in one place; `insecure` retains it, which gives its holder the ability to decrypt everything.
> Global pseudonyms are linkable across all domains, which defeats the purpose of domain-specific pseudonymization.
> Use `insecure` only for testing, `global-pseudonyms` only when that linkability is an explicit requirement, and `legacy` only for interoperability with existing legacy PEP deployments.

## Security

The library uses the Ristretto group over Curve25519 as implemented by [`curve25519-dalek`](https://docs.rs/curve25519-dalek), offering 128 bits of security.
Confidentiality rests on the semantic security of ElGamal, and pseudonym unlinkability on the pseudorandomness of the DH-PRF evaluated by reshuffling; both hold under the DDH assumption in the Ristretto group.
All scalar and group arithmetic is constant time, and randomness comes from the caller's cryptographically secure random number generator.
The library has been designed for production use but has not undergone a formal security audit.

The minimum supported Rust version is 1.85; raising it is considered a semver-relevant change.

## Development

```bash
cargo test
cargo clippy --workspace --all-targets
cargo test --features elgamal3   # the other ciphertext mode
```

The bindings live in [`bindings/python`](bindings/python) and [`bindings/wasm`](bindings/wasm); their READMEs describe how to build and test them.

## Background

This library implements the *n-PEP* scheme, described in:

> Job Doesburg, Bernard van Gastel and Erik Poll, *n-PEP: Secure Data Sharing with Transitive and Distributed Blind Pseudonymization*. In **Security and Trust Management. 22nd International Workshop, STM 2026, Proceedings**, Lecture Notes in Computer Science, Springer. [PDF](https://jobdoesburg.nl/docs/n-PEP-STM2026.pdf)

n-PEP extends the PEP framework with *reversible* and *transitive* pseudonymization between domains (the `reshuffle2`, `rekey2` and `rsk2` operations), eliminating the polymorphic pseudonyms that act as a linking oracle in basic PEP, and distributes transcryption and session key establishment over `n` semi-trusted transcryptors, so that confidentiality and pseudonym unlinkability hold as long as at least one transcryptor remains uncompromised.

The original PEP framework was introduced in:

> Eric Verheul and Bart Jacobs, *Polymorphic Encryption and Pseudonymisation in Identity Management and Medical Research*. In **Nieuw Archief voor Wiskunde (NAW)**, 5/18, nr. 3, 2017, p. 168-172. [PDF](https://repository.ubn.ru.nl/bitstream/handle/2066/178461/178461.pdf?sequence=1)

## Citing

If you use this library in academic work, please cite the n-PEP paper (see also [`CITATION.cff`](CITATION.cff)).

## License

Apache License 2.0. Authors: Bernard van Gastel and Job Doesburg.
