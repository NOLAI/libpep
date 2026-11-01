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

`libpep` implements *n-PEP*, a scheme for end-to-end encrypted, asynchronous, pseudonymized data sharing between users.
Every user knows its data subjects under its own pseudonyms, which cannot be linked to another user's pseudonyms for the same data subjects.
A sender encrypts data without the receiver being online, or even known, at that moment; *transcryptors* later blindly re-encrypt (*transcrypt*) it for the receiver's pseudonymization domain and encryption context, converting the pseudonyms in it without decrypting anything.
Transcryption can be distributed over `n` transcryptors, so that every transcryptor can independently monitor and block data exchanges.

The transcryptors are *semi-trusted*: no single transcryptor can read data or link pseudonyms, and confidentiality and pseudonym unlinkability hold as long as at least one of the `n` transcryptors remains uncompromised.
n-PEP does not guarantee integrity: nothing shows that a transcryptor applied the right factors.
The `verifiable` feature lets that be checked (see [Verifiable transcryption](#verifiable-transcryption)).

The library is the reference implementation of n-PEP and of its verifiable extension (see [Background](#background)).
It ships as a Rust crate with Python and JavaScript/WebAssembly bindings that mirror the Rust API.

The library is generic over the group and the hash, and is built for ristretto255 with SHA-512, which every type defaults to.
Most code therefore writes no type parameters (see [API overview](#api-overview)), and `use libpep::prelude::*;` imports what a typical application needs.
`peppy` and the Python and JavaScript bindings are fixed to ristretto255 with SHA-512.

## Installation

Rust, in `Cargo.toml`:
```toml
[dependencies]
libpep = "0.14"
```

Python, importable as `libpep`:
```bash
pip install libpep-py
```

JavaScript, for Node.js and browsers:
```bash
npm install @nolai/libpep-wasm
```

The `peppy` command-line tool is installed with `cargo install libpep --features cli` (see [Command line](#command-line)).

## Quick start

A transcryptor holds two secrets from which all its factors derive.
Every user works in its own *pseudonymization domain* (typically its role or user group) and *encryption context* (typically a session), and holds session keys for that context.

```rust
use libpep::prelude::*;

let rng = &mut rand::rng();

// System setup: global keys, and the secrets of the transcryptor. The types default to ristretto255
// with SHA-512, so no type parameter is written.
let (_global_public, global_secret) = make_global_keys(rng);
let transcryptor = Transcryptor::new(
    PseudonymizationSecret::from(b"pseudonymization secret".to_vec()),
    RekeyingSecret::from(b"rekeying secret".to_vec()),
);

// User A (a sender) and user B (a receiver) each work in their own pseudonymization domain and
// encryption context, with session keys for it.
let (domain_a, session_a) = (PseudonymizationDomain::from("hospital"), EncryptionContext::from("session-a"));
let (domain_b, session_b) = (PseudonymizationDomain::from("research"), EncryptionContext::from("session-b"));
let keys_a = make_session_keys(&global_secret, &session_a, transcryptor.rekeying_secret());
let keys_b = make_session_keys(&global_secret, &session_b, transcryptor.rekeying_secret());

// A encrypts one of its pseudonyms for its own encryption context.
let pseudonym_a = Pseudonym::random(rng);
let encrypted = encrypt(&pseudonym_a, &keys_a.public(), rng);

// The transcryptor converts it to B's domain and encryption context, without decrypting it.
// Every transcryption rerandomizes the ciphertext first, which needs the key it is currently
// encrypted under (A's session public key here; with the `elgamal3` feature the ciphertext carries it).
let info = transcryptor.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
let transcrypted = transcryptor.transcrypt(&encrypted, &info, &keys_a.public(), rng);

// B, the receiver, decrypts its own pseudonym for the same subject, which is unlinkable to A's.
let pseudonym_b = decrypt(&transcrypted, &keys_b);
assert_ne!(pseudonym_a, pseudonym_b);

// Transcryption is reversible: converting back yields A's pseudonym again.
let back = transcryptor.transcrypt(&transcrypted, &info.reverse(), &keys_b.public(), rng);
assert_eq!(pseudonym_a, decrypt(&back, &keys_a));
```

Every key operation takes either the one key it needs or a bundle to take it from: `keys_a.public()` for the session's public keys, `keys_a` itself where a secret key is needed. The *data's* type selects the half, so a pseudonym is always encrypted and decrypted under the pseudonym key and never the attribute one; `&keys_a.pseudonym.public` also works where naming the exact key is clearer.

Attributes (`Attribute`, `LongAttribute`) are encrypted and transcrypted the same way, but only rekeyed, never converted between domains.
With the `json` feature, whole JSON documents with nested pseudonyms and attributes are encrypted and transcrypted as one value.

In the distributed setting, a trusted authority runs `keys::distribution::make_distributed_global_keys` once.
It generates the global keys, blinds the global secret key with one *blinding factor* per transcryptor, discards the global secret key, and hands each transcryptor its blinding factor.
The authority exists only for this setup, and never sees the secrets the transcryptors derive their factors from.
After that, each `transcryptor::DistributedTranscryptor` hands a client (after authenticating it) a *session key share*, and `client::Client::from_shares` reconstructs the session keys from the blinded global key and the shares.
Without the shares of all transcryptors, the blinded global key does not reveal the global secret key.
The public key a ciphertext is encrypted under travels with it from transcryptor to transcryptor: each obtains the next key with `rekey_public_key` (the `factors::RekeyPublicKey` trait) on its transcryption info (the CLI prints it as `key`).
[`tests/distributed.rs`](tests/distributed.rs) walks through this flow; the Python and JavaScript test suites under [`bindings/`](bindings/) do the same in those languages.

## How it works

In the ElGamal scheme, a message `M` is encrypted for a receiver with public key `Y`, belonging to secret key `y`.
Encryption is randomized (*polymorphic*): every fresh random `b` gives a different ciphertext for the same message.
It is written `Enc(b, M, Y)`.

The library provides three homomorphic operations on a ciphertext `in = Enc(b, M, Y)`.
Each is applied blindly, without the party that performs it seeing the message:

- `rekey(in, k)`: makes a ciphertext decryptable with `k*y` instead of `y`, without the party performing it knowing `y`.
  Both decrypt to `M`.
  `Enc(b, M, Y)` becomes `Enc(k^-1*b, M, k*Y)`.
  This is a form of proxy re-encryption.
- `reshuffle(in, s)`: scales the message, so that decrypting the result yields `s*M`.
  This turns an identifier into a pseudonym that is unlinkable to it while `s` stays secret.
  `Enc(b, M, Y)` becomes `Enc(s*b, s*M, Y)`.
- `rerandomize(in, r)`: re-encodes the ciphertext without changing its message or the key it is encrypted for, which gives unlinkable copies of it.
  `Enc(b, M, Y)` becomes `Enc(b+r, M, Y)`.

Because these operations work on *encrypted* data, the receiver does not need to be known at encryption time.
Data is encrypted once and later rekeyed, and reshuffled if it is an identifier, for whichever user is granted access: non-interactive, asynchronous end-to-end encryption with built-in pseudonymization.
Reshuffling and then rekeying identifiers (`rsk`), or only rekeying attributes, is called *transcryption*.
A transcryptor can decide whether transcryption between two users is allowed.
A request reveals the authenticated requesting user and the source and target domains and contexts, but not the values of pseudonyms or data.

Data consists of *pseudonyms*, the identifiers of data subjects, and *attributes*, facts about data subjects that do not identify them.
Pseudonyms and attributes are encrypted with different keys and rekeyed with different factors.
Otherwise an encrypted pseudonym could be presented as an encrypted attribute and rekeyed without being reshuffled, which would leak the pseudonym of another user.
Pseudonymization only protects against identification through identifiers: the shared data itself must not contain quasi-identifiers or other linkable attributes.

### Pseudonymization

Every user knows a data subject under its own *local pseudonym*, and reshuffling converts a pseudonym from one user's domain to another's, applying `s = s_from^-1 * s_to`, without a global pseudonym existing in between.
The factor `s` is tied to the *pseudonymization domain* of a user.
Conversion is reversible, converting back gives the original pseudonym, and transitive, converting from A to B and then to C gives the pseudonym that converting from A to C directly gives.
A global pseudonym that is valid in every domain would let colluding users link their pseudonyms, which is why pseudonyms are local.

Reshuffling with factor `s` evaluates `F_s(M) = s*M`, the Diffie-Hellman function (the DH-PRF).
This is a *weak PRF*: under the Decisional Diffie-Hellman (DDH) assumption, and as long as `s` stays secret, `s*M` is indistinguishable from a random group element when `M` is a uniformly random group element, chosen independently of `s`.
Pseudonyms in different domains then cannot be linked without knowing the ratio of their domain factors.
Reshuffling an *encrypted* pseudonym is an encryption-based *oblivious evaluation* of this weak PRF: because the operation is homomorphic, the transcryptor applies its secret factor `s` without ever seeing the pseudonym or the result, and the sender and receiver never learn `s`.

#### Origin identifiers must be uniformly random

`F_s` is not a (strong) PRF.
For structured or adversarially chosen inputs it is linear, `F_s(a*M) = a*F_s(M)`, so if `M1 = a*M2` for a known `a`, then `s*M1 = a*(s*M2)` in every pseudonymization domain, and anyone who knows `a` can recognize the related pseudonyms.
A strong PRF avoids this by hashing the input into the group first, `s*H(M)`.
`libpep` does not hash at reshuffle time, as it works on ElGamal ciphertexts of identifiers that are already encoded as group elements.
It therefore assumes that origin identifiers are indistinguishable from uniformly random group elements, or at least that nobody can produce two identifiers with a known discrete-log relation.
In practice:

- Sample identifiers at random (`Pseudonym::random`), or use random 16-byte identifiers or hashes of identifiers, encoded with `from_lizard`.
- Encode identifiers with the lizard encoding (`from_lizard`, `from_string_padded` and the long variants).
  It maps a 16-byte block to a ristretto255 element with the Elligator 2 map.
  The block is placed in the input of the map next to 16 bytes of a SHA-256 hash of the block, so that the block can be decoded again.
  No relation between the discrete logarithms of the encodings of different blocks is known, even for structured blocks such as `1`, `2` and `3`.
  This is a property of the map that has no proof, and it holds for low-entropy identifiers too, so lizard-encoded identifiers remain unlinkable across domains.
  Lizard only roughly gives uniform identifiers: the encoding is injective and unkeyed, so it reaches at most `2^128` of the roughly `2^252` group elements, one per block.
- Longer identifiers are split into blocks by the long types, and every block is reshuffled separately, so identifiers that share a block share its pseudonym in every domain.
- Never encode an identifier as `x*G`.
- Elements imported with `from_bytes`, `from_hex`, `from_slice` or `from_point` bypass the encoding and keep whatever relations they have.
  Import only elements that are random or that no adversary could have chosen.

Individual pseudonyms remain unlinkable across domains under DDH, as long as nobody knows a relation between origin identifiers.

A reshuffle alone is not enough, as the pseudonym is still encrypted for a key the receiver does not possess.
A *rekey* with `k` makes it decryptable with `k*y`, in combination with a protocol to hand the receiver that secret key.
The factor `k` is tied to the *encryption context* of a user, typically its current session.
`rsk(in, s, k)` performs both at once, and `reshuffle2`, `rekey2` and `rsk2` are the transitive and reversible n-PEP variants that convert directly between two domains or sessions, applying `s = s_from^-1 * s_to` and `k = k_from^-1 * k_to`.

When the same encrypted pseudonym is used more than once, it is rerandomized every time, so that comparing ciphertexts byte for byte reveals nothing.
Rerandomizing also protects against plaintext injection at transcryption.
A malicious sender could place a plaintext pseudonym `M` directly in the second component of a ciphertext, so that an `rsk` returns the reshuffled pseudonym `s*M` in the clear and bypasses rekeying.
Mixing fresh randomness into the ciphertext before reshuffling keeps `s*M` hidden even for such a malformed input.
This is why pseudonymization and transcryption always rerandomize, and in the default ciphertext mode take the public key the ciphertext is encrypted under.

With `n` transcryptors, each applies its own secret factors, and the factors that are effectively applied are their products, `s = s_1*...*s_n` and `k = k_1*...*k_n`.
They stay secret as long as one transcryptor keeps its own factors secret.
Every transcryptor derives its factors from two secrets of its own, a pseudonymization secret and a rekeying secret, with the pseudonymization domain and the encryption context.
Rerandomization distributes the same way, and the protection against plaintext injection holds as long as one transcryptor rerandomizes honestly.

### Verifiable transcryption

Without further measures, nothing binds the output of a transcryptor to a correct application of the operations on its input: it could return an arbitrary ciphertext, or apply different factors for the same domain or session.
Such corruption is hard to notice, as pseudonyms look random by design.
The `verifiable` feature closes this gap without breaking unlinkability.
A transcryptor publishes a *commitment* `s·G` or `k·G` to each reshuffle and rekey factor it uses for a domain or session, and every transcryption can produce a zero-knowledge proof that the committed factors were applied.
The proofs are Schnorr-style non-interactive proofs of discrete-log equality (Chaum-Pedersen proofs made non-interactive with the Fiat-Shamir transform) and can be verified in batch.
*Verifiers*, which are users or other transcryptors, record the commitments and check the proofs against them, so that consistency, and with it integrity, is enforced and not trusted.
A verifier is not trusted, and learns nothing about the factors.

Pseudonyms are transformed with a verifiable `rrsk`: the rerandomization is proved first, and then the reshuffle and rekey are proved together in one chain of proofs over the factor commitments.
Proving reshuffle and rekey one after the other would expose the intermediate ciphertext to the verifier, which, if it colludes with the sender or receiver, could decrypt it and learn a pseudonym.
Attributes are transformed with a verifiable rekey, which does not rerandomize, so anyone who sees both sides of a verifiable transcryption can match attribute ciphertexts.
Verifying a rerandomization needs the original ciphertext, so the verifier learns the link between a ciphertext and its copy; who verifies is a deployment choice.
Session key shares carry a proof of correct construction against the transcryptor's blinding commitment as well.

A commitment makes the use of a factor consistent, but it does not show how the factor was derived or that it was sampled uniformly.
With distributed transcryption this does not break the system, as the effective factor is uniform as long as one transcryptor samples honestly.
The proofs are the building blocks of integrity, not a security proof of a complete protocol.
This closes the gap noted under [As a three-party oblivious PRF](#as-a-three-party-oblivious-prf): a transcryptor that applies a wrong factor is detected.

## Relation to other primitives

`libpep` combines two familiar primitives: `reshuffle` is an oblivious PRF evaluation and `rekey` is a proxy re-encryption, applied to the same ciphertext.

### As a three-party oblivious PRF

An oblivious pseudorandom function (OPRF, specified over prime-order groups in [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html)) is a two-party, blinding-based protocol.
A *client* blinds an input, a *server* applies its secret key, and the client unblinds the result to obtain the PRF output.
The server learns neither input nor output.

`libpep` evaluates the same Diffie-Hellman function `F_s(M) = s*M`, in a three-party, encryption-based protocol: the client role is split over a **sender** and a **receiver**, with the **transcryptor** as evaluator.
ElGamal encryption takes the place of blinding: the sender's encryption randomness `b` blinds the pseudonym, the transcryptor reshuffles with its domain factor `s`, and the receiver's decryption unblinds.
The transcryptor learns neither `M` nor `s*M`, and neither sender nor receiver learns `s`.
Because blinding and unblinding are done by different users, evaluation is non-interactive and asynchronous: the sender can encrypt before the receiver is known, and the PRF output appears only in the receiver's domain.

There are two differences with the two-party protocol.
An OPRF hashes the input into the group first, so it is a strong PRF for any input.
`libpep` does not: it relies on the weak PRF property and on origin identifiers being uniformly random group elements, as described under [origin identifiers](#origin-identifiers-must-be-uniformly-random).
And plain PEP transcryption is not verifiable: a transcryptor that applies a wrong factor produces an incorrect pseudonym undetectably.
The `verifiable` feature closes that gap with discrete-log-equality proofs of the kind the verifiable OPRF of RFC 9497 uses.

The primitives shared with RFC 9497 are checked against its ristretto255-SHA512 test vectors (Appendix A.1): `hash_to_group`, `HashToScalar`, and the batched DLEQ proof in `elgamal::dleq`.
Hashing to the group follows [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html): `hash_to_group` is `hash_to_ristretto255` (Appendix B) over `expand_message_xmd` (Section 5.3.1) with SHA-512, and `expand_message_xmd` is also checked against the vectors of RFC 9380 (Appendix K).
The library uses its own context string (`nPEPV1-`) in production, so that its hashes are separate from those of any OPRF.
The proofs of verifiable transcryption use the four-element encoding of `elgamal::zkps`, not the two-scalar encoding of `elgamal::dleq`.

The three-party construction, with its sender, receiver and transcryptor, is specified as a convertible OPRF (coPRF) in the Internet-Draft `draft-doesburg-cfrg-coprf`, which uses the same prime-order group API as RFC 9497.

### As proxy re-encryption with built-in pseudonymization

`rekey` is [proxy re-encryption](https://en.wikipedia.org/wiki/Proxy_re-encryption) over ElGamal: it transforms `Enc(b, M, Y)` into `Enc(k^-1*b, M, k*Y)`, decryptable by `k*y`, with the transcryptor acting as the proxy without learning the message or holding either secret key.
`reshuffle` adds the one transformation a plain proxy cannot do, mapping `M` to `s*M`.
Attributes are never reshuffled, so for attributes the scheme is exactly proxy re-encryption; for identifiers, the same homomorphic step that re-encrypts a pseudonym for a new receiver also rewrites it into that receiver's domain, so no global identifier is ever exposed.

With the transitive `rekey2` and `reshuffle2`, the scheme is a bidirectional, multi-hop proxy re-encryption scheme with built-in pseudonymization.
Traditional proxy re-encryption treats transitivity and bidirectionality as vulnerabilities: a single proxy could derive re-encryption keys that were never authorized, or collude with a receiver to recover the sender's key.
Here the transcryptors are themselves the authorization point for conversions, which makes transitivity a feature, and with `n` transcryptors no single one can convert or decrypt data without the cooperation of all others.

This is what the name refers to: *polymorphic* encryption is the proxy re-encryption, and *pseudonymization* is the PRF evaluation carried out in the same step.

## API overview

| Module | Description |
|--------|-------------|
| `client` | Encryption and decryption with session keys, or with global public keys for offline encryption; the `Distributed` extension reconstructs session keys from shares |
| `transcryptor` | Pseudonymization, rekeying and transcryption, single and in batch; `DistributedTranscryptor` produces session key shares; with the `verifiable` feature, the same operations with zero-knowledge proofs of correct transcryption |
| `data` | `Pseudonym` and `Attribute`, their long (multi-block) variants, records, and JSON documents with nested pseudonyms and attributes |
| `keys` | Global and session key types and generation, and the distributed key setup with blinding factors and shares |
| `contexts` | `PseudonymizationDomain` and `EncryptionContext`, the identifiers that data is pseudonymized and encrypted for, and the `TranscryptorId` that names a transcryptor |
| `factors` | Reshuffle, rekey and rerandomize factors, the transcryption info that bundles them for one transcryption, and their derivation from secrets and contexts |
| `elgamal` | The ElGamal ciphertext with `encrypt` and `decrypt`; the PEP primitives (`rekey`, `reshuffle`, `rerandomize` and their combinations) in `elgamal::primitives`; in `elgamal::arithmetic` the `Group` trait (the prime-order group API) with its `Ristretto255` instance and its scalar and group element arithmetic, the `Ciphersuite` trait that pairs a group with a hash and supplies the domain separation tags of the protocol's hashes (`Ristretto255Sha512` for ristretto255 with SHA-512), and the hashing to the group and to scalars (`elgamal::arithmetic::hashing`: `expand_message_xmd`, `hash_to_group`, `hash_to_nonzero_scalar`); with the `verifiable` feature the primitives that emit proofs in `elgamal::verifiable`, and the underlying `elgamal::zkps` and `elgamal::dleq` |
| `prelude` | The imports a typical application needs, with subsets `prelude::client` and `prelude::transcryptor` for each role |
| `verifier` | Verification of transcryption proofs against factor commitments, with a cache of verified commitments (`verifiable` feature) |

The API is generic in two layers.
The data types and the group arithmetic (`Pseudonym<G>`, `SessionKeys<G>`, ciphertexts, proofs, ...) take a `G: Group` parameter.
Whatever hashes (factor derivation, `hash_to_group`, creating and verifying proofs, and with them `Transcryptor`, `DistributedTranscryptor` and `Verifier`) takes a `C: Ciphersuite`, which pairs a group with a hash.
Both traits are in `elgamal::arithmetic`, and another group or hash is added by implementing them.
ristretto255 is `Ristretto255` and the ciphersuite `ristretto255-SHA512` is `Ristretto255Sha512`.
Every generic type defaults its parameter to them: `Pseudonym<G: Group = Ristretto255>`, `Transcryptor<C: Ciphersuite = Ristretto255Sha512>`.
`Pseudonym<OtherGroup>` works like `Pseudonym`.

Rust does not use a default type parameter to infer one, so an expression that nothing constrains still needs a type: `Pseudonym::random(rng).to_hex()` does not compile, `let pseudonym: Pseudonym = Pseudonym::random(rng);` does.
Functions and constructors that cannot infer their parameter, because it appears only in the result or in an associated type, come in pairs.
The plain name is the ristretto255 one: `make_global_keys(rng)`, `make_session_keys(..)`, `make_*_factor(..)`, `hash_to_group(..)`, `Transcryptor::new(..)`, `DistributedTranscryptor::new(..)`, `TranscryptionInfo::new(..)` and `Verifier::new()`.
The same name with the suffix `_generic` takes the group or ciphersuite as a type parameter: `make_global_keys_generic::<G, _>(rng)`, `make_session_keys_generic::<C>(..)`, `Transcryptor::<C>::new_generic(..)`.
Generic code uses the `_generic` names. Methods that take the ciphersuite as a type parameter, such as `proof.verify::<Ristretto255Sha512>(..)`, name it in both cases.

The Python and JavaScript bindings expose the same modules and names.
Full API documentation is on [docs.rs/libpep](https://docs.rs/libpep).

## Features

Default features:
- `long`: pseudonyms and attributes over 15 bytes, using PKCS#7 padding.
- `offline`: encryption towards global public keys, for when no session key is available or using one would leak information.
- `batch`: batch transcryption with shuffling, so that outputs cannot be linked to inputs by position.
- `serde`: serialization and deserialization support via Serde.
- `json`: JSON documents with nested pseudonyms and attributes.
- `batch-pk`: batches carry the public key their ciphertexts are encrypted under, so batch operations that rerandomize do not need it as a separate argument. No effect under `elgamal3`, where every ciphertext carries its key.
- `verifiable`: verifiable transcryption. Every operation gets a counterpart that also emits a Schnorr-style discrete-log-equality proof, made non-interactive with Fiat-Shamir, so a verifier can check that a transcryptor applied the factors it committed to without learning them. See [Verifiable transcryption](#verifiable-transcryption).

Optional features:
- `cli`: the `peppy` command-line tool, see [Command line](#command-line) (enables `long`, `offline`, `serde` and `verifiable`).
- `verifiable-derivation`: derive factors from a pair of master secrets with a Carter-Wegman universal hash, so that a verifier can compute the commitment for any domain or context from two master public keys instead of storing one commitment per factor.
  This is not the preferred scheme: the factors are linear in two public hashes, so two leaked factors give the master secret, and two pseudonyms of one subject (or two session keys) give all of them.
  Use the published commitments of the `verifiable` feature unless commitment storage is the binding constraint and that trade-off is acceptable.
- `elgamal3`: ciphertexts additionally encode the public key they were encrypted for, the `(B, C, Y)` triple encoding of the original PEP framework.
  This makes decryption with a mismatched key detectable, at the cost of larger ciphertexts and slower operations.
  Decryption functions return an `Option` (or an error for batches) instead of a plain value.
  The two modes are not wire-compatible; choose one per deployment.
- `legacy`: compatibility with the legacy PEP repository implementation, which derives scalars from domains, contexts and secrets differently.
  Implies `elgamal3`, `offline` and `global-pseudonyms`.
  The default and `legacy` derivations produce different factors and session keys from the same secrets, so a deployment picks one.
- `insecure`: methods that use global *secret* keys directly, such as `decrypt_global`.
- `global-pseudonyms`: pseudonyms in a *global* pseudonymization domain, using reshuffle factor 1 (the global, or polymorphic, pseudonyms of the original PEP framework).

> [!WARNING]
> In the intended security model the global secret key is discarded after distributed setup and exists only at the trusted authority during setup; `insecure` retains it, so its holder can decrypt everything.
> Global pseudonyms are linkable across all domains, which defeats the purpose of domain-specific pseudonymization.
> Use `insecure` only for testing, `global-pseudonyms` only when that linkability is an explicit requirement, and `legacy` only for interoperability with existing legacy PEP deployments.

## Security

The library uses the Ristretto group over Curve25519 as implemented by [`curve25519-dalek`](https://docs.rs/curve25519-dalek), offering 128 bits of security; other prime-order groups can be used by implementing the `Group` trait, and a hash for them by implementing the `Ciphersuite` trait.
Confidentiality rests on the semantic security of ElGamal, and pseudonym unlinkability on the weak PRF property of the Diffie-Hellman function evaluated by reshuffling, for uniformly random origin identifiers (see [origin identifiers](#origin-identifiers-must-be-uniformly-random)); both hold under the DDH assumption in the Ristretto group.
All scalar and group arithmetic is constant time, and randomness comes from the caller's cryptographically secure random number generator.
Secret keys, blinding factors and factors print as `[redacted]` in `Debug` output and implement `Zeroize`, but they are `Copy`, so they are not wiped when dropped: an application that needs them gone from memory has to call `zeroize` on every copy itself. `PseudonymizationSecret` and `RekeyingSecret` are zeroized on drop.
Distribution costs availability: all `n` transcryptors must take part in a transcryption.

The security properties of n-PEP are the following, against an attacker that compromises (learns all secrets of) at most `n-1` transcryptors and any number of storages and users not involved in the communication:

- *Attribute confidentiality*: the value of attributes sent between a sender and a receiver stays confidential to anyone but the two.
- *Pseudonym confidentiality*: the value of a user's pseudonym for a data subject stays confidential against any other user, including compromised receivers.
- *Pseudonym unlinkability*: given two pseudonyms in two different pseudonymization domains, it is not possible to tell whether they are for the same data subject without the cooperation of at least one uncompromised transcryptor.
  This also holds if both the senders and the receivers are compromised, as long as the attributes are unlinkable.
- *Cross-encryption ciphertext unlinkability*: given two ciphertexts from different encryptions, it is not possible to tell whether they encrypt the same plaintext.
- *Cross-rerandomization ciphertext unlinkability*: given two ciphertexts, it is not possible to tell whether one is a rerandomized copy of the other.
  This excludes compromised storages that are involved in the communication.

These properties assume a trusted initial setup (see [Quick start](#quick-start)), secure authenticated connections between users, transcryptors and storages, and the DDH assumption in the Ristretto group.
They also assume that the shared data is unlinkable (it contains no quasi-identifiers) and that no other channel links the data, such as traffic or timing analysis, which batch transcryption with shuffling mitigates.
Linkable artifacts can also arise in an application, for example the session names that a storage keeps next to ciphertexts, or symmetric encryption of large attributes, which cannot be rerandomized.
n-PEP itself does not guarantee integrity or authenticity of pseudonyms or attributes; the `verifiable` feature adds proofs that the transcryptors transformed ciphertexts correctly.
The security rests on the hardness of the discrete logarithm problem, so it is not post-quantum.

The library has been designed for production use but has not undergone a formal security audit.

The minimum supported Rust version is 1.88; raising it is considered a semver-relevant change.

## Command line

The `peppy` tool exposes the library on the command line. The first word names what is operated on, the second the operation:

| Group | Operations |
|-------|------------|
| `keys global`, `keys session`, `keys distributed` | `generate`; `derive`; `setup`, `share`, `reconstruct`, `update` |
| `factors` | `reshuffle`, `rekey`, `info`, `commitments` |
| `pseudonym`, `attribute` | `random`, `encode`, `decode`, `encrypt`, `decrypt`, `rerandomize`, `rekey`, `transcrypt`, `verify-rekey`, and `pseudonymize`, `verify-pseudonymize` for pseudonyms |
| `json` | `encrypt`, `decrypt`, `transcrypt`, `verify-transcrypt` |
| `elgamal` | `encrypt`, `decrypt`, `rr`, `rs`, `rk`, `rsk`, `rrsk`, `rs2`, `rk2`, `rsk2`, `rrsk2` |
| `scalar`, `point` | `random`, `invert`, `mul`, `from-hash`; `random`, `base`, `mul`, `from-hash`, `hash-to-group` |

`point hash-to-group` domain-separates its hash with the ciphersuite `ristretto255-SHA512`, which `peppy` is fixed to. Factor derivation is separated by the transcryptor secrets, the domain and the session.

Values print one per line on standard output, labelled when that is a terminal and bare when piped; `--json` prints all values of a command as one object, which is the form to use when a command prints several values.
Any value argument may be `-` to read standard input or `@path` to read a file.
Scalars and group elements are hex, ciphertexts base64, and long values are given as space-separated (plain) or `|`-separated (encrypted) blocks.
Malformed input exits with status 1 (a usage error with 2, from clap); with the `elgamal3` feature a decryption with the wrong key exits with status 3; a proof that does not verify exits with status 4.

The quick start on the command line:

```bash
peppy keys global generate --json > global.json
peppy keys session derive --pseudonym-global-secret "$(jq -r .pseudonym_secret_key global.json)" \
    --rekeying-secret "rekeying secret" --context session-a --json > session-a.json
peppy keys session derive --pseudonym-global-secret "$(jq -r .pseudonym_secret_key global.json)" \
    --rekeying-secret "rekeying secret" --context session-b --json > session-b.json

value=$(peppy pseudonym encode patient-42)
encrypted=$(peppy pseudonym encrypt --key "$(jq -r .pseudonym_public_key session-a.json)" "$value")
transcrypted=$(peppy pseudonym transcrypt \
    --pseudonymization-secret "pseudonymization secret" --rekeying-secret "rekeying secret" \
    --from-domain hospital --to-domain research --from-context session-a --to-context session-b \
    --key "$(jq -r .pseudonym_public_key session-a.json)" "$encrypted" --json | jq -r .ciphertext)
peppy pseudonym decrypt --key "$(jq -r .pseudonym_secret_key session-b.json)" "$transcrypted"
```

Transcryption is verifiable on the command line as well: `factors commitments` prints the commitments a transcryptor publishes for a transition, `--prove` on `rekey`, `pseudonymize` and `transcrypt` adds a `proof` (JSON) to the output, and `verify-rekey`, `verify-pseudonymize` and `json verify-transcrypt` check a proof against the original ciphertext and the commitments, printing the transcrypted ciphertext only if it holds.
A proof of `pseudonym transcrypt` is a pseudonymization proof, a proof of `attribute transcrypt` a rekey proof.

```bash
peppy factors commitments \
    --pseudonymization-secret "pseudonymization secret" --rekeying-secret "rekeying secret" \
    --from-domain hospital --to-domain research --from-context session-a --to-context session-b \
    --json > commitments.json
peppy pseudonym transcrypt --prove \
    --pseudonymization-secret "pseudonymization secret" --rekeying-secret "rekeying secret" \
    --from-domain hospital --to-domain research --from-context session-a --to-context session-b \
    --key "$(jq -r .pseudonym_public_key session-a.json)" "$encrypted" --json > transcrypted.json
jq -c .proof transcrypted.json > proof.json
peppy pseudonym verify-pseudonymize \
    --reshuffle-commitment "$(jq -r .reshuffle_commitment commitments.json)" \
    --rekey-commitment "$(jq -r .pseudonym_rekey_commitment commitments.json)" \
    --key "$(jq -r .pseudonym_public_key session-a.json)" --proof @proof.json "$encrypted"
```

`peppy keys distributed setup -n 3` sets up a system with three transcryptors; each one then answers a client with `keys distributed share`, and the client combines the shares with `keys distributed reconstruct`.
`peppy completions <shell>` prints a completion script and `peppy man` the man page.

## Development

```bash
cargo test
cargo clippy --workspace --all-targets
cargo test --features elgamal3   # the other ciphertext mode
```

The bindings live in [`bindings/python`](bindings/python) and [`bindings/wasm`](bindings/wasm); their READMEs describe how to build and test them.

## Background

This library implements the *n-PEP* scheme, described in:

> Job Doesburg, Bernard van Gastel and Erik Poll, *n-PEP: Secure Data Sharing with Transitive and Distributed Blind Pseudonymization*. In **Security and Trust Management. STM 2026**, Lecture Notes in Computer Science, vol. 17172, Springer, Cham, 2027. [doi:10.1007/978-3-032-41330-7_5](https://doi.org/10.1007/978-3-032-41330-7_5) · [PDF](https://jobdoesburg.nl/docs/n-PEP-STM2026.pdf)

n-PEP extends the PEP framework with *reversible* and *transitive* pseudonymization between domains (the `reshuffle2`, `rekey2` and `rsk2` operations), eliminating the polymorphic pseudonyms that act as a linking oracle in basic PEP, and distributes transcryption and session key establishment over `n` semi-trusted transcryptors (none of which alone can read data or link pseudonyms), so that confidentiality and pseudonym unlinkability hold as long as at least one transcryptor remains uncompromised. It does not guarantee the integrity of pseudonyms or attributes: a transcryptor could transcrypt inconsistently, which the verifiable operations below address.

The verifiable operations (the `verifiable` feature: the DLEQ proofs, the factor commitments and the verifier) are specified in:

> Job Doesburg, Bernard van Gastel and Erik Poll, *Verifiable Blind Pseudonymization via Polymorphic Encryption Using Zero-Knowledge Proofs*. In **25th Workshop on Privacy in the Electronic Society (WPES '26)**, November 15-19, 2026, The Hague, Netherlands, ACM, New York, NY, USA, 13 pages. [doi:10.1145/3847192.3847358](https://doi.org/10.1145/3847192.3847358)

That paper guarantees integrity without breaking the unlinkability of PEP: each transcryptor proves in zero knowledge that it transformed a ciphertext with the factors it committed to, so that a transcryptor that applies other factors is detected. Table 1 of the paper is the reference for the cost of each verifiable operation.

The original PEP framework was introduced in:

> Eric Verheul and Bart Jacobs, *Polymorphic Encryption and Pseudonymisation in Identity Management and Medical Research*. In **Nieuw Archief voor Wiskunde (NAW)**, 5/18, nr. 3, 2017, p. 168-172. [PDF](https://repository.ubn.ru.nl/bitstream/handle/2066/178461/178461.pdf?sequence=1)

## Citing

If you use this library in academic work, please cite the n-PEP paper (see also [`CITATION.cff`](CITATION.cff)).

## License

Apache License 2.0. Authors: Bernard van Gastel and Job Doesburg.
