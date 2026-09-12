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

This library implements PEP cryptography based on ElGamal encrypted messages.
It enables secure, end-to-end encrypted, pseudonymized data sharing between parties that each know their data subjects under different, unlinkable pseudonyms.
Encrypted data can blindly be re-encrypted (*transcrypted*) for different keys by semi-trusted *transcryptors*, without decrypting the data and while pseudonymizing encrypted identifiers in the data.
Following the principle of *distributed trust*, transcryption can be distributed over `n` transcryptors: every transcryptor can independently monitor and block data exchanges, while confidentiality and pseudonym unlinkability hold as long as at least one transcryptor remains uncompromised.
The library primarily implements the *n-PEP* scheme (see [Background](#background)).
In terms of other primitives, the pseudonymisation step is an oblivious evaluation of the same DH-PRF as an [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html) OPRF, and the re-encryption step is ordinary ElGamal proxy re-encryption (see [Relation to other primitives](#relation-to-other-primitives)).

In the ElGamal scheme, a message `M` can be encrypted for a receiver which has public key `Y` associated with it, belonging to secret key `y`. 
This encryption is random (polymorphic): every time a different random `b` is used, results in different ciphertexts (encrypted messages).
We represent this encryption function as `Enc(b, M, Y)`.

The library supports three homomorphic operations on ciphertext `in` (= `Enc(b, M, Y)`, encrypting message `M` for public key `Y` with random `b`):
- `out = rekey(in, k)`: if `in` can be decrypted by secret key `y`, then `out` can be decrypted by secret key `k*y`.
   Both decrypt to the same message `M`. Specifically, `in = Enc(b, M, Y)` is transformed to `out = Enc(k^-1*b, M, k*Y)`.
- `out = reshuffle(in, s)`: modifies a ciphertext `in` (an encrypted form of `M`), so that after decryption of `out` the decrypted message will be equal to `s*M`.
  Specifically, `in = Enc(b, M, Y)` is transformed to `out = Enc(s*b, s*M, Y)`.
- `out = rerandomize(in, r)`: scrambles a ciphertext.
  Both `in` and `out` can be decrypted by the same secret key `y`, both resulting in the same decrypted message `M`.
  However, the binary form of `in` and `out` differs. Specifically, `in = Enc(b, M, Y)` is transformed to `out = Enc(b+r, M, Y)`.

With these three operations, encrypted data can be re-encrypted for different keys without decrypting the data, while pseudonymizing encrypted identifiers by reshuffling them with a user-specific factor.
The core idea behind is that the pseudonymization and rekeying operations are applied on *encrypted* data.
This means that during initial encryption, the ultimate receiver(s) do(es) not yet need to be known.
Data can initially be encrypted for one key, and later rekeyed and potentially reshuffled (in case of identifiers) for another key, leading to non-interactive asynchronous end-to-end encryption with built-in pseudonymisation.

## Applications

For pseudonymization, the core operation is *reshuffle* with `s`.
Every user (or user group) knows a data subject under its own *local pseudonym*, and reshuffling converts a pseudonym from one user's domain to another's (effectively applying `s = s_from^-1 * s_to`), without a global pseudonym existing in between.
The factor `s` is typically tied to the *access group* or *domain of a user*, which we call the *pseudonymization domain*.

Pseudonym unlinkability rests on the fact that `F_s(M) = s*M` is the Diffie–Hellman pseudorandom function (DH-PRF): as long as `s` stays secret, `s*M` is indistinguishable from a random group element under the Decisional Diffie–Hellman (DDH) assumption, so pseudonyms in different domains cannot be linked without knowing the ratio of their domain factors.
Reshuffling an *encrypted* pseudonym is an encryption-based *oblivious evaluation* of this PRF: because the operation is homomorphic, the transcryptor applies its secret factor `s` without ever seeing the pseudonym or the result, and the sender and recipient never learn `s`.

Strictly, the DH-PRF is `F_s(M) = s*H(M)` for a hash `H` into the group: without `H`, `F_s` is linear (`F_s(a*M) = a*F_s(M)`) and thus not pseudorandom for inputs with known discrete-log relations.
This library omits `H` because origin identifiers are expected to be uniformly random group elements, either sampled directly or produced by the elligator2-based lizard encoding, which makes it infeasible to construct identifiers with known relations.
Importing group elements with other distributions (e.g. via `from_bytes` or `from_hex`) weakens this: reshuffling is then no longer fully pseudorandom, since discrete-log relations between origin identifiers are preserved in every domain (if `M1 = 2*M2`, then also `s*M1 = 2*(s*M2)`).
Individual pseudonyms remain unlinkable across domains under DDH, so this is acceptable as long as no party knows the relations between origin identifiers: a party that does could recognize related pseudonyms by testing for the known relation.

Using only a reshuffle is insufficient, as the pseudonym is still encrypted for a key the user does not possess.
To allow a user to decrypt the encrypted pseudonym, a *rekey* with `k` is needed, in combination with a protocol to hand the user the secret key `k*y`.
The factor `k` is typically tied to the *current session of a user*, which we call the *encryption context*.

When the same encrypted pseudonym is used multiple times, rerandomize is applied every time.
This way a binary compare of the encrypted pseudonym will not leak any information.
Mixing fresh randomness into a ciphertext before reshuffling also protects against plaintext injection attacks at transcryption.

The `reshuffle(in, s)` and `rekey(in, k)` can be combined in a slightly more efficient `rsk(in, s, k)`.

Additionally, `reshuffle2(in, s_from, s_to)` and `rekey2(in, k_from, k_to)`, as well as `rsk2(...)`, are the transitive and reversible n-PEP variants that convert directly between two domains or sessions, effectively applying `s = s_from^-1 * s_to` and `k = k_from^-1 * k_to`.

## Relation to other primitives

libpep combines two familiar primitives: `reshuffle` is an OPRF evaluation and `rekey` is a proxy re-encryption, applied to the same ciphertext.

### As a three-party OPRF

[RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html) specifies oblivious pseudorandom functions over prime-order groups as a two-party protocol: a *Client* (or *requester*) blinds an input, a *Server* (or *evaluator*) applies its secret key `skS`, and the client unblinds to obtain `F_skS(input)`, with the server learning neither input nor output.

libpep evaluates the same DH-PRF `F_s(M) = s*M`, but splits the requester role over a **sender** and a **recipient**, with the **transcryptor** as evaluator.
ElGamal encryption takes the place of blinding: the sender's encryption randomness `b` blinds the pseudonym, the transcryptor reshuffles with its domain factor `s`, and the recipient's decryption unblinds.
The transcryptor learns neither `M` nor `s*M`, and neither sender nor recipient learns `s`.

Because blinding and unblinding are performed by different parties, evaluation is non-interactive and asynchronous: the sender can encrypt before the recipient is known, and the PRF output appears only in the recipient's domain.

Two differences with the RFC are worth noting.
RFC 9497 defines the PRF as `F_s(M) = s*H(M)`, hashing into the group first; libpep omits `H` and instead relies on origin identifiers being uniformly random group elements, as described under [Applications](#applications).
And the RFC's VOPRF and POPRF modes provide verifiability, whereas plain PEP transcryption does not: a transcryptor that applies a wrong factor produces an incorrect pseudonym undetectably.

### As proxy re-encryption with built-in pseudonymisation

`rekey` is ordinary unidirectional [proxy re-encryption](https://en.wikipedia.org/wiki/Proxy_re-encryption) over ElGamal: it transforms `Enc(b, M, Y)` into `Enc(k^-1*b, M, k*Y)`, decryptable by `k*y`.
The message component is untouched, and the transcryptor acts as the proxy without learning the message or holding either secret key.

`reshuffle` adds the one transformation a plain proxy cannot do, mapping `M` to `s*M`.
Attributes are never reshuffled — transcrypting an `EncryptedAttribute` is a `rekey` and nothing else — so for attributes the scheme is exactly proxy re-encryption.
For identifiers, the same homomorphic step that re-encrypts a pseudonym for a new recipient also rewrites it into that recipient's domain, so no global identifier is ever exposed.

This is what the name refers to: *polymorphic* encryption is the proxy re-encryption, and *pseudonymisation* is the PRF evaluation carried out in the same step.
`rsk(in, s, k)` performs both at once.

## Installation

Install from crates.io using cargo:
```
cargo install libpep
```

or add as a dependency in your `Cargo.toml`:
```toml
[dependencies]
libpep = <latest-version>
```

Run the `peppy` CLI using cargo:
```
cargo run --bin peppy
```

Apart from a Rust crate, this library provides bindings for multiple platforms:

### Python

Install from PyPI:
```bash
pip install libpep-py
```

### WebAssembly (WASM)

Install from npm:
```bash
npm install @nolai/libpep-wasm
```

## API Structure

The library is organized into the following main modules, each providing a different level of abstraction and functionality for working with PEP:

| Module | Description |
|--------|-------------|
| `elgamal` | Low-level ElGamal encryption/decryption, PEP primitives (`rekey`, `reshuffle`, `rerandomize`) in `elgamal::primitives`, and the underlying Curve25519 scalar and group element arithmetic in `elgamal::arithmetic` |
| `data` | Data types: `Pseudonym`, `Attribute`, JSON structures, long data support, and padding |
| `keys` | Key management: global keys, session keys, key generation, and distributed key setup |
| `contexts` | Pseudonymization domains and encryption contexts, the identifiers that data is pseudonymized and encrypted for |
| `factors` | Cryptographic factors: secrets, rekey/reshuffle/rerandomize factors, transcryption info, and derivation functions |
| `transcryptor` | Transcryptor for pseudonymization and rekeying operations |
| `client` | Client-side encryption and decryption using session keys |

### Keys Module (`keys`)

- `keys::types` - Key type definitions (GlobalPublicKeys, SessionKeys, etc.)
- `keys::generation` - Functions for generating global and session keys
- `keys::traits` - `PublicKey` and `SecretKey`: encoding, explicit construction from a group element or scalar, and deriving a public key from a secret key
- `keys::distribution` - Distributed key generation and setup for multi-party transcryptors; its blinding factors, blinded global secret keys and session key shares are protocol material rather than keys and have their own traits

Key types have no implicit conversions from raw scalars or group elements: a key is generated, derived from another key, or explicitly constructed with `SecretKey::from_scalar` or `PublicKey::from_point`.

### Contexts Module (`contexts`)

- `PseudonymizationDomain` - the domain a pseudonym exists in (typically a user's role or usergroup)
- `EncryptionContext` - the context a ciphertext exists in (typically a user's session)

### Factors Module (`factors`)

- `factors::types` - Factor types (ReshuffleFactor, PseudonymRekeyFactor, AttributeRekeyFactor, RerandomizeFactor) and the info types bundling them for one transcryption (PseudonymizationInfo, PseudonymRekeyInfo, AttributeRekeyInfo, TranscryptionInfo)
- `factors::secrets` - Secret types (PseudonymizationSecret, EncryptionSecret)
- `factors::derivation` - Derivation of factors and transcryption info from secrets and contexts

### Data Module (`data`)

- `data::simple` - Simple `Pseudonym` and `Attribute` types (up to 15 bytes)
- `data::padding` - Padding utilities for data types
- `data::long` - Long pseudonyms and attributes (over 15 bytes with PKCS#7 padding) (requires `long` feature)
- `data::records` - Record types for batch operations
- `data::json` - JSON structured data with nested pseudonyms and attributes (requires `json` feature)
- `data::traits` - Common traits for data types

### Prelude

The library provides convenient prelude modules for common operations:

- `prelude::client` - Re-exports for client-side encryption/decryption operations
- `prelude::transcryptor` - Re-exports for transcryptor operations (pseudonymization, rekeying, transcryption)

### Distributed Transcryptors

The library supports distributed n-PEP operations where multiple transcryptors cooperatively perform pseudonymization and rekeying without any single party having access to the global secret keys:

- Key distribution setup is in `keys::distribution`
- The transcryptor side is `transcryptor::DistributedTranscryptor`, which produces session key shares
- The client side is the `client::Distributed` extension trait, which reconstructs and updates session keys from shares

For detailed API documentation, see [docs.rs/libpep](https://docs.rs/libpep)

Both Python and WASM bindings mirror the Rust API structure with the same modules and organization.

### Features

The following features are available:

**Default features** (included unless you use `--no-default-features`):
- `long`: enables support for long pseudonyms and attributes over 15 bytes using PKCS#7 padding.
- `offline`: enables offline encryption towards global keys (instead of only session keys).
- `batch`: enables batch transcryption operations with reordering to prevent linkability.
- `serde`: enables serialization/deserialization support via Serde.
- `json`: enables PEP json structured data types.
- `build-binary`: builds the `peppy` command-line tool.

**Optional features:**
- `elgamal3`: enables ElGamal triple encryption (the `(B, C, Y)` triple encoding of the original basic-PEP framework), where ciphertexts additionally encode the public key they were encrypted for. This makes decryption with a mismatched key detectable, at the cost of larger ciphertexts and slower operations. **This feature changes API signatures**: decryption functions return `Option` (or an error for batches) instead of a plain value, since key mismatch becomes detectable. Choose one mode for your deployment; the two modes are not wire-compatible.
- `legacy`: enables compatibility with the legacy PEP repository implementation, which uses a different function to derive scalars from domains, contexts, and secrets. Implies `elgamal3`, `offline` and `global-pseudonyms`. Only use this for interoperability with existing legacy PEP deployments.
- `insecure`: enables methods that use global *secret* keys directly, such as offline decryption (`decrypt_global`). In the intended security model, the global secret key is discarded after distributed setup and never exists in one place; retaining it to use these methods gives whoever holds it the ability to decrypt everything. Only intended for testing and for special deployments that consciously accept this.
- `global-pseudonyms`: allows pseudonyms in a *global* pseudonymization domain (using reshuffle factor 1). Global pseudonyms are linkable across all domains, which defeats the purpose of domain-specific pseudonymization; only use this when such linkability is an explicit requirement.


## Security and Implementation

This library uses Ristretto encoding on Curve25519, implemented in the [`curve25519-dalek` crate](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/), offering 128 bits of security.
The minimum supported Rust version (MSRV) is 1.85; raising it is considered a semver-relevant change.
Confidentiality rests on the semantic security of ElGamal, and pseudonym unlinkability on the pseudorandomness of the DH-PRF evaluated by reshuffling; both hold under the Decisional Diffie–Hellman (DDH) assumption in the Ristretto group and thus ultimately on the hardness of the discrete logarithm problem.

### Security Considerations
- All cryptographic operations use constant-time algorithms to prevent timing attacks
- Random number generation uses cryptographically secure sources
- The library has been designed for production use but hasn't yet undergone formal security auditing
- Users should properly secure private keys and avoid exposing sensitive cryptographic material

### Arithmetic Rules
There are a number of arithmetic rules for scalars and group elements: group elements can be added and subtracted from each other.
Scalars support addition, subtraction, and multiplication.
Division can be done by multiplying with the inverse (using `s.invert()` for non-zero scalar `s`).
A scalar can be converted to a group element (by multiplying with the special generator `G`), but not the other way around.
Group elements can also be multiplied by a scalar.

Group elements have an *almost* 32 byte range (top bit is always zero, and some other values are invalid).
Group elements can be generated by `GroupElement::random(..)` or `GroupElement::from_hash(..)`.
Scalars are also 32 bytes, and can be generated with `Scalar::random(..)` or `Scalar::from_hash(..)`.
There are specific classes for `ScalarNonZero` and `ScalarCanBeZero`, since for almost all PEP operations, the scalar should be non-zero.

## Development

### Prerequisites
- Rust 1.85+ (MSRV)
- Node.js 18+ (for WASM bindings)
- Python 3.8+ (for Python bindings)

### Building and Testing

Build and test the core Rust library:
```bash
cargo build
cargo test
cargo clippy
cargo doc --no-deps
```

Run tests with different feature combinations:
```bash
cargo test --features elgamal3
cargo test --features legacy
```

### Building Bindings

#### Python

The Python bindings live in the `bindings/python` workspace crate. To build and test them:
```bash
python -m venv .venv
source .venv/bin/activate
pip install maturin pytest
cd bindings/python
maturin develop
python -m unittest discover tests -v
```

To build a wheel for distribution (from `bindings/python`):
```bash
maturin build --release
```

#### WASM

The WASM bindings live in the `bindings/wasm` workspace crate. To build and test them:
```bash
cd bindings/wasm
npm install
npm run build  # Builds both bundler and web targets
npm test
```

To build for a specific target (from `bindings/wasm`):
```bash
npm run build:nodejs  # For Node.js, into pkg/
npm run build:web     # For browsers, into pkg-web/
```

## License
- Authors: Bernard van Gastel and Job Doesburg
- License: Apache License 2.0

## Background

This library primarily implements the *n-PEP* scheme, described in:

> Job Doesburg, Bernard van Gastel and Erik Poll, *n-PEP: Secure Data Sharing with Transitive and Distributed Blind Pseudonymization*. In **Security and Trust Management. 22nd International Workshop, STM 2026, Proceedings**, Lecture Notes in Computer Science, Springer. [PDF](https://jobdoesburg.nl/docs/n-PEP-STM2026.pdf)

n-PEP extends the PEP framework with *reversible* and *transitive* pseudonymization between domains (the `reshuffle2`/`rekey2`/`rsk2` operations), eliminating the polymorphic pseudonyms that act as a linking oracle in basic PEP, and distributes transcryption and session key establishment over `n` semi-trusted transcryptors, so that confidentiality and pseudonym unlinkability hold as long as at least one transcryptor remains uncompromised.

The original PEP framework, which n-PEP extends, was introduced in:

> Eric Verheul and Bart Jacobs, *Polymorphic Encryption and Pseudonymisation in Identity Management and Medical Research*. In **Nieuw Archief voor Wiskunde (NAW)**, 5/18, nr. 3, 2017, p. 168-172. [PDF](https://repository.ubn.ru.nl/bitstream/handle/2066/178461/178461.pdf?sequence=1)

## Citing

If you use this library in academic work, please cite the n-PEP paper (see also [`CITATION.cff`](CITATION.cff)).
