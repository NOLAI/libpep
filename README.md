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
In the ElGamal scheme, a message `M` can be encrypted for a receiver which has public key `Y` associated with it, belonging to secret key `y`. 
This encryption is random (polymorphic): every time a different random `b` is used, results in different ciphertexts (encrypted messages).
We represent this encryption function as `Enc(b, M, Y)`.

The library supports three homomorphic operations on ciphertext `in` (= `Enc(b, M, Y)`, encrypting message `M` for public key `Y` with random `b`):
- `out = rekey(in, k)`: if `in` can be decrypted by secret key `y`, then `out` can be decrypted by secret key `k*y`.
   Decryption will both result in message `M`. Specifically, `in = Enc(r, M, Y)` is transformed to `out = Enc(r, M, k*Y)`.
- `out = reshuffle(in, s)`: modifies a ciphertext `in` (an encrypted form of `M`), so that after decryption of `out` the decrypted message will be equal to `s*M`.
  Specifically, `in = Enc(r, M, Y)` is transformed to `out = Enc(r, n*M, Y)`.
- `o = rerandomize(in, r)`: scrambles a ciphertext.
  Both `in` and `out` can be decrypted by the same secret key `y`, both resulting in the same decrypted message `M`.
  However, the binary form of `in` and `out` differs. Spec: `in = Enc(b, M, Y)` is transformed to `out = Enc(r+b, M, Y)`;

With these three operations, encrypted data can be re-encrypted for different keys without decrypting the data, while pseudonymizing encrypted identifiers by reshuffling them with a user-specific factor.
The core idea behind is that the pseudonymization and rekeying operations are applied on *encrypted* data.
This means that during initial encryption, the ultimate receiver(s) do(es) not yet need to be known.
Data can initially be encrypted for one key, and later rekeyed and potentially reshuffled (in case of identifiers) for another key, leading to non-interactive asynchronous end-to-end encryption with built-in pseudonymisation.

## Applications

For pseudonymization, the core operation is *reshuffle* with `s`.
It modifies a main pseudonym with a factor `s` that is specific to a user (or user group) receiving the pseudonym.
After applying a user specific factor `s`, a pseudonym is called a *local pseudonym*.
The factor `s` is typically tied to the *access group* or *domain of a user*, which we call the *pseudonymization domain*.

Using only a reshuffle is insufficient, as the pseudonym is still encrypted for a key the user does not possess.
To allow a user to decrypt the encrypted pseudonym, a *rekey* with `k` is needed, in combination with a protocol to hand the user the secret key `k*y`.
The factor `k` is typically tied to the *current session of a user*, which we call the *encryption context*.

When the same encrypted pseudonym is used multiple times, rerandomize is applied every time.
This way a binary compare of the encrypted pseudonym will not leak any information.

The `reshuffle(in, n)` and `rekey(in, k)` can be combined in a slightly more efficient `rsk(in, k, n)`.

Additionally, `reshuffle2(in, n_from, n_to)` and `rekey2(in, k_from, k_to)`, as well as `rsk2(...)`, can be used for bidirectional transformations between two keys, effectively applying `k = k_from^-1 * k_to` and `n = n_from^-1 * n_to`.

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

The library is organized into the following main modules, each providing a different level of abstraction and functionality for working with PEP (not so coincidentally organized alphabetically):

| Module | Description |
|--------|-------------|
| `arithmetic` | Basic arithmetic operations on scalars and group elements |
| `base` | ElGamal encryption/decryption and core PEP primitives (`rekey`, `reshuffle`, `rerandomize`) |
| `core` | User-friendly API with `Pseudonym` and `Attribute` types, keys, and transcryption operations |
| `distributed` | Distributed n-PEP operations with `PEPSystem` and `PEPClient` for multi-server setups |

For detailed API documentation, see [docs.rs/libpep](https://docs.rs/libpep)

Both Python and WASM bindings mirror the Rust API structure with the same modules.

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
- `python`: enables Python bindings via PyO3 (mutually exclusive with `wasm`).
- `wasm`: enables WebAssembly bindings via wasm-bindgen (mutually exclusive with `python`).
- `elgamal3`: enables ElGamal triple encryption, including the recipient's public key in message encoding. This provides additional security verification but is less efficient.
- `legacy`: enables compatibility with the legacy PEP repository implementation, which uses a different function to derive scalars from domains, contexts, and secrets.
- `insecure`: enables methods that expose global secret keys, to be used with care for testing or special use cases.
- `global-pseudonyms`: enables global pseudonyms (which are insecure).

**Note:** The `python` and `wasm` features are mutually exclusive because PyO3 (Python bindings) builds a cdylib that links to the Python interpreter, while wasm-bindgen builds a cdylib targeting WebAssembly.
These have incompatible linking requirements and cannot coexist in the same build.

## Security and Implementation

This library uses Ristretto encoding on Curve25519, implemented in the [`curve25519-dalek` crate](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/).

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
- Rust 1.70+ (MSRV)
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

To build and test Python bindings:
```bash
python -m venv .venv
source .venv/bin/activate
pip install maturin pytest
maturin develop --features python
python -m unittest discover tests/python/ -v
```

To build a wheel for distribution:
```bash
maturin build --release --features python
```

#### WASM

To build and test WASM bindings:
```bash
npm install
npm run build  # Builds both Node.js and web targets
npm test
```

To build for a specific target:
```bash
wasm-pack build --target nodejs --features wasm  # For Node.js
wasm-pack build --target web --features wasm     # For browsers
```

## License
- Authors: Bernard van Gastel and Job Doesburg
- License: Apache License 2.0

## Background

Based on the article by Eric Verheul and Bart Jacobs, *Polymorphic Encryption and Pseudonymisation in Identity Management and Medical Research*. In **Nieuw Archief voor Wiskunde (NAW)**, 5/18, nr. 3, 2017, p. 168-172.
