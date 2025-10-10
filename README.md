# `libpep`: Library for polymorphic pseudonymization and encryption
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
This encryption is random: every time a different random `b` is used, results in different ciphertexts (encrypted messages).
We represent this encryption function as `Enc(b, M, Y)`.

The library supports three homomorphic operations on ciphertext `in` (= `Enc(b, M, Y)`, encrypting message `M` for public key `Y` with random `b`):
- `out = rekey(in, k)`: if `in` can be decrypted by secret key `y`, then `out` can be decrypted by secret key `k*y`.
   Decryption will both result in message `M`. Specifically, `in = Enc(r, M, Y)` is transformed to `out = Enc(r, M, k*Y)`.
- `out = reshuffle(in, s)`: modifies a ciphertext `in` (an encrypted form of `M`), so that after decryption of `out` the decrypted message will be equal to `s*M`.
  Specifically, `in = Enc(r, M, Y)` is transformed to `out = Enc(r, n*M, Y)`.
- `o = rerandomize(in, r)`: scrambles a ciphertext.
  Both `in` and `out` can be decrypted by the same secret key `y`, both resulting in the same decrypted message `M`.
  However, the binary form of `in` and `out` differs. Spec: `in = Enc(b, M, Y)` is transformed to `out = Enc(r+b, M, Y)`;

The `reshuffle(in, n)` and `rekey(in, k)` can be combined in a slightly more efficient `rsk(in, k, n)`.

Additionally, `reshuffle2(in, n_from, n_to)` and `rekey2(in, k_from, k_to)`, as well as `rsk2(...)`, can be used for bidirectional transformations between two keys, effectively applying `k = k_from^-1 * k_to` and `n = n_from^-1 * n_to`.

The key idea behind this form of cryptography is that the pseudonymization and rekeying operations are applied on *encrypted* data.
This means that during initial encryption, the ultimate receiver(s) do(es) not yet need to be known.
Data can initially be encrypted for one key, and later rekeyed and potentially reshuffled (in case of identifiers) for another key, leading to asynchronous end-to-end encryption with built-in pseudonymisation.

Apart from a Rust crate, this library provides bindings for multiple platforms:

## Language Bindings

### Python

Install from PyPI:
```bash
pip install libpep-py
```

Use with direct imports from submodules:
```python
from libpep.high_level import Pseudonym, Attribute, make_global_keys
from libpep.arithmetic import GroupElement, ScalarNonZero

# Generate keys
keys = make_global_keys()

# Create and work with pseudonyms
pseudonym = Pseudonym.random()
print(f"Pseudonym: {pseudonym.as_hex()}")

# Create data points
data = Attribute.random()
print(f"Data point: {data.as_hex()}")
```

### WebAssembly (WASM)

Install from npm:
```bash
npm install @nolai/libpep-wasm
```

Use in Node.js or browser applications:
```javascript
import * as libpep from '@nolai/libpep-wasm';

// Generate keys
const keys = libpep.make_global_keys();

// Create and work with pseudonyms
const pseudonym = libpep.Pseudonym.random();
console.log(`Pseudonym: ${pseudonym.as_hex()}`);

// Create data points
const data = libpep.Attribute.random();
console.log(`Data point: ${data.as_hex()}`);
```

### API Structure

Both Python and WASM bindings mirror the Rust API structure with the same modules:

| Module | Description |
|--------|-------------|
| `arithmetic` | Basic arithmetic operations on scalars and group elements |
| `elgamal` | ElGamal encryption and decryption primitives |
| `primitives` | Core PEP operations (`rekey`, `reshuffle`, `rerandomize`) |
| `high_level` | User-friendly API with `Pseudonym` and `Attribute` classes |
| `distributed` | Distributed n-PEP operations with multiple servers |

For detailed API documentation, see [docs.rs/libpep](https://docs.rs/libpep).

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

## Security and Implementation

This library uses the Ristretto encoding on Curve25519, implemented in the [`curve25519-dalek` crate](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/), with [patches by Signal](https://github.com/signalapp/curve25519-dalek) for _lizard_ encoding of arbitrary 16 byte values into ristretto points.

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

## API

We offer APIs at different abstraction levels.

0. The `arithmetic` module (internal API) offers the basic arithmetic operations on scalars and group elements and the `elgamal` module offers the ElGamal encryption and decryption operations.
1. The `primitives` module implements the basic PEP operations such as `rekey`, `reshuffle`, and `rerandomize` and the extended `rekey2` and `reshuffle2` variants, as well as a combined `rsk` and `rsk2` operation.
2. The `high_level` module offer a more user-friendly API with many high level data types such as `Pseudonyms` and `Attributes`.
3. The `distributed` module additionally provides a high-level API for distributed scenarios, where multiple servers are involved in the rekeying and reshuffling operations and keys are derived from multiple master keys.

Depending on the use case, you can choose the appropriate level of abstraction.

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
cargo test --features legacy-pep-repo-compatible
```

## Building Bindings

### Python

To build Python bindings for testing:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
maturin develop --features python
python -m pytest tests/python/ -v
```

### WASM

To build WASM bindings for testing:
```bash
npm install
npm run build  # Builds both Node.js and web targets
npm test
```

The following features are available:
- `python`: enables the Python bindings (mutually exclusive with `wasm`).
- `wasm`: enables the WASM library (mutually exclusive with `python`).
- `elgamal3`: enables longer ElGamal for debugging purposes or backward compatibility, but with being less efficient.
- `legacy-pep-repo-compatible`: enables the legacy PEP repository compatible mode, which uses a different function to derive scalars from domains, contexts and secrets.
- `insecure-methods`: enables insecure methods, to be used with care.
- `build-binary`: builds the `peppy` command-line tool to interact with the library (not recommended for production use).

**Note:** The `python` and `wasm` features are mutually exclusive because PyO3 (Python bindings) builds a cdylib that links to the Python interpreter, while wasm-bindgen builds a cdylib targeting WebAssembly. These have incompatible linking requirements and cannot coexist in the same build.

## Install

Install using
```
cargo install libpep
```

Run `peppy` using cargo:
```
cargo run --bin peppy
```

## License
- Authors: Bernard van Gastel and Job Doesburg
- License: Apache License 2.0

## Background

Based on the article by Eric Verheul and Bart Jacobs, *Polymorphic Encryption and Pseudonymisation in Identity Management and Medical Research*. In **Nieuw Archief voor Wiskunde (NAW)**, 5/18, nr. 3, 2017, p. 168-172.
