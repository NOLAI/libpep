# `libpep`: Library for polymorphic pseudonymization and encryption
[![Crates.io](https://img.shields.io/crates/v/libpep.svg)](https://crates.io/crates/libpep)
[![Downloads](https://img.shields.io/crates/d/libpep.svg)](https://crates.io/crates/libpep)
[![npm](https://img.shields.io/npm/v/@nolai/libpep-wasm.svg)](https://www.npmjs.com/package/@nolai/libpep-wasm)
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
- `out = rerandomize(in, r)`: scrambles a ciphertext.
  Both `in` and `out` can be decrypted by the same secret key `y`, both resulting in the same decrypted message `M`.
  However, the binary form of `in` and `out` differs. Spec: `in = Enc(b, M, Y)` is transformed to `out = Enc(r+b, M, Y)`;

The `reshuffle(in, n)` and `rekey(in, k)` can be combined in a slightly more efficient `rsk(in, k, n)`.

Additionally, `reshuffle2(in, n_from, n_to)` and `rekey2(in, k_from, k_to)`, as well as `rsk2(...)`, can be used for bidirectional transformations between two keys, effectively applying `k = k_from^-1 * k_to` and `n = n_from^-1 * n_to`.

The key idea behind this form of cryptography is that the pseudonymization and rekeying operations are applied on *encrypted* data.
This means that during initial encryption, the ultimate receiver(s) do(es) not yet need to be known.
Data can initially be encrypted for one key, and later rekeyed and potentially reshuffled (in case of identifiers) for another key, leading to asynchronous end-to-end encryption with built-in pseudonymisation.

Apart from a Rust crate, this library also contains a WASM library for usage in the browser or web applications with a similar API, enabled with the `wasm` feature.

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

## Implementation

This library is using the Ristretto encoding on Curve25519, implemented in the [`curve25519-dalek` crate](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/), but with [patches by Signal](https://github.com/signalapp/curve25519-dalek) for _lizard_ encoding of arbitrary 16 byte values into ristretto points. 
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
2. The `high_level` module offer a more user-friendly API with many high level data types such as `Pseudonyms` and `DataPoints`.
3. The `distributed` module additionally provides a high-level API for distributed scenarios, where multiple servers are involved in the rekeying and reshuffling operations and keys are derived from multiple master keys.

Depending on the use case, you can choose the appropriate level of abstraction.

## Building and running

Build using cargo: `cargo build` and test using `cargo test`.

To build the WASM library, use either `npm run build:nodejs` or `npm run build:web` (which will call `wasm-pack build --features wasm` for the preferred target).

The wasm library can be tested using the Node.js `jest` framework, after compiling the wasm library for Node.js: `npm run test`.

The following features are available:
- `wasm`: enables the WASM library.
- `elgamal3`: enables longer ElGamal for debugging purposes or backward compatibility, but with being less efficient.
- `legacy-pep-repo-compatible`: enables the legacy PEP repository compatible mode, which uses a different function to derive scalars from domains, contexts and secrets.
- `insecure-methods`: enables insecure methods, to be used with care.
- `build-binary`: builds the `peppy` command-line tool to interact with the library (not recommended for production use).

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
