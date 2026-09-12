# @nolai/libpep-wasm: WebAssembly bindings for libpep

WebAssembly bindings for [libpep](https://github.com/NOLAI/libpep), a library for polymorphic encryption and pseudonymization implementing the *n-PEP* scheme: end-to-end encrypted, pseudonymized data sharing where semi-trusted *transcryptors* blindly re-encrypt data and convert pseudonyms between domains, with distributed trust over `n` transcryptors.

## Installation

```bash
npm install @nolai/libpep-wasm
```

The package ships both a Node.js and a browser build, selected automatically through the `exports` field:

```javascript
import { Pseudonym, makeGlobalKeys, makeSessionKeys, encrypt, decrypt } from "@nolai/libpep-wasm";
```

See the [repository README](https://github.com/NOLAI/libpep) for the full documentation, the cryptographic background, and the papers describing the scheme.

## Development

Build and test from this crate directory:

```bash
cd bindings/wasm
npm install
npm test
```

To build for a specific target:

```bash
npm run build:nodejs  # Node.js, into pkg/
npm run build:web     # browsers, into pkg-web/
npm run build         # bundler + web, for publishing
```

## License
- Authors: Bernard van Gastel and Job Doesburg
- License: Apache License 2.0
