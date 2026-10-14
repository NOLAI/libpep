//! Helpers shared by the integration tests: the transcryption calls that differ between the two
//! ciphertext encodings.
#![allow(unused_macros)]

/// Call a transcryption function with the argument list of the active ciphertext encoding: with
/// `elgamal3` the ciphertext carries its public key, otherwise it is passed explicitly.
macro_rules! tx {
    ($f:path, $enc:expr, $info:expr, $pk:expr, $rng:expr) => {{
        #[cfg(feature = "elgamal3")]
        let result = {
            let _ = &$pk;
            $f($enc, $info, $rng)
        };
        #[cfg(not(feature = "elgamal3"))]
        let result = $f($enc, $info, $pk, $rng);
        result
    }};
}

/// As [`tx!`], for a method call `$obj.$method(...)`.
macro_rules! txm {
    ($obj:ident . $m:ident, $enc:expr, $info:expr, $pk:expr, $rng:expr) => {{
        #[cfg(feature = "elgamal3")]
        let result = {
            let _ = &$pk;
            $obj.$m($enc, $info, $rng)
        };
        #[cfg(not(feature = "elgamal3"))]
        let result = $obj.$m($enc, $info, $pk, $rng);
        result
    }};
}

/// Decrypt with the active ciphertext encoding (with `elgamal3`, decryption can fail).
macro_rules! dec {
    ($enc:expr, $sk:expr) => {{
        #[cfg(feature = "elgamal3")]
        let result = libpep::client::decrypt($enc, $sk).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let result = libpep::client::decrypt($enc, $sk);
        result
    }};
}
