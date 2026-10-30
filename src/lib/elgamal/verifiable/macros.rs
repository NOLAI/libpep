//! Macros shared by the verifiable operations.

/// `verified_reconstruct` (the result of the operation if the proof verifies) and, with
/// `insecure`, `unverified_reconstruct` (the result without verifying), from a proof type's
/// `verify` and its crate-private `result`, so that the two can never disagree with `verify`.
macro_rules! reconstruct {
    (
        verified($($va:ident: $vt:ty),*) -> $out:ty = verify($($vv:ident),*);
        unverified($($ua:ident: $ut:ty),*) = result($($rv:ident),*);
    ) => {
        /// Verify the proof and return the result of the operation, or `None` if it does not
        /// verify.
        #[must_use]
        pub fn verified_reconstruct(&self, $($va: $vt),*) -> Option<$out> {
            self.verify($($vv),*).then(|| self.result($($rv),*))
        }

        /// The result of the operation, without verifying the proof.
        #[cfg(feature = "insecure")]
        pub fn unverified_reconstruct(&self, $($ua: $ut),*) -> $out {
            self.result($($rv),*)
        }
    };
}
