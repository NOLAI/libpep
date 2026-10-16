//! Secret values print redacted and can be wiped.
//!
//! Every type that holds a secret scalar or secret bytes implements `Debug` through
//! [`redacted_debug!`], so that a secret never ends up in a log through a derived `Debug`, and
//! implements [`Zeroize`](zeroize::Zeroize) through [`zeroize_fields!`]. The byte-string
//! secrets and the master secrets also wipe themselves when dropped; the scalar keys, shares
//! and factors are `Copy`, which rules out a `Drop` implementation, so a caller that wants them
//! wiped calls `zeroize` on every copy it holds.

/// Implement [`Zeroize`](zeroize::Zeroize) for a secret type by wiping the listed fields.
macro_rules! zeroize_fields {
    ($($name:ident$(<$g:ident>)? { $($field:tt),+ }),+ $(,)?) => {$(
        impl$(<$g: $crate::elgamal::arithmetic::group::Group>)? zeroize::Zeroize for $name$(<$g>)? {
            fn zeroize(&mut self) {
                $(zeroize::Zeroize::zeroize(&mut self.$field);)+
            }
        }
    )+};
}

/// Implement `Debug` for a secret type as `Name([redacted])`.
macro_rules! redacted_debug {
    ($($name:ident$(<$g:ident>)?),+ $(,)?) => {$(
        impl$(<$g: $crate::elgamal::arithmetic::group::Group>)? core::fmt::Debug
            for $name$(<$g>)?
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}([redacted])", stringify!($name))
            }
        }
    )+};
}
