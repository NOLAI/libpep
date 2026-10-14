//! Secret values print redacted.
//!
//! Every type that holds a secret scalar or secret bytes implements `Debug` through
//! [`redacted_debug!`], so that a secret never ends up in a log through a derived `Debug`.

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
