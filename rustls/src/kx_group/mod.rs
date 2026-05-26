//! Key exchange groups using leancrypto
use rustls::crypto::SupportedKxGroup;

#[cfg(all(not(feature = "fips"), feature = "nonpqc"))]
mod x25519;
#[cfg(all(not(feature = "fips"), feature = "nonpqc"))]
pub use x25519::X25519;

mod mlkem;
pub use mlkem::{MLKEM768, MLKEM1024};

mod x25519mlkem768;
pub use x25519mlkem768::X25519MLKEM768;

/// Key exchanges enabled by default by this provider:
/// * [X25519MLKEM768]
/// * [MLKEM1024]
/// * [MLKEM768]
/// * [X25519] (if fips feature not enabled)
///
/// If the `prefer-post-quantum` feature is enabled, X25519MLKEM768 will
/// be the first group offered, otherwise it will be the last.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    X25519MLKEM768,
    MLKEM1024,
    MLKEM768,
    #[cfg(all(not(feature = "fips"), feature = "nonpqc"))]
    X25519,
];
