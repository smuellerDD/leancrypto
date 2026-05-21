//! Key exchange groups using OpenSSL
use rustls::crypto::SupportedKxGroup;

//#[cfg(not(feature = "fips"))]
mod x25519;
//#[cfg(not(feature = "fips"))]
pub use x25519::X25519;

mod kem;
pub use kem::{MLKEM768, MLKEM1024};

mod hybrid_kem;
pub use hybrid_kem::{X25519MLKEM768};

/// Key exchanges enabled by default by this provider:
/// * [X25519MLKEM768]
/// * [X25519] (if fips feature not enabled)
/// * [MLKEM768]
/// * [MLKEM1024]
///
/// If the `prefer-post-quantum` feature is enabled, X25519MLKEM768 will
/// be the first group offered, otherwise it will be the last.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
	X25519MLKEM768,
	//#[cfg(not(feature = "fips"))]
	X25519,
	MLKEM768,
	MLKEM1024
];
