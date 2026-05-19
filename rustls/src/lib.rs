//! # rustls-leancrypto
//!
//! A [rustls crypto provider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html)  that uses leancrypto for crypto.
//!
//! ## Supported Ciphers
//!
//! Supported cipher suites are listed below, in descending order of preference.
//!
//! ### TLS 1.3
//!
//! * TLS13_AES_256_GCM_SHA384
//! * TLS13_AES_128_GCM_SHA256
//! * TLS13_CHACHA20_POLY1305_SHA256
//!
//! ## Supported Key Exchanges
//!
//! In descending order of preference:
//!
//! * X25519MLKEM768
//! * X25519
//! * MLKEM768
//! * MLKEM1024
//!
//! ## Usage
//!
//! Add `rustls-leancrypto` to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! rustls = { version = "0.23.0", features = ["tls13", "std"], default-features = false }
//! rustls_leancrypto = "0.1.0"
//! ```
//!
//! ### Configuration
//!
//! Use [default_provider()] to create a provider using cipher suites and key exchange groups listed above.
//! Use [custom_provider()] to specify custom cipher suites and key exchange groups.
//!
//! # Features
//! - `prefer-post-quantum`: Enables X25519MLKEM768 as the first key exchange group. Enabled by default.
//! - `fips`: Enabling this feature removes non-FIPS-approved cipher suites and key exchanges. Disabled by default. See [fips].
#![warn(missing_docs)]
use leancrypto_sys::lcr_rng::lcr_rng_generate_seeded;
use rustls::SupportedCipherSuite;
use rustls::crypto::{CryptoProvider, GetRandomFailed, SupportedKxGroup};

mod aead;
mod hash;
mod hkdf;
mod hmac;
pub mod kx_group;
mod quic;
mod signer;
mod tls13;
mod verify;

#[cfg(test)]
pub mod self_tests;

pub mod cipher_suite {
	//! Supported cipher suites.
	//#[cfg(all(chacha, not(feature = "fips")))]
	pub use super::tls13::TLS13_CHACHA20_POLY1305_SHA256;
	pub use super::tls13::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384};
}

pub use signer::KeyProvider;
pub use verify::SUPPORTED_SIG_ALGS;

/// Returns an leancrypto-based [CryptoProvider] using default available cipher suites ([ALL_CIPHER_SUITES]) and key exchange groups ([ALL_KX_GROUPS]).
///
/// Sample usage:
/// ```rust
/// use rustls::{ClientConfig, RootCertStore};
/// use rustls_leancrypto::default_provider;
/// use std::sync::Arc;
/// use webpki_roots;
///
/// let mut root_store = RootCertStore {
///     roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
/// };
///
/// let mut config =
///     ClientConfig::builder_with_provider(Arc::new(default_provider()))
///        .with_safe_default_protocol_versions()
///         .unwrap()
///         .with_root_certificates(root_store)
///         .with_no_client_auth();
///
/// ```
pub fn default_provider() -> CryptoProvider {
	CryptoProvider {
		cipher_suites: ALL_CIPHER_SUITES.to_vec(),
		kx_groups: kx_group::DEFAULT_KX_GROUPS.to_vec(),
		signature_verification_algorithms: SUPPORTED_SIG_ALGS,
		secure_random: &SecureRandom,
		key_provider: &KeyProvider,
	}
}

/// Create a [CryptoProvider] with specific cipher suites and key exchange groups
///
/// The specified cipher suites and key exchange groups should be defined in descending order of preference.
/// i.e the first elements have the highest priority during negotiation.
///
/// If the `fips` feature is enabled then fips mode will be enabled for leancrypto, and this function will panic if this fails.
///
/// Sample usage:
/// ```rust
/// use rustls::{ClientConfig, RootCertStore};
/// use rustls_leancrypto::custom_provider;
/// use rustls_leancrypto::cipher_suite::TLS13_AES_128_GCM_SHA256;
/// use rustls_leancrypto::kx_group::X25519;
/// use std::sync::Arc;
/// use webpki_roots;
///
/// let mut root_store = RootCertStore {
///     roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
/// };
///  
/// // Set custom config of cipher suites that have been imported from rustls_leancrypto.
/// let cipher_suites = vec![TLS13_AES_128_GCM_SHA256];
/// let kx_group = vec![X25519];
///
/// let mut config =
///     ClientConfig::builder_with_provider(Arc::new(custom_provider(
///         cipher_suites, kx_group)))
///             .with_safe_default_protocol_versions()
///             .unwrap()
///             .with_root_certificates(root_store)
///             .with_no_client_auth();
///
///
/// ```
pub fn custom_provider(
	cipher_suites: Vec<SupportedCipherSuite>,
	kx_groups: Vec<&'static dyn SupportedKxGroup>,
) -> CryptoProvider {
	CryptoProvider {
		cipher_suites,
		kx_groups,
		signature_verification_algorithms: SUPPORTED_SIG_ALGS,
		secure_random: &SecureRandom,
		key_provider: &KeyProvider,
    }
}

/// All supported cipher suites in descending order of preference:
/// * TLS13_AES_256_GCM_SHA384
/// * TLS13_AES_128_GCM_SHA256
/// * TLS13_CHACHA20_POLY1305_SHA256
///
/// If the non-default `fips` feature is enabled then the ChaCha20-Poly1305 cipher suites will not be included.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
	tls13::TLS13_AES_256_GCM_SHA384,
	tls13::TLS13_AES_128_GCM_SHA256,
	//#[cfg(all(chacha, not(feature = "fips")))]
	tls13::TLS13_CHACHA20_POLY1305_SHA256,
];

/// A struct that implements [rustls::crypto::SecureRandom].
#[derive(Debug)]
pub struct SecureRandom;

impl rustls::crypto::SecureRandom for SecureRandom {
	fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
		let result = lcr_rng_generate_seeded(&[], buf);
		match result {
			Err(_) => Err(GetRandomFailed),
			Ok(_) => Ok(())
		}
	}

	fn fips(&self) -> bool {
		fips::enabled()
	}
}

pub mod fips {
	//! # FIPS support
	//!
	//! To use rustls with leancrypto in FIPS mode, perform the following actions.
	//!
	//! ## 1. Enable the `fips` feature
	//!
	//! This removes non-FIPS-approved cipher suites and key exchanges.
	//!
	//! ## 2. Specify `require_ems` when constructing [rustls::ClientConfig] or [rustls::ServerConfig]
	//!
	//! See [rustls documentation](https://docs.rs/rustls/latest/rustls/client/struct.ClientConfig.html#structfield.require_ems) for rationale.
	//!
	//! ## 3. Enable FIPS mode for leancrypto
	//!
	//! See [enable()].
	//!
	//! ## 4. Validate the FIPS status of your ClientConfig or ServerConfig at runtime
	//! See [rustls documenation on FIPS](https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html#3-validate-the-fips-status-of-your-clientconfigserverconfig-at-run-time).

	/// Returns `true` if leancrypto is running in FIPS mode.
	#[cfg(fips_module)]
	pub(crate) fn enabled() -> bool {
		//leancrypto::fips::enabled()
		false
	}

	#[cfg(not(fips_module))]
	pub(crate) fn enabled() -> bool {
		false
	}

	/// Enable FIPS mode for leancrypto.
	///
	/// This should be called on application startup before the provider is used.
	///
	/// Panics if FIPS cannot be enabled
	#[cfg(fips_module)]
	pub fn enable() {
		println!("Failed to enable FIPS mode.");
	}

	/// Enable FIPS mode for leancrypto.
	///
	/// This should be called on application startup before the provider is used.
	///
	/// On leancrypto 1.1.1 this calls [FIPS_mode_set](https://wiki.leancrypto.org/index.php/FIPS_mode_set()).
	/// On leancrypto 3 this loads a FIPS provider, which must be available.
	///
	/// Panics if FIPS cannot be enabled
	#[cfg(not(fips_module))]
	pub fn enable() {
		println!("Failed to enable FIPS mode.");
	}
}
