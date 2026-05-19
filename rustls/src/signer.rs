use leancrypto_sys::lcr_x509::lcr_x509;
use leancrypto_sys::lcr_x509::lcr_x509_key;
use leancrypto_sys::lcr_x509::lcr_x509_key_type;

use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use std::sync::RwLock;
use std::sync::Arc;

/// A struct that implements [rustls::crypto::KeyProvider].
#[derive(Debug)]
pub struct KeyProvider;

#[derive(Debug)]
struct Signer {
	key: Arc<RwLock<leancrypto_sys::lcr_x509::lcr_x509_key>>,
	scheme: SignatureScheme,
}

#[derive(Debug)]
struct PKey(Arc<RwLock<leancrypto_sys::lcr_x509::lcr_x509_key>>);

#[allow(dead_code)]
impl PKey {
	fn signer(&self, scheme: SignatureScheme) -> Signer {
		Signer {
			key: Arc::clone(&self.0),
			scheme: scheme,
		}
	}
}

impl rustls::crypto::KeyProvider for KeyProvider {
	fn load_private_key(
		&self,
		key_der: PrivateKeyDer<'static>,
	) -> Result<Arc<dyn SigningKey>, Error> {
		let mut pkcs8 = lcr_x509_key::new();

		pkcs8.pkcs8_sk_load(&key_der.secret_der())
			.map_err(|e| Error::General(format!("leancrypto error: {e}")))?;
		Ok(Arc::new(PKey(Arc::new(RwLock::new(pkcs8)))))
	}

	fn fips(&self) -> bool {
		crate::fips::enabled()
	}
}

impl SigningKey for PKey {
	fn choose_scheme(
		&self,
		offered: &[SignatureScheme]
	) -> Option<Box<dyn rustls::sign::Signer>> {
		//TODO enable once rustls has it
		// if offered.contains(&SignatureScheme::ML_DSA_87) {
		// 	Some(Box::new(Signer {
		// 		key: Arc::clone(&self.0),
		// 		scheme: SignatureScheme::ML_DSA_87,
		// 	}))
		// } else if offered.contains(&SignatureScheme::ML_DSA_65) {
		// 	Some(Box::new(Signer {
		// 		key: Arc::clone(&self.0),
		// 		scheme: SignatureScheme::ML_DSA_65,
		// 	}))
		// } else if offered.contains(&SignatureScheme::ML_DSA_44) {
		// 	Some(Box::new(Signer {
		// 		key: Arc::clone(&self.0),
		// 		scheme: SignatureScheme::ML_DSA_44,
		// 	}))
		/*} else*/ if offered.contains(&SignatureScheme::ED25519) {
			Some(Box::new(Signer {
				key: Arc::clone(&self.0),
				scheme: SignatureScheme::ED25519,
			}))
		} else {
			None
		}
	}

	fn algorithm(&self) -> SignatureAlgorithm {
		let clone = Arc::clone(&self.0);
		let key = clone.read().unwrap();

		let val = key.key_type() as u8;
		match key.key_type() {
		//TODO enable once rustls has it
		// lcr_x509_key_type::lcr_dilithium_44 => SignatureAlgorithm::ML_DSA_44,
		// lcr_x509_key_type::lcr_dilithium_65 => SignatureAlgorithm::ML_DSA_65,
		// lcr_x509_key_type::lcr_dilithium_87 => SignatureAlgorithm::ML_DSA_87,
		lcr_x509_key_type::lcr_ed25519 => SignatureAlgorithm::ED25519,
		_ => SignatureAlgorithm::Unknown(val),
		}
	}
}

impl rustls::sign::Signer for Signer {
	fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
		let mut x509 = lcr_x509::new();
		let clone = Arc::clone(&self.key);
		let key = clone.read().unwrap();

		if self.scheme == SignatureScheme::ED25519 {
			x509.enable()
				.map_err(|e| Error::General(format!("leancrypto error: {e}")))?;
		}

		x509.sign(key.get_self(), message)
			.map_err(|e| Error::General(format!("leancrypto error: {e}")))
	}

	fn scheme(&self) -> SignatureScheme {
		self.scheme
	}
}
