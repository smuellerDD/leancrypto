/*
 * Copyright (C) 2025 - 2026, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

use std::ptr;
use std::sync::atomic;
use crate::ffi::leancrypto;
use crate::error::X509Error;

#[derive(Clone, Copy, Debug)]
pub enum lcr_key_type {
	lcr_unknown,
	lcr_dilithium_44,
	lcr_dilithium_65,
	lcr_dilithium_87,
	lcr_dilithium_44_ed25519,
	lcr_dilithium_65_ed25519,
	lcr_dilithium_87_ed25519,
	lcr_dilithium_44_ed448,
	lcr_dilithium_65_ed448,
	lcr_dilithium_87_ed448,
	lcr_sphincs_shake_256s,
	lcr_sphincs_shake_256f,
	lcr_sphincs_shake_192s,
	lcr_sphincs_shake_192f,
	lcr_sphincs_shake_128s,
	lcr_sphincs_shake_128f,
	lcr_ed25519,
	lcr_ed448,
}

#[derive(Debug)]
pub struct lcr_pkcs8 {
	pkcs8_sk: leancrypto::lc_pkcs8_message,
	raw_key: Vec<u8>,
	key_type: lcr_key_type,
	pkcs8_sk_parsed: bool,
}

#[allow(dead_code)]
impl lcr_pkcs8 {
	pub fn new() -> Self {
		lcr_pkcs8 {
			pkcs8_sk: unsafe { std::mem::zeroed() },
			raw_key: Vec::new(),
			key_type: lcr_key_type::lcr_unknown,
			pkcs8_sk_parsed: false,
		}
	}

	/// Is the key present and usable?
	pub fn key_is_usable(
		&self
	) -> bool {
		if self.pkcs8_sk_parsed == false {
			return false
		}

		true
	}

	pub fn key_type(
		&self
	) -> lcr_key_type {
		self.key_type
	}

	pub fn get_self(&self) -> &lcr_pkcs8 {
		return self;
	}

	/// Load private key formatted as PKCS8 DER blob
	pub fn pkcs8_sk_load(
		&mut self,
		der_key: &[u8]
	) -> Result<(), X509Error> {
		/*
		 * Copy the DER blob into local storage as the pkcs8_sk is only
		 * set of pointers into the DER structure.
		 */
		self.raw_key = Vec::from(der_key);

		let result = unsafe {
			leancrypto::lc_pkcs8_decode(&mut self.pkcs8_sk,
						    self.raw_key.as_ptr(),
						    self.raw_key.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}

		let mut key_type: u32 = 0;
		let result = unsafe {
			leancrypto::lc_pkcs8_key_type(&mut key_type,
						      &self.pkcs8_sk)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}

		self.key_type = match key_type {
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44 =>
				lcr_key_type::lcr_dilithium_44,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65 =>
				lcr_key_type::lcr_dilithium_65,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87 =>
				lcr_key_type::lcr_dilithium_87,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44_ED25519 =>
				lcr_key_type::lcr_dilithium_44_ed25519,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65_ED25519 =>
				lcr_key_type::lcr_dilithium_65_ed25519,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87_ED25519 =>
				lcr_key_type::lcr_dilithium_87_ed25519,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44_ED448 =>
				lcr_key_type::lcr_dilithium_44_ed448,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65_ED448 =>
				lcr_key_type::lcr_dilithium_65_ed448,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87_ED448 =>
				lcr_key_type::lcr_dilithium_87_ed448,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_256S =>
				lcr_key_type::lcr_sphincs_shake_256s,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_256F =>
				lcr_key_type::lcr_sphincs_shake_256f,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_192S =>
				lcr_key_type::lcr_sphincs_shake_192s,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_192F =>
				lcr_key_type::lcr_sphincs_shake_192f,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_128S =>
				lcr_key_type::lcr_sphincs_shake_128s,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_128F =>
				lcr_key_type::lcr_sphincs_shake_128f,
			leancrypto::lc_sig_types_LC_SIG_ED25519 =>
				lcr_key_type::lcr_ed25519,
			leancrypto::lc_sig_types_LC_SIG_ED448 =>
				lcr_key_type::lcr_ed448,
			_ => lcr_key_type::lcr_unknown,
		};

		self.pkcs8_sk_parsed = true;
		Ok(())
	}
}

unsafe impl Sync for lcr_pkcs8 {}
unsafe impl Send for lcr_pkcs8 {}

// impl Clone for lcr_pkcs8 {
// 	fn clone(&self) -> lcr_pkcs8 {
// 		lcr_pkcs8 {
// 			pkcs8_sk: self.pkcs8_sk,
// 			key_type: self.key_type,
// 			pkcs8_sk_parsed: self.pkcs8_sk_parsed,
// 		}
// 	}
// }

/// Leancrypto wrapper for the Leancrypto X.509 API
pub struct lcr_x509 {
	x509_cert: leancrypto::lc_x509_certificate,
	x509_cert_parsed: bool,
}

#[allow(dead_code)]
impl lcr_x509 {
	pub fn new() -> Self {
		lcr_x509 {
			x509_cert: unsafe { std::mem::zeroed() },
			x509_cert_parsed: false,
		}
	}

	/// Wrapper around lc_x509_cert_decode
	pub fn cert_decode(
		&mut self,
		der_certificate: &[u8]
	) -> Result<(), X509Error> {
		let result = unsafe {
			leancrypto::lc_x509_cert_decode(&mut self.x509_cert,
							der_certificate.as_ptr(),
							der_certificate.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}

		self.x509_cert_parsed = true;
		Ok(())
	}

	/// Is the certificate present and usable?
	pub fn cert_is_usable(
		&self
	) -> bool {
		if self.x509_cert_parsed == false {
			return false
		}

		true
	}

	/// Verify another certificate with self
	pub fn verify(
		&mut self,
		signature: &[u8],
		message: &[u8]
	) -> Result<(), X509Error> {
		if !self.cert_is_usable() {
			return Err(X509Error::UninitializedContext)
		}

		let result = unsafe {
			leancrypto::lc_x509_signature_verify(
				signature.as_ptr(), signature.len(),
				&self.x509_cert, message.as_ptr(),
				message.len(), ptr::null_mut())
		};
		if result < 0 {
			return Err(X509Error::VerifyError)
		}

		Ok(())
	}

	/// Verify another certificate with self
	pub fn verify_certificate(
		&mut self,
		cert: &lcr_x509
	) -> Result<(), X509Error> {
		if !self.cert_is_usable() || !cert.cert_is_usable() {
			return Err(X509Error::UninitializedContext)
		}

		Err(X509Error::UninitializedContext)
		//Ok(())
	}

	/// Method for safe immutable access to certificate
	// pub fn _get_x509_cert(
	// 	&mut self
	// ) -> (*mut leancrypto::lc_x509_certificate, Result<(), X509Error>) {
	// 	if self.cert_is_usable() {
	// 		return (ptr::null_mut(),
	// 			Err(X509Error::UninitializedContext));
	// 	}
 //
	// 	(&mut self.x509_cert, Ok(()))
	// }

	pub fn sign(
		&mut self,
		pkcs8: &lcr_pkcs8,
		message: &[u8]
	) -> Result<Vec<u8>, X509Error> {
		if !self.cert_is_usable() || !pkcs8.key_is_usable() {
			return Err(X509Error::UninitializedContext)
		}

		let mut siglen = 0;
		let result = unsafe {
			leancrypto::lc_pkcs8_get_signature_size_from_sk(
				&mut siglen, &pkcs8.pkcs8_sk)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}

		let mut signature = vec![0; siglen];
		let result = unsafe {
			leancrypto::lc_pkcs8_signature_gen(signature.as_mut_ptr(),
							   &mut siglen,
							   &pkcs8.pkcs8_sk,
							   message.as_ptr(),
							   message.len(),
							   ptr::null_mut())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}

		Ok(signature)
	}
}

/// This ensures the buffer is always freed
/// regardless of when it goes out of scope
impl Drop for lcr_x509 {
	fn drop(&mut self) {
		let /*mut*/ x509_cert: leancrypto::lc_x509_certificate = unsafe {
			std::mem::zeroed()
		};
		unsafe { std::ptr::write_volatile(&mut self.x509_cert, x509_cert) };
		atomic::compiler_fence(atomic::Ordering::SeqCst);
		self.x509_cert_parsed = false;
	}
}
