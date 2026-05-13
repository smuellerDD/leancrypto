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

use std::ffi::CString;
use std::fmt;
use std::ptr;
use crate::ffi::leancrypto;
use crate::error::X509Error;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug)]
pub enum lcr_x509_key_type {
	lcr_unknown,
	lcr_dilithium_44,
	lcr_dilithium_65,
	lcr_dilithium_87,
	lcr_dilithium_44_ed25519,
	lcr_dilithium_65_ed25519,
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
pub struct lcr_x509_key {
	/// Key type
	key_type: lcr_x509_key_type,

	/// Buffer memory holding the actual public/private key
	x509_key_data: *mut leancrypto::lc_x509_key_data,

	/// Secret key information
	pkcs8_sk: leancrypto::lc_pkcs8_message,
	sk_der_key: Vec<u8>,
	has_sk: bool,

	/// Public key information
	x509_cert: leancrypto::lc_x509_certificate,
	cert_der: Vec<u8>,
	has_pk: bool,
	has_certificate: bool,
}

#[allow(dead_code)]
impl lcr_x509_key {
	pub fn new() -> Self {
		lcr_x509_key {
			key_type: lcr_x509_key_type::lcr_unknown,
			x509_key_data: ptr::null_mut(),

			pkcs8_sk: unsafe { std::mem::zeroed() },
			sk_der_key: Vec::new(),
			has_sk: false,

			x509_cert: unsafe { std::mem::zeroed() },
			cert_der: Vec::new(),
			has_pk: false,
			has_certificate: false
		}
	}

	pub fn key_type(
		&self
	) -> lcr_x509_key_type {
		self.key_type
	}

	pub fn get_self(
		&self
	) -> &lcr_x509_key {
		return self;
	}

	fn alloc_key_data(
		&mut self
	) -> Result<(), X509Error> {
		let mut result = 0;

		if self.x509_key_data.is_null() {
			/* Allocate the hash context */
			result = unsafe {
				leancrypto::lc_x509_keypair_data_alloc(
					&mut self.x509_key_data, 0)
			};
		}
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}

		result = unsafe {
			leancrypto::lc_pkcs8_set_privkey(
				&mut self.pkcs8_sk,  self.x509_key_data)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError);
		}

		Ok(())
	}

	pub fn key_pair_generation(
		&mut self,
		key_type: lcr_x509_key_type,
	) -> Result<(), X509Error> {
		self.alloc_key_data()?;

		self.key_type = key_type;

		let lcr_x509_key_type: u32 = match key_type {
			lcr_x509_key_type::lcr_dilithium_44 =>
				leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44,
			lcr_x509_key_type::lcr_dilithium_65 =>
				leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65,
			lcr_x509_key_type::lcr_dilithium_87 =>
				leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87,
			lcr_x509_key_type::lcr_dilithium_44_ed25519 =>
				leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44_ED25519,
			lcr_x509_key_type::lcr_dilithium_65_ed25519 =>
				leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65_ED25519,
			// lcr_x509_key_type::lcr_dilithium_87_ed25519 =>
			// 	leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87_ED25519,
			// lcr_x509_key_type::lcr_dilithium_44_ed448 =>
			// 	leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44_ED448,
			// lcr_x509_key_type::lcr_dilithium_65_ed448 =>
			// 	leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65_ED448,
			lcr_x509_key_type::lcr_dilithium_87_ed448 =>
				leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87_ED448,
			lcr_x509_key_type::lcr_sphincs_shake_256s =>
				leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_256S,
			lcr_x509_key_type::lcr_sphincs_shake_256f =>
				leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_256F,
			lcr_x509_key_type::lcr_sphincs_shake_192s =>
				leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_192S,
			lcr_x509_key_type::lcr_sphincs_shake_192f =>
				leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_192F,
			lcr_x509_key_type::lcr_sphincs_shake_128s =>
				leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_128S,
			lcr_x509_key_type::lcr_sphincs_shake_128f =>
				leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_128F,
			lcr_x509_key_type::lcr_ed25519 =>
				leancrypto::lc_sig_types_LC_SIG_ED25519,
			lcr_x509_key_type::lcr_ed448 =>
				leancrypto::lc_sig_types_LC_SIG_ED448,
			_ => 0,
		};

		let result = unsafe {
			leancrypto::lc_x509_keypair_gen(&mut self.x509_cert,
							self.x509_key_data,
							lcr_x509_key_type)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError);
		}

		self.has_sk = true;
		self.has_pk = true;

		Ok(())
	}

	/// Wrapper around lc_pkcs8_encode
	pub fn pkcs8_generation(
		&mut self,
	) -> Result<&Vec<u8>, X509Error> {
		self.key_is_usable()?;

		let mut pkcs8_size: usize = 0;

		/* Get the length of the memory to allocate */
		let result = unsafe {
			leancrypto::lc_pkcs8_encode(&self.pkcs8_sk,
						    ptr::null_mut(),
						    &mut pkcs8_size)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError);
		}

		self.sk_der_key = Vec::with_capacity(pkcs8_size);
		let orig_size = pkcs8_size;

		let result = unsafe {
			leancrypto::lc_pkcs8_encode(&self.pkcs8_sk,
						    self.sk_der_key.as_mut_ptr(),
						    &mut pkcs8_size)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError);
		}

		/* Set vector to to consumed length */
		unsafe { self.sk_der_key.set_len(orig_size - pkcs8_size) }

		Ok(&self.sk_der_key)
	}

	/// Load private key formatted as PKCS8 DER blob
	pub fn pkcs8_sk_load(
		&mut self,
		sk_der_key: &[u8]
	) -> Result<(), X509Error> {
		/*
		 * Copy the DER blob into local storage as the pkcs8_sk is only
		 * set of pointers into the DER structure.
		 */
		self.sk_der_key = Vec::from(sk_der_key);

		self.alloc_key_data()?;

		let result = unsafe {
			leancrypto::lc_pkcs8_decode(&mut self.pkcs8_sk,
						    self.sk_der_key.as_ptr(),
						    self.sk_der_key.len())
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
				lcr_x509_key_type::lcr_dilithium_44,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65 =>
				lcr_x509_key_type::lcr_dilithium_65,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87 =>
				lcr_x509_key_type::lcr_dilithium_87,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44_ED25519 =>
				lcr_x509_key_type::lcr_dilithium_44_ed25519,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65_ED25519 =>
				lcr_x509_key_type::lcr_dilithium_65_ed25519,
			// leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87_ED25519 =>
			//	lcr_x509_key_type::lcr_dilithium_87_ed25519,
			// leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44_ED448 =>
			//	lcr_x509_key_type::lcr_dilithium_44_ed448,
			// leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65_ED448 =>
			//	lcr_x509_key_type::lcr_dilithium_65_ed448,
			leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87_ED448 =>
				lcr_x509_key_type::lcr_dilithium_87_ed448,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_256S =>
				lcr_x509_key_type::lcr_sphincs_shake_256s,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_256F =>
				lcr_x509_key_type::lcr_sphincs_shake_256f,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_192S =>
				lcr_x509_key_type::lcr_sphincs_shake_192s,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_192F =>
				lcr_x509_key_type::lcr_sphincs_shake_192f,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_128S =>
				lcr_x509_key_type::lcr_sphincs_shake_128s,
			leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_128F =>
				lcr_x509_key_type::lcr_sphincs_shake_128f,
			leancrypto::lc_sig_types_LC_SIG_ED25519 =>
				lcr_x509_key_type::lcr_ed25519,
			leancrypto::lc_sig_types_LC_SIG_ED448 =>
				lcr_x509_key_type::lcr_ed448,
			_ => lcr_x509_key_type::lcr_unknown,
		};

		self.has_sk = true;
		Ok(())
	}

	/// Is the key present and usable?
	pub fn key_is_usable(
		&self
	) -> Result<(), X509Error> {
		if self.has_sk == false {
			return Err(X509Error::UninitializedContext)
		}
		Ok(())
	}

	pub fn get_sk(
		&self
	) -> Result<leancrypto::lc_pkcs8_message, X509Error> {
		if !self.has_sk {
			return Err(X509Error::UninitializedContext)
		}
		Ok(self.pkcs8_sk)
	}

	/// Wrapper around lc_x509_cert_decode
	pub fn cert_load(
		&mut self,
		der_certificate: &[u8]
	) -> Result<(), X509Error> {
		/*
		 * Copy the DER blob into local storage as the pkcs8_sk is only
		 * set of pointers into the DER structure.
		 */
		self.cert_der = Vec::from(der_certificate);

		let result = unsafe {
			leancrypto::lc_x509_cert_decode(
				&mut self.x509_cert, self.cert_der.as_ptr(),
				self.cert_der.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}

		self.has_pk = true;
		self.has_certificate = true;
		Ok(())
	}

	/// Is the certificate present and usable?
	pub fn cert_is_usable(
		&self
	) -> Result<(), X509Error> {
		if self.has_certificate == false {
			return Err(X509Error::UninitializedContext)
		}
		Ok(())
	}

	pub fn get_pk(
		&self
	) -> Result<leancrypto::lc_x509_certificate, X509Error> {
		if !self.has_certificate {
			return Err(X509Error::UninitializedContext)
		}
		Ok(self.x509_cert)
	}

	fn cert_configurable(
		&self
	) -> Result<(), X509Error> {
		if self.has_certificate {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_signer
	pub fn cert_set_signer(
		&mut self,
		signer: lcr_x509_key
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_signer(
				&mut self.x509_cert, signer.x509_key_data,
				&signer.x509_cert)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_eku
	pub fn cert_set_eku(
		&mut self,
		eku: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_eku(
				&mut self.x509_cert,
				CString::new(eku).unwrap().as_ptr())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_eku_val
	pub fn cert_set_eku_val(
		&mut self,
		eku: u16
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_eku_val(
				&mut self.x509_cert, eku)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_keyusage
	pub fn cert_set_keyusage(
		&mut self,
		keyusage: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_keyusage(
				&mut self.x509_cert,
				CString::new(keyusage).unwrap().as_ptr())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_keyusage_val
	pub fn cert_set_keyusage_val(
		&mut self,
		keyusage: u16
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_keyusage_val(
				&mut self.x509_cert, keyusage)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_ca
	pub fn cert_set_ca(
		&mut self
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_ca(&mut self.x509_cert)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_check_issuer_ca
	pub fn cert_check_issuer_ca(
		&mut self
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_check_issuer_ca(
				&mut self.x509_cert)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_ca_pathlen
	pub fn cert_set_ca_pathlen(
		&mut self,
		pathlen: u32
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_ca_pathlen(
				&mut self.x509_cert, pathlen)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_san_email
	pub fn cert_set_san_email(
		&mut self,
		email: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_san_email(
				&mut self.x509_cert,
				CString::new(email).unwrap().as_ptr())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_san_dns
	pub fn cert_set_san_dns(
		&mut self,
		dns: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_san_dns(
				&mut self.x509_cert,
				CString::new(dns).unwrap().as_ptr())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_san_ip
	pub fn cert_set_san_ip(
		&mut self,
		ip: &[u8]
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_san_ip(
				&mut self.x509_cert, ip.as_ptr(), ip.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_skid
	pub fn cert_set_skid(
		&mut self,
		skid: &[u8]
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_skid(
				&mut self.x509_cert, skid.as_ptr(), skid.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_akid
	pub fn cert_set_akid(
		&mut self,
		akid: &[u8]
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_akid(
				&mut self.x509_cert, akid.as_ptr(), akid.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_valid_from
	pub fn cert_set_valid_from(
		&mut self,
		time: i64
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_valid_from(
				&mut self.x509_cert, time)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_valid_to
	pub fn cert_set_valid_to(
		&mut self,
		time: i64
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_valid_to(
				&mut self.x509_cert, time)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_subject_cn
	pub fn cert_set_subject_cn(
		&mut self,
		cn: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_subject_cn(
				&mut self.x509_cert,
				CString::new(cn).unwrap().as_ptr(), cn.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_subject_email
	pub fn cert_set_subject_email(
		&mut self,
		email: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_subject_email(
				&mut self.x509_cert,
				CString::new(email).unwrap().as_ptr(),
				email.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_subject_ou
	pub fn cert_set_subject_ou(
		&mut self,
		ou: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_subject_ou(
				&mut self.x509_cert,
				CString::new(ou).unwrap().as_ptr(), ou.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper arond lc_x509_cert_set_subject_o
	pub fn cert_set_subject_o(
		&mut self,
		o: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_subject_o(
				&mut self.x509_cert,
				CString::new(o).unwrap().as_ptr(), o.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper arstnd lc_x509_cert_set_subject_st
	pub fn cert_set_subject_st(
		&mut self,
		st: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_subject_st(
				&mut self.x509_cert,
				CString::new(st).unwrap().as_ptr(), st.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper arcnd lc_x509_cert_set_subject_c
	pub fn cert_set_subject_c(
		&mut self,
		c: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_subject_c(
				&mut self.x509_cert,
				CString::new(c).unwrap().as_ptr(), c.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_issuer_cn
	pub fn cert_set_issuer_cn(
		&mut self,
		cn: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_issuer_cn(
				&mut self.x509_cert,
				CString::new(cn).unwrap().as_ptr(), cn.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_issuer_email
	pub fn cert_set_issuer_email(
		&mut self,
		email: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_issuer_email(
				&mut self.x509_cert,
				CString::new(email).unwrap().as_ptr(),
				email.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper around lc_x509_cert_set_issuer_ou
	pub fn cert_set_issuer_ou(
		&mut self,
		ou: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_issuer_ou(
				&mut self.x509_cert,
				CString::new(ou).unwrap().as_ptr(), ou.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper arond lc_x509_cert_set_issuer_o
	pub fn cert_set_issuer_o(
		&mut self,
		o: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_issuer_o(
				&mut self.x509_cert,
				CString::new(o).unwrap().as_ptr(), o.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper arstnd lc_x509_cert_set_issuer_st
	pub fn cert_set_issuer_st(
		&mut self,
		st: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_issuer_st(
				&mut self.x509_cert,
				CString::new(st).unwrap().as_ptr(), st.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper arcnd lc_x509_cert_set_issuer_c
	pub fn cert_set_issuer_c(
		&mut self,
		c: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_issuer_c(
				&mut self.x509_cert,
				CString::new(c).unwrap().as_ptr(), c.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Wrapper arcnd lc_x509_cert_set_serial
	pub fn cert_set_serial(
		&mut self,
		serial: &str
	) -> Result<(), X509Error> {
		self.cert_configurable()?;

		let result = unsafe {
			leancrypto::lc_x509_cert_set_serial(
				&mut self.x509_cert, serial.as_ptr(),
				serial.len())
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}
		Ok(())
	}

	/// Generate certificate of previously set certificate details
	/// Wrapper around lc_x509_cert_encode
	pub fn certificate_generation(
		&mut self,
	) -> Result<&Vec<u8>, X509Error> {
		self.cert_configurable()?;
		self.key_is_usable()?;

		let mut cert_size: usize = 0;

		/* Get the length of the memory to allocate */
		let result = unsafe {
			leancrypto::lc_x509_cert_encode(&self.x509_cert,
							ptr::null_mut(),
							&mut cert_size)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError);
		}

		self.cert_der = Vec::with_capacity(cert_size);
		let orig_size = cert_size;

		let result = unsafe {
			leancrypto::lc_x509_cert_encode(
				&self.x509_cert, self.cert_der.as_mut_ptr(),
				&mut cert_size)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError);
		}

		/* Set vector to to consumed length */
		unsafe { self.cert_der.set_len(orig_size - cert_size) }

		self.has_certificate = true;

		Ok(&self.cert_der)
	}
}

/*
 * Sync and Send do not need a special consideration. Even though
 * lcr_x509_key::pkcs8_sk contains pointers, the pointers all to the buffer
 * lcr_x509_key::sk_der_key which is a private buffer. Therefore, the whole memory
 * and the pointers into it are managed and released jointly without any special
 * considerations.
 */
unsafe impl Sync for lcr_x509_key {}
unsafe impl Send for lcr_x509_key {}

impl fmt::Debug for leancrypto::lc_x509_certificate {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "lc_x509_certificate")
	}
}

impl Drop for lcr_x509_key {
	fn drop(&mut self) {
		self.sk_der_key.zeroize();
		self.has_sk = false;
		unsafe { leancrypto::lc_x509_keypair_data_zero_free(self.x509_key_data) };

		self.cert_der.zeroize();
		self.has_pk = false;
		self.has_certificate = false;
	}
}

/// Leancrypto wrapper for the Leancrypto X.509 API
pub struct lcr_x509 {
}

#[allow(dead_code)]
impl lcr_x509 {
	pub fn new() -> Self {
		lcr_x509 { }
	}

	/// Verify another certificate with self
	pub fn verify(
		&mut self,
		x509_key: &lcr_x509_key,
		signature: &[u8],
		message: &[u8]
	) -> Result<(), X509Error> {
		x509_key.cert_is_usable()?;

		let cert_res = x509_key.get_pk();
		let cert = match cert_res {
			Ok(cert_blob) => cert_blob,
			Err(error) => return Err(error),
		};

		let result = unsafe {
			leancrypto::lc_x509_signature_verify(
				signature.as_ptr(), signature.len(),
				&cert, message.as_ptr(),
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
		signer: &lcr_x509_key,
		cert: &lcr_x509_key
	) -> Result<(), X509Error> {
		signer.cert_is_usable()?;
		cert.cert_is_usable()?;

		Err(X509Error::UninitializedContext)
		//Ok(())
	}

	pub fn sign(
		&mut self,
		x509_key: &lcr_x509_key,
		message: &[u8]
	) -> Result<Vec<u8>, X509Error> {
		let pkcs8_res = x509_key.get_sk();
		let pkcs8 = match pkcs8_res {
			Ok(pkcs8_blob) => pkcs8_blob,
			Err(error) => return Err(error),
		};

		let mut siglen = 0;
		let result = unsafe {
			leancrypto::lc_pkcs8_get_signature_size_from_sk(
				&mut siglen, &pkcs8)
		};
		if result < 0 {
			return Err(X509Error::ProcessingError)
		}

		let mut signature = vec![0; siglen];
		let result = unsafe {
			leancrypto::lc_pkcs8_signature_gen(signature.as_mut_ptr(),
							   &mut siglen,
							   &pkcs8,
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
