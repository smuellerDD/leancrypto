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
use crate::error::KemError;

pub enum lcr_kyber_x448_type {
	lcr_kyber_512,
	lcr_kyber_768,
	lcr_kyber_1024,
}

/// Leancrypto wrapper for lc_kyber
pub struct lcr_kyber_x448 {
	// Context
	//kyber_ctx: *mut leancrypto::lc_kyber_ctx,

	/// Kyber public key
	pk: leancrypto::lc_kyber_x448_pk,

	/// Kyber secret key
	sk: leancrypto::lc_kyber_x448_sk,

	/// Kyber cipher text
	ct: leancrypto::lc_kyber_x448_ct,

	/// Kyber shared secret
	ss: leancrypto::lc_kyber_x448_ss,

	pk_set: bool,
	sk_set: bool,
	ct_set: bool,
	ss_set: bool,
}

#[allow(dead_code)]
impl lcr_kyber_x448 {
	pub fn new() -> Self {
		lcr_kyber_x448 {
			//kyber_ctx: ptr::null_mut(),
			pk: unsafe { std::mem::zeroed() },
			sk: unsafe { std::mem::zeroed() },
			ct: unsafe { std::mem::zeroed() },
			ss: unsafe { std::mem::zeroed() },
			pk_set: false,
			sk_set: false,
			ct_set: false,
			ss_set: false,
		}
	}

	/// # Arguments
	///
	/// * `sk_kyber_buf` buffer with ML-KEM raw secret key
	/// * `sk_x448_buf` buffer with X448 raw secret key
	///
	/// # Returns
	///
	/// * Returns Ok() on success or KemError on error
	pub fn sk_load(
		&mut self,
		sk_kyber_buf: &[u8],
		sk_x448_buf: &[u8]
	) -> Result<(), KemError> {
		// No check for self.sk_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_kyber_x448_sk_load(
				&mut self.sk,
				sk_kyber_buf.as_ptr(), sk_kyber_buf.len(),
				sk_x448_buf.as_ptr(), sk_x448_buf.len())
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.sk_set = true;

		Ok(())
	}

	/// Load public key for using with leancrypto
	///
	/// # Arguments
	///
	/// * `pk_kyber_buf` buffer with ML-KEM raw public key
	/// * `pk_x448_buf` buffer with X448 raw public key
	///
	/// # Returns
	///
	/// * Returns Ok() on success or KemError on error
	pub fn pk_load(
		&mut self,
		pk_kyber_buf: &[u8],
		pk_x448_buf: &[u8]
	) -> Result<(), KemError> {
		// No check for self.pk_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_kyber_x448_pk_load(
				&mut self.pk,
				pk_kyber_buf.as_ptr(), pk_kyber_buf.len(),
				pk_x448_buf.as_ptr(), pk_x448_buf.len())
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.pk_set = true;

		Ok(())
	}

	/// Load hybrid ML-KEM ciphertext using with leancrypto
	///
	/// # Arguments
	///
	/// * `ct_kyber_buf` buffer with ML-KEM ciphertext
	/// * `x448_rem_pub_key_buf` buffer with raw X448 remote public key
	///
	/// # Returns
	///
	/// * Returns Ok() on success or KemError on error
	pub fn ct_load(
		&mut self,
		ct_kyber_buf: &[u8],
		x448_rem_pub_key_buf: &[u8]
	) -> Result<(), KemError> {
		// No check for self.ct_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_kyber_x448_ct_load(
				&mut self.ct,
				ct_kyber_buf.as_ptr(), ct_kyber_buf.len(),
				x448_rem_pub_key_buf.as_ptr(),
				x448_rem_pub_key_buf.len())
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.ct_set = true;

		Ok(())
	}

	/// Mapping of lcr_kyber_x448_type to leancrypto hybrid  ML-KEM
	/// implementation type
	///
	/// # Arguments
	///
	/// * `kyber_x448_type` ML-KEM type to convert
	///
	/// # Returns
	///
	/// * Returns leancrypto ML-KEM implementation type
	fn lcr_kyber_type_mapping(kyber_type: lcr_kyber_x448_type) ->
		u32 {
		match kyber_type {
			lcr_kyber_x448_type::lcr_kyber_512 =>
				leancrypto::lc_kyber_type_LC_KYBER_512,
			lcr_kyber_x448_type::lcr_kyber_768 =>
				leancrypto::lc_kyber_type_LC_KYBER_768,
			lcr_kyber_x448_type::lcr_kyber_1024 =>
				leancrypto::lc_kyber_type_LC_KYBER_1024,
		}
	}

	/// Generate hybrid ML-KEM key pair
	///
	/// # Arguments
	///
	/// * `kyber_x448_type` hybrid ML-KEM type to generate key pair for
	///
	/// # Returns
	///
	/// * Returns Ok() on success or KemError on error
	pub fn keypair(
		&mut self,
		kyber_type: lcr_kyber_x448_type
	) -> Result<(), KemError> {
		let result = unsafe {
			leancrypto::lc_kyber_x448_keypair(
				&mut self.pk, &mut self.sk,
				leancrypto::lc_seeded_rng,
				Self::lcr_kyber_type_mapping(kyber_type))
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.sk_set = true;
		self.pk_set = true;

		Ok(())
	}

	/// Decapsulate message
	///
	/// The ciphertext and the secret key must be already loaded. Upon
	/// success, the shared secret is present and can be retrieved.
	///
	/// # Returns
	///
	/// * Returns Ok() on success or KemError on error
	pub fn decapsulate(
		&mut self
	) -> Result<(), KemError> {
		if self.sk_set == false || self.ct_set == false {
			return Err(KemError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_kyber_x448_dec(
				&mut self.ss, &self.ct, &self.sk)
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.ss_set = true;

		Ok(())
	}

	/// Encapsulate message
	///
	/// The publick key must be already loaded. Upon success, the shared
	/// secret and the ciphertext are present and can be retrieved.
	///
	/// # Returns
	///
	/// * Returns Ok() on success or KemError on error
	pub fn encapsulate(
		&mut self
	) -> Result<(), KemError> {
		if self.pk_set == false {
			return Err(KemError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_kyber_x448_enc(
				&mut self.ct, &mut self.ss, &self.pk)
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.ct_set = true;
		self.ss_set = true;

		Ok(())
	}

	/// Method for safe immutable access to hybrid ML-KEM ciphertext buffer
	///
	/// # Returns
	///
	/// * Returns Ok() with the ciphertext on success or KemError on error
	pub fn get_ct(
		&mut self
	) -> Result<(&[u8], &[u8]), KemError> {
		if self.ct_set == false {
			return Err(KemError::UninitializedContext);
		}

		let mut kyber_ptr: *mut u8 = ptr::null_mut();
		let mut kyber_len: usize = 0;
		let mut x448_ptr: *mut u8 = ptr::null_mut();
		let mut x448_len: usize = 0;

		let result = unsafe {
			leancrypto::lc_kyber_x448_ct_ptr(
				&mut kyber_ptr, &mut kyber_len,
				&mut x448_ptr, &mut x448_len,
				&mut self.ct)
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		let slice_kyber = unsafe {
			std::slice::from_raw_parts(kyber_ptr, kyber_len)
		};
		let slice_x448 = unsafe {
			std::slice::from_raw_parts(x448_ptr, x448_len)
		};

		Ok((&slice_kyber, &slice_x448))
	}

	/// Method for safe immutable access to hybrid ML-KEM secret key
	///
	/// # Returns
	///
	/// * Returns Ok() with the secret key on success or KemError on error
	pub fn get_sk(
		&mut self
	) -> Result<(&[u8], &[u8]), KemError> {
		if self.sk_set == false {
			return Err(KemError::UninitializedContext);
		}

		let mut kyber_ptr: *mut u8 = ptr::null_mut();
		let mut kyber_len: usize = 0;
		let mut x448_ptr: *mut u8 = ptr::null_mut();
		let mut x448_len: usize = 0;

		let result = unsafe {
			leancrypto::lc_kyber_x448_sk_ptr(
				&mut kyber_ptr, &mut kyber_len,
				&mut x448_ptr, &mut x448_len,
				&mut self.sk)
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		let slice_kyber = unsafe {
			std::slice::from_raw_parts(kyber_ptr, kyber_len)
		};
		let slice_x448 = unsafe {
			std::slice::from_raw_parts(x448_ptr, x448_len)
		};

		Ok((&slice_kyber, &slice_x448))
	}

	/// Method for safe immutable access to hybrid ML-KEM shared secret
	///
	/// # Returns
	///
	/// * Returns Ok() with the shared secret on success or KemError on error
	pub fn get_pk(
		&mut self
	) -> Result<(&[u8], &[u8]), KemError> {
		if self.pk_set == false {
			return Err(KemError::UninitializedContext);
		}

		let mut kyber_ptr: *mut u8 = ptr::null_mut();
		let mut kyber_len: usize = 0;
		let mut x448_ptr: *mut u8 = ptr::null_mut();
		let mut x448_len: usize = 0;

		let result = unsafe {
			leancrypto::lc_kyber_x448_pk_ptr(
				&mut kyber_ptr, &mut kyber_len,
				&mut x448_ptr, &mut x448_len,
				&mut self.pk)
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		let slice_kyber = unsafe {
			std::slice::from_raw_parts(kyber_ptr, kyber_len)
		};
		let slice_x448 = unsafe {
			std::slice::from_raw_parts(x448_ptr, x448_len)
		};

		Ok((&slice_kyber, &slice_x448))
	}

	/// Method for safe immutable access to hybrid ML-KEM shared secret
	/// buffer
	///
	/// # Returns
	///
	/// * Returns Ok() with the ciphertext on success or KemError on error
	pub fn get_ss(
		&mut self
	) -> Result<(&[u8], &[u8]), KemError> {
		if self.ss_set == false {
			return Err(KemError::UninitializedContext);
		}

		let mut kyber_ptr: *mut u8 = ptr::null_mut();
		let mut kyber_len: usize = 0;
		let mut x448_ptr: *mut u8 = ptr::null_mut();
		let mut x448_len: usize = 0;

		let result = unsafe {
			leancrypto::lc_kyber_x448_ss_ptr(
				&mut kyber_ptr, &mut kyber_len,
				&mut x448_ptr, &mut x448_len,
				&mut self.ss)
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		let slice_kyber = unsafe {
			std::slice::from_raw_parts(kyber_ptr, kyber_len)
		};
		let slice_x448 = unsafe {
			std::slice::from_raw_parts(x448_ptr, x448_len)
		};

		Ok((&slice_kyber, &slice_x448))
	}
}

/// This ensures the sensitive buffers are always zeroized
/// regardless of when it goes out of scope
impl Drop for lcr_kyber_x448 {
	fn drop(&mut self) {
		if self.sk_set {
			let sk: leancrypto::lc_kyber_x448_sk = unsafe {
				std::mem::zeroed()
			};

			unsafe { std::ptr::write_volatile(&mut self.sk, sk) };
			atomic::compiler_fence(atomic::Ordering::SeqCst);
		}

		if self.ct_set {
			let ct: leancrypto::lc_kyber_x448_ct = unsafe {
				std::mem::zeroed()
			};

			unsafe { std::ptr::write_volatile(&mut self.ct, ct) };
			atomic::compiler_fence(atomic::Ordering::SeqCst);
		}

		if self.ss_set {
			let ss: leancrypto::lc_kyber_x448_ss = unsafe {
				std::mem::zeroed()
			};

			unsafe { std::ptr::write_volatile(&mut self.ss, ss) };
			atomic::compiler_fence(atomic::Ordering::SeqCst);
		}
	}
}
