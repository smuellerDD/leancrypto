/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

	pk_set: bool,
	sk_set: bool,
	ct_set: bool,
}

#[allow(dead_code)]
impl lcr_kyber_x448 {
	pub fn new() -> Self {
		lcr_kyber_x448 {
			//kyber_ctx: ptr::null_mut(),
			pk: unsafe { std::mem::zeroed() },
			sk: unsafe { std::mem::zeroed() },
			ct: unsafe { std::mem::zeroed() },
			pk_set: false,
			sk_set: false,
			ct_set: false,
		}
	}

	/// Load secret key for using with leancrypto
	///
	/// [sk_kyber_buf] buffer with Kyber raw secret key
	/// [sk_x448_buf] buffer with X448 raw secret key
	pub fn sk_load(&mut self, sk_kyber_buf: &[u8], sk_x448_buf: &[u8]) ->
		Result<(), KemError> {
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
	/// [pk_kyber_buf] buffer with Kyber public key
	/// [pk_x448_buf] buffer with X448 public key
	pub fn pk_load(&mut self, pk_kyber_buf: &[u8], pk_x448_buf: &[u8]) ->
		Result<(), KemError> {
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

	/// Load ctnature using with leancrypto
	///
	/// [ct_kyber_buf] buffer with raw Kyber cipher text
	/// [x448_rem_pub_key_buf] buffer with raw X448 remote public key
	pub fn ct_load(&mut self, ct_kyber_buf: &[u8],
		       x448_rem_pub_key_buf: &[u8]) ->
		Result<(), KemError> {
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

	/// Generate Kyber / ML-KEM key pair
	///
	/// [kyber_type] key type
	pub fn keypair(&mut self, kyber_type: lcr_kyber_x448_type) ->
		Result<(), KemError> {
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
	pub fn decapsulate(&mut self, ss: &mut [u8]) -> Result<(), KemError> {
		if self.sk_set == false || self.ct_set == false {
			return Err(KemError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_kyber_x448_dec_kdf(
				ss.as_mut_ptr(), ss.len(), &self.ct, &self.sk)
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		Ok(())
	}

	/// Deterministically sign message with pure signature operation
	pub fn encapsulate(&mut self, ss: &mut [u8]) -> Result<(), KemError> {
		if self.pk_set == false {
			return Err(KemError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_kyber_x448_enc_kdf(
				&mut self.ct, ss.as_mut_ptr(), ss.len(),
				&self.pk)
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.ct_set = true;

		Ok(())
	}

	/// Method for safe immutable access to Kyber ciphertext buffer
	pub fn ct(&mut self) -> (&[u8], &[u8], Result<(), KemError>) {
		if self.ct_set == false {
			return (&[], &[], Err(KemError::UninitializedContext));
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
			return (&[], &[], Err(KemError::ProcessingError));
		}

		let slice_kyber = unsafe {
			std::slice::from_raw_parts(kyber_ptr, kyber_len)
		};
		let slice_x448 = unsafe {
			std::slice::from_raw_parts(x448_ptr, x448_len)
		};

		(&slice_kyber, &slice_x448, Ok(()))
	}

	/// Method for safe immutable access to secret key buffer
	pub fn sk(&mut self) -> (&[u8], &[u8], Result<(), KemError>) {
		if self.sk_set == false {
			return (&[], &[], Err(KemError::UninitializedContext));
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
			return (&[], &[], Err(KemError::ProcessingError));
		}

		let slice_kyber = unsafe {
			std::slice::from_raw_parts(kyber_ptr, kyber_len)
		};
		let slice_x448 = unsafe {
			std::slice::from_raw_parts(x448_ptr, x448_len)
		};

		(&slice_kyber, &slice_x448, Ok(()))
	}

	/// Method for safe immutable access to public key buffer
	pub fn pk(&mut self) -> (&[u8], &[u8], Result<(), KemError>) {
		if self.pk_set == false {
			return (&[], &[], Err(KemError::UninitializedContext));
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
			return (&[], &[], Err(KemError::ProcessingError));
		}

		let slice_kyber = unsafe {
			std::slice::from_raw_parts(kyber_ptr, kyber_len)
		};
		let slice_x448 = unsafe {
			std::slice::from_raw_parts(x448_ptr, x448_len)
		};

		(&slice_kyber, &slice_x448, Ok(()))
	}
}

/// This ensures the sensitive buffers are always zeroized
/// regardless of when it goes out of scope
impl Drop for lcr_kyber_x448 {
	fn drop(&mut self) {
		let sk: leancrypto::lc_kyber_x448_sk = unsafe {
			std::mem::zeroed()
		};

		unsafe { std::ptr::write_volatile(&mut self.sk, sk) };
		atomic::compiler_fence(atomic::Ordering::SeqCst);

		let ct: leancrypto::lc_kyber_x448_ct = unsafe {
			std::mem::zeroed()
		};

		unsafe { std::ptr::write_volatile(&mut self.ct, ct) };
		atomic::compiler_fence(atomic::Ordering::SeqCst);
	}
}
