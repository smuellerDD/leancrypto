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

pub enum lcr_hqc_type {
	lcr_hqc_128,
	lcr_hqc_192,
	lcr_hqc_256,
}

/// Leancrypto wrapper for lc_hqc
pub struct lcr_hqc {
	// Context
	//hqc_ctx: *mut leancrypto::lc_hqc_ctx,

	/// HQC shared secret
	ss: leancrypto::lc_hqc_ss,

	/// HQC public key
	pk: leancrypto::lc_hqc_pk,

	/// HQC secret key
	sk: leancrypto::lc_hqc_sk,

	/// HQC cipher text
	ct: leancrypto::lc_hqc_ct,

	pk_set: bool,
	sk_set: bool,
	ct_set: bool,
	ss_set: bool,
}

#[allow(dead_code)]
impl lcr_hqc {
	pub fn new() -> Self {
		lcr_hqc {
			//hqc_ctx: ptr::null_mut(),
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

	/// Load secret key for using with leancrypto
	///
	/// [sk_buf] buffer with raw secret key
	pub fn sk_load(&mut self, sk_buf: &[u8]) -> Result<(), KemError> {
		// No check for self.sk_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_hqc_sk_load(&mut self.sk,
						   sk_buf.as_ptr(),
						   sk_buf.len())
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.sk_set = true;

		Ok(())
	}

	/// Load public key for using with leancrypto
	///
	/// [pk_buf] buffer with raw public key
	pub fn pk_load(&mut self, pk_buf: &[u8]) -> Result<(), KemError> {
		// No check for self.pk_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_hqc_pk_load(&mut self.pk,
						   pk_buf.as_ptr(),
						   pk_buf.len())
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.pk_set = true;

		Ok(())
	}

	/// Load ctnature using with leancrypto
	///
	/// [ct_buf] buffer with raw HQC cipher text
	pub fn ct_load(&mut self, ct_buf: &[u8]) ->
		Result<(), KemError> {
		// No check for self.ct_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_hqc_ct_load(&mut self.ct,
						   ct_buf.as_ptr(),
						   ct_buf.len())
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.ct_set = true;

		Ok(())
	}

	/// Load ctnature using with leancrypto
	///
	/// [ss_buf] buffer with raw shared secret
	pub fn ss_load(&mut self, ss_buf: &[u8]) ->
		Result<(), KemError> {
		// No check for self.ss_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_hqc_ss_load(&mut self.ss,
						     ss_buf.as_ptr(),
						     ss_buf.len())
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.ss_set = true;

		Ok(())
	}

	fn lcr_hqc_type_mapping(hqc_type: lcr_hqc_type) ->
		u32 {
		match hqc_type {
			lcr_hqc_type::lcr_hqc_128 =>
				leancrypto::lc_hqc_type_LC_HQC_128,
			lcr_hqc_type::lcr_hqc_192 =>
				leancrypto::lc_hqc_type_LC_HQC_192,
			lcr_hqc_type::lcr_hqc_256 =>
				leancrypto::lc_hqc_type_LC_HQC_256,
		}
	}

	/// Generate HQC / ML-KEM key pair
	///
	/// [hqc_type] key type
	pub fn keypair(&mut self, hqc_type: lcr_hqc_type) ->
		Result<(), KemError> {
		let result = unsafe {
			leancrypto::lc_hqc_keypair(
				&mut self.pk, &mut self.sk,
				leancrypto::lc_seeded_rng,
				Self::lcr_hqc_type_mapping(hqc_type))
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.sk_set = true;
		self.pk_set = true;

		Ok(())
	}

	/// Decapsulate message
	pub fn decapsulate(&mut self) -> Result<(), KemError> {
		if self.sk_set == false || self.ct_set == false {
			return Err(KemError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_hqc_dec(
				&mut self.ss, &self.ct, &self.sk)
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.ss_set = true;

		Ok(())
	}

	/// Deterministically sign message with pure signature operation
	pub fn encapsulate(&mut self) -> Result<(), KemError> {
		if self.pk_set == false {
			return Err(KemError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_hqc_enc(
				&mut self.ct, &mut self.ss, &self.pk)
		};
		if result < 0 {
			return Err(KemError::ProcessingError);
		}

		self.ct_set = true;
		self.ss_set = true;

		Ok(())
	}

	/// Method for safe immutable access to HQC ciphertext buffer
	pub fn ct(&mut self) -> (&[u8], Result<(), KemError>) {
		if self.ct_set == false {
			return (&[], Err(KemError::UninitializedContext));
		}

		let mut ptr: *mut u8 = ptr::null_mut();
		let mut len: usize = 0;

		let result = unsafe {
			leancrypto::lc_hqc_ct_ptr(&mut ptr, &mut len,
						  &mut self.ct)
		};
		if result < 0 {
			return (&[], Err(KemError::ProcessingError));
		}

		let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

		(&slice, Ok(()))
	}

	/// Method for safe immutable access to secret key buffer
	pub fn sk(&mut self) -> (&[u8], Result<(), KemError>) {
		if self.sk_set == false {
			return (&[], Err(KemError::UninitializedContext));
		}

		let mut ptr: *mut u8 = ptr::null_mut();
		let mut len: usize = 0;

		let result = unsafe {
			leancrypto::lc_hqc_sk_ptr(&mut ptr, &mut len,
						  &mut self.sk)
		};
		if result < 0 {
			return (&[], Err(KemError::ProcessingError));
		}

		let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

		(&slice, Ok(()))
	}

	/// Method for safe immutable access to public key buffer
	pub fn pk(&mut self) -> (&[u8], Result<(), KemError>) {
		if self.pk_set == false {
			return (&[], Err(KemError::UninitializedContext));
		}

		let mut ptr: *mut u8 = ptr::null_mut();
		let mut len: usize = 0;

		let result = unsafe {
			leancrypto::lc_hqc_pk_ptr(&mut ptr, &mut len,
						  &mut self.pk)
		};
		if result < 0 {
			return (&[], Err(KemError::ProcessingError));
		}

		let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

		(&slice, Ok(()))
	}

	/// Method for safe immutable access to shared secret buffer
	pub fn ss(&mut self) -> (&[u8], Result<(), KemError>) {
		if self.ss_set == false {
			return (&[], Err(KemError::UninitializedContext));
		}

		let mut ptr: *mut u8 = ptr::null_mut();
		let mut len: usize = 0;

		let result = unsafe {
			leancrypto::lc_hqc_ss_ptr(&mut ptr, &mut len,
						  &mut self.ss)
		};
		if result < 0 {
			return (&[], Err(KemError::ProcessingError));
		}

		let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

		(&slice, Ok(()))
	}
}

/// This ensures the sensitive buffers are always zeroized
/// regardless of when it goes out of scope
impl Drop for lcr_hqc {
	fn drop(&mut self) {
		let sk: leancrypto::lc_hqc_sk = unsafe {
			std::mem::zeroed()
		};

		unsafe { std::ptr::write_volatile(&mut self.sk, sk) };
		atomic::compiler_fence(atomic::Ordering::SeqCst);

		let ct: leancrypto::lc_hqc_ct = unsafe {
			std::mem::zeroed()
		};

		unsafe { std::ptr::write_volatile(&mut self.ct, ct) };
		atomic::compiler_fence(atomic::Ordering::SeqCst);

		let ss: leancrypto::lc_hqc_ss = unsafe {
			std::mem::zeroed()
		};

		unsafe { std::ptr::write_volatile(&mut self.ss, ss) };
		atomic::compiler_fence(atomic::Ordering::SeqCst);
	}
}
