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
use crate::error::SignatureError;

pub enum lcr_dilithium_ed448_type {
	lcr_dilithium_44,
	lcr_dilithium_65,
	lcr_dilithium_87,
}

/// Leancrypto wrapper for lc_dilithium_ed448
pub struct lcr_dilithium_ed448 {
	// Context
	//dilithium_ed448_ctx: *mut leancrypto::lc_dilithium_ed448_ctx,

	/// Dilithium public key
	pk: leancrypto::lc_dilithium_ed448_pk,

	/// Dilithium secret key
	sk: leancrypto::lc_dilithium_ed448_sk,

	/// Dilithium signature
	sig: leancrypto::lc_dilithium_ed448_sig,

	pk_set: bool,
	sk_set: bool,
	sig_set: bool,
}

#[allow(dead_code)]
impl lcr_dilithium_ed448 {
	pub fn new() -> Self {
		lcr_dilithium_ed448 {
			//dilithium_ed448_ctx: ptr::null_mut(),
			pk: unsafe { std::mem::zeroed() },
			sk: unsafe { std::mem::zeroed() },
			sig: unsafe { std::mem::zeroed() },
			pk_set: false,
			sk_set: false,
			sig_set: false,
		}
	}

	/// Load secret key for using with leancrypto
	///
	/// [sk_dilithium_buf] buffer with Dilithium raw secret key
	/// [sk_ed448_buf] buffer with ED448 raw secret key
	pub fn sk_load(&mut self, sk_dilithium_buf: &[u8], sk_ed448_buf: &[u8]) ->
		Result<(), SignatureError> {
		// No check for self.sk_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_dilithium_ed448_sk_load(
				&mut self.sk, sk_dilithium_buf.as_ptr(),
				sk_dilithium_buf.len(), sk_ed448_buf.as_ptr(),
				sk_ed448_buf.len())
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		self.sk_set = true;

		Ok(())
	}

	/// Load public key for using with leancrypto
	///
	/// [pk_dilithium_buf] buffer with Dilithium raw public key
	/// [pk_ed448_buf] buffer with ED448 raw public key
	pub fn pk_load(&mut self, pk_dilithium_buf: &[u8], pk_ed448_buf: &[u8]) ->
		Result<(), SignatureError> {
		// No check for self.pk_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_dilithium_ed448_pk_load(
				&mut self.pk, pk_dilithium_buf.as_ptr(),
				pk_dilithium_buf.len(), pk_ed448_buf.as_ptr(),
				pk_ed448_buf.len())
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		self.pk_set = true;

		Ok(())
	}

	/// Load signature using with leancrypto
	///
	/// [sig_dilithium_buf] buffer with Dilithium raw secret key
	/// [sig_ed448_buf] buffer with ED448 raw secret key
	pub fn sig_load(&mut self, sig_dilithium_buf: &[u8], sig_ed448_buf: &[u8]) ->
		Result<(), SignatureError> {
		// No check for self.sig_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_dilithium_ed448_sig_load(
				&mut self.sig, sig_dilithium_buf.as_ptr(),
				sig_dilithium_buf.len(),
				sig_ed448_buf.as_ptr(),
				sig_ed448_buf.len())
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		self.sig_set = true;

		Ok(())
	}

	fn lcr_dilithium_ed448_type_mapping(dilithium_ed448_type: lcr_dilithium_ed448_type) ->
		u32 {
		match dilithium_ed448_type {
			lcr_dilithium_ed448_type::lcr_dilithium_44 =>
				leancrypto::lc_dilithium_type_LC_DILITHIUM_44,
			lcr_dilithium_ed448_type::lcr_dilithium_65 =>
				leancrypto::lc_dilithium_type_LC_DILITHIUM_65,
			lcr_dilithium_ed448_type::lcr_dilithium_87 =>
				leancrypto::lc_dilithium_type_LC_DILITHIUM_87,
		}
	}

	/// Generate hybrid Dilithium/ML-DSA Ed448 key pair
	///
	/// [dilithium_ed448_type] key type
	pub fn keypair(&mut self,
		       dilithium_ed448_type: lcr_dilithium_ed448_type) ->
		Result<(), SignatureError> {
		let result = unsafe {
			leancrypto::lc_dilithium_ed448_keypair(
				&mut self.pk, &mut self.sk,
				leancrypto::lc_seeded_rng,
				Self::lcr_dilithium_ed448_type_mapping(dilithium_ed448_type))
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		self.sk_set = true;
		self.pk_set = true;

		Ok(())
	}

	/// Sign message with pure signature operation
	///
	/// [msg] holds the message to be signed
	pub fn sign(&mut self, msg: &[u8]) -> Result<(), SignatureError> {
		if self.sk_set == false {
			return Err(SignatureError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_dilithium_ed448_sign(
				&mut self.sig, msg.as_ptr(), msg.len(),
				&self.sk, leancrypto::lc_seeded_rng)
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		self.sig_set = true;

		Ok(())
	}

	/// Deterministically sign message with pure signature operation
	///
	/// [msg] holds the message to be signed
	pub fn sign_deterministic(&mut self, msg: &[u8]) ->
		Result<(), SignatureError> {
		if self.sk_set == false {
			return Err(SignatureError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_dilithium_ed448_sign(
				&mut self.sig, msg.as_ptr(), msg.len(),
				&self.sk, ptr::null_mut())
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		self.sig_set = true;

		Ok(())
	}

	/// Verify message with pure signature operation
	///
	/// [msg] holds the message to be verified
	pub fn verify(&mut self, msg: &[u8]) -> Result<(), SignatureError> {
		if self.pk_set == false || self.sig_set == false {
			return Err(SignatureError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_dilithium_ed448_verify(
				&mut self.sig, msg.as_ptr(), msg.len(),
				&self.pk)
		};
		if result == -1*(leancrypto::EBADMSG as i32) {
			return Err(SignatureError::VerificationError);
		}
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		Ok(())
	}

	/// Method for safe immutable access to signature buffer
	pub fn sig(&mut self) ->
		(&[u8], &[u8], Result<(), SignatureError>) {
		if self.sig_set == false {
			return (&[], &[],
				Err(SignatureError::UninitializedContext));
		}

		let mut dilithium_ptr: *mut u8 = ptr::null_mut();
		let mut dilithium_len: usize = 0;
		let mut ed448_ptr: *mut u8 = ptr::null_mut();
		let mut ed448_len: usize = 0;

		let result = unsafe {
			leancrypto::lc_dilithium_ed448_sig_ptr(
				&mut dilithium_ptr, &mut dilithium_len,
				&mut ed448_ptr, &mut ed448_len,
				&mut self.sig)
		};
		if result < 0 {
			return (&[], &[], Err(SignatureError::ProcessingError));
		}

		let slice_dilithium = unsafe {
			std::slice::from_raw_parts(dilithium_ptr, dilithium_len)
		};
		let slice_ed448 = unsafe {
			std::slice::from_raw_parts(ed448_ptr, ed448_len)
		};

		(&slice_dilithium, &slice_ed448, Ok(()))
	}

	/// Method for safe immutable access to secret key buffer
	pub fn sk(&mut self) ->
		(&[u8], &[u8], Result<(), SignatureError>) {
		if self.sk_set == false {
			return (&[], &[],
				Err(SignatureError::UninitializedContext));
		}

		let mut dilithium_ptr: *mut u8 = ptr::null_mut();
		let mut dilithium_len: usize = 0;
		let mut ed448_ptr: *mut u8 = ptr::null_mut();
		let mut ed448_len: usize = 0;

		let result = unsafe {
			leancrypto::lc_dilithium_ed448_sk_ptr(
				&mut dilithium_ptr, &mut dilithium_len,
				&mut ed448_ptr, &mut ed448_len,
				&mut self.sk)
		};
		if result < 0 {
			return (&[], &[], Err(SignatureError::ProcessingError));
		}

		let slice_dilithium = unsafe {
			std::slice::from_raw_parts(dilithium_ptr, dilithium_len)
		};
		let slice_ed448 = unsafe {
			std::slice::from_raw_parts(ed448_ptr, ed448_len)
		};

		(&slice_dilithium, &slice_ed448, Ok(()))
	}

	/// Method for safe immutable access to public key buffer
	pub fn pk(&mut self) ->
		(&[u8], &[u8], Result<(), SignatureError>) {
		if self.pk_set == false {
			return (&[], &[],
				Err(SignatureError::UninitializedContext));
		}

		let mut dilithium_ptr: *mut u8 = ptr::null_mut();
		let mut dilithium_len: usize = 0;
		let mut ed448_ptr: *mut u8 = ptr::null_mut();
		let mut ed448_len: usize = 0;

		let result = unsafe {
			leancrypto::lc_dilithium_ed448_pk_ptr(
				&mut dilithium_ptr, &mut dilithium_len,
				&mut ed448_ptr, &mut ed448_len,
				&mut self.pk)
		};
		if result < 0 {
			return (&[], &[], Err(SignatureError::ProcessingError));
		}

		let slice_dilithium = unsafe {
			std::slice::from_raw_parts(dilithium_ptr, dilithium_len)
		};
		let slice_ed448 = unsafe {
			std::slice::from_raw_parts(ed448_ptr, ed448_len)
		};

		(&slice_dilithium, &slice_ed448, Ok(()))
	}
}

/// This ensures the sensitive buffers are always zeroized
/// regardless of when it goes out of scope
impl Drop for lcr_dilithium_ed448 {
	fn drop(&mut self) {
		let sk: leancrypto::lc_dilithium_ed448_sk = unsafe {
			std::mem::zeroed()
		};

		unsafe { std::ptr::write_volatile(&mut self.sk, sk) };
		atomic::compiler_fence(atomic::Ordering::SeqCst);
	}
}
