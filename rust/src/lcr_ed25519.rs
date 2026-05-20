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
use crate::error::SignatureError;

/// Leancrypto wrapper for lc_ed25519
pub struct lcr_ed25519 {
	// Context
	//ed25519_ctx: *mut leancrypto::lc_ed25519_ctx,

	/// ED25519 public key
	pk: leancrypto::lc_ed25519_pk,

	/// ED25519 secret key
	sk: leancrypto::lc_ed25519_sk,

	/// ED25519 signature
	sig: leancrypto::lc_ed25519_sig,

	pk_set: bool,
	sk_set: bool,
	sig_set: bool,
}

#[allow(dead_code)]
impl lcr_ed25519 {
	pub fn new() -> Self {
		lcr_ed25519 {
			//ed25519_ctx: ptr::null_mut(),
			pk: unsafe { std::mem::zeroed() },
			sk: unsafe { std::mem::zeroed() },
			sig: unsafe { std::mem::zeroed() },
			pk_set: false,
			sk_set: false,
			sig_set: false,
		}
	}

	/// Enable the ED25519 support in leancrypto (by default, it is disabled)
	///
	/// # Returns
	///
	/// * Returns Ok() on success or SignatureError on error
	pub fn enable(
		&self
	) -> Result<(), SignatureError> {
		let result = unsafe {
			leancrypto::lc_init(leancrypto::LC_INIT_NON_PQC_ENABLED)
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}
		Ok(())
	}

	/// Load secret key for using with leancrypto
	///
	/// # Arguments
	///
	/// * `sk_buf` buffer with raw secret key
	///
	/// # Returns
	///
	/// * Returns Ok() on success or SignatureError on error
	pub fn sk_load(
		&mut self,
		sk_buf: &[u8]
	) -> Result<(), SignatureError> {
		// No check for self.sk_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_ed25519_sk_load(&mut self.sk,
						       sk_buf.as_ptr(),
						       sk_buf.len())
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		self.sk_set = true;

		Ok(())
	}

	/// Load public key for using with leancrypto
	///
	/// # Arguments
	///
	/// * `pk_buf` buffer with raw public key
	///
	/// # Returns
	///
	/// * Returns Ok() on success or SignatureError on error
	pub fn pk_load(
		&mut self,
		pk_buf: &[u8]
	) -> Result<(), SignatureError> {
		// No check for self.pk_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_ed25519_pk_load(&mut self.pk,
						       pk_buf.as_ptr(),
						       pk_buf.len())
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		self.pk_set = true;

		Ok(())
	}

	/// Load signature using with leancrypto
	///
	/// # Arguments
	///
	/// * `sig_buf` buffer with raw public key
	///
	/// # Returns
	///
	/// * Returns Ok() on success or SignatureError on error
	pub fn sig_load(
		&mut self,
		sig_buf: &[u8]
	) -> Result<(), SignatureError> {
		// No check for self.sig_set == false as we allow overwriting
		// of existing key.

		let result = unsafe {
			leancrypto::lc_ed25519_sig_load(&mut self.sig,
							sig_buf.as_ptr(),
							sig_buf.len())
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		self.sig_set = true;

		Ok(())
	}

	/// Generate ED25519 key pair
	///
	/// # Arguments
	///
	/// * `dilithium_type` ED25519 type to generate key pair for
	///
	/// # Returns
	///
	/// * Returns Ok() on success or SignatureError on error
	pub fn keypair(
		&mut self
	) -> Result<(), SignatureError> {
		let result = unsafe {
			leancrypto::lc_ed25519_keypair(
				&mut self.pk, &mut self.sk,
				leancrypto::lc_seeded_rng)
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		self.sk_set = true;
		self.pk_set = true;

		Ok(())
	}

	/// Sign message
	///
	/// The the secret key must be already loaded. Upon success, the
	/// signature is present and can be retrieved.
	///
	/// # Arguments
	///
	/// * `msg` message to be signed
	///
	/// # Returns
	///
	/// * Returns Ok() on success or SignatureError on error
	pub fn sign(
		&mut self,
		msg: &[u8]
	) -> Result<(), SignatureError> {
		if self.sk_set == false {
			return Err(SignatureError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_ed25519_sign(
				&mut self.sig, msg.as_ptr(), msg.len(),
				&self.sk, leancrypto::lc_seeded_rng)
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		self.sig_set = true;

		Ok(())
	}

	/// Verify message with pure signature operation
	///
	/// The the publich key must be already loaded.
	///
	/// # Arguments
	///
	/// * `msg` message to be verified
	///
	/// # Returns
	///
	/// * Returns Ok() on success or SignatureError on error
	pub fn verify(
		&mut self,
		msg: &[u8]
	) -> Result<(), SignatureError> {
		if self.pk_set == false || self.sig_set == false {
			return Err(SignatureError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_ed25519_verify(
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
	///
	/// # Returns
	///
	/// * Returns Ok() with the signature on success or SignatureError on error
	pub fn get_sig(
		&mut self
	) -> Result<&[u8], SignatureError> {
		if self.sig_set == false {
			return Err(SignatureError::UninitializedContext);
		}

		let mut ptr: *mut u8 = ptr::null_mut();
		let mut len: usize = 0;

		let result = unsafe {
			leancrypto::lc_ed25519_sig_ptr(&mut ptr, &mut len,
						       &mut self.sig)
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

		Ok(&slice)
	}

	/// Method for safe immutable access to ED25519 secret key
	///
	/// # Returns
	///
	/// * Returns Ok() with the secret key on success or SignatureError on error
	pub fn get_sk(
		&mut self
	) -> Result<&[u8], SignatureError> {
		if self.sk_set == false {
			return Err(SignatureError::UninitializedContext);
		}

		let mut ptr: *mut u8 = ptr::null_mut();
		let mut len: usize = 0;

		let result = unsafe {
			leancrypto::lc_ed25519_sk_ptr(&mut ptr, &mut len,
						      &mut self.sk)
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

		Ok(&slice)
	}

	/// Method for safe immutable access to ED25519 public key
	///
	/// # Returns
	///
	/// * Returns Ok() with the public key on success or SignatureError on error
	pub fn get_pk(
		&mut self
	) -> Result<&[u8], SignatureError> {
		if self.pk_set == false {
			return Err(SignatureError::UninitializedContext);
		}

		let mut ptr: *mut u8 = ptr::null_mut();
		let mut len: usize = 0;

		let result = unsafe {
			leancrypto::lc_ed25519_pk_ptr(&mut ptr, &mut len,
						      &mut self.pk)
		};
		if result < 0 {
			return Err(SignatureError::ProcessingError);
		}

		let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

		Ok(&slice)
	}
}

/// This ensures the sensitive buffers are always zeroized
/// regardless of when it goes out of scope
impl Drop for lcr_ed25519 {
	fn drop(&mut self) {
		let /*mut*/ sk: leancrypto::lc_ed25519_sk = unsafe {
			std::mem::zeroed()
		};

		unsafe { std::ptr::write_volatile(&mut self.sk, sk) };
		atomic::compiler_fence(atomic::Ordering::SeqCst);
	}
}
