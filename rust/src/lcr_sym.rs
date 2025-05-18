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
use crate::ffi::leancrypto;
use crate::error::SymError;

pub enum lcr_sym_type {
	lcr_aes_cbc,
	lcr_aes_ctr,
	lcr_aes_kw,
	lcr_chacha20,
}

/// Leancrypto wrapper for lc_sym
pub struct lcr_sym {
	/// Context for init/update/final
	sym_ctx: *mut leancrypto::lc_sym_ctx,

	/// Leancrypto AEAD reference
	sym: lcr_sym_type
}

#[allow(dead_code)]
impl lcr_sym {
	pub fn new(sym_type: lcr_sym_type) -> Self {
		lcr_sym {
			sym_ctx: ptr::null_mut(),
			sym: sym_type
		}
	}

	fn lcr_sym_alloc(&mut self) -> i32 {
		match self.sym {
			lcr_sym_type::lcr_aes_cbc => unsafe {
				leancrypto::lc_sym_alloc(
					leancrypto::lc_aes_cbc,
					&mut self.sym_ctx)
			},
			lcr_sym_type::lcr_aes_ctr => unsafe {
				leancrypto::lc_sym_alloc(
					leancrypto::lc_aes_ctr,
					&mut self.sym_ctx)
			},
			lcr_sym_type::lcr_aes_kw => unsafe {
				leancrypto::lc_sym_alloc(
					leancrypto::lc_aes_kw,
					&mut self.sym_ctx)
			},
			lcr_sym_type::lcr_chacha20 => unsafe {
				leancrypto::lc_sym_alloc(
					leancrypto::lc_chacha20,
					&mut self.sym_ctx)
			},
		}
	}

	/// Set key and symmetric context
	///
	/// [key] key
	pub fn setkey(&mut self, key: &[u8]) ->
		Result<(), SymError> {
		if self.sym_ctx.is_null() {
			let result = self.lcr_sym_alloc();

			if result < 0 {
				return Err(SymError::UninitializedContext)
			}
		}

		unsafe { leancrypto::lc_sym_init(self.sym_ctx) };

		let result = unsafe {
			leancrypto::lc_sym_setkey(self.sym_ctx,
						  key.as_ptr(), key.len())
		};

		if result < 0 {
			return Err(SymError::ProcessingError)
		}

		Ok(())
	}

	/// Set key and IV for symmetric context
	///
	/// [iv] IV
	pub fn setiv(&mut self, iv: &[u8]) ->
		Result<(), SymError> {
		if self.sym_ctx.is_null() {
			let result = self.lcr_sym_alloc();

			if result < 0 {
				return Err(SymError::UninitializedContext)
			}
		}

		let result = unsafe {
			leancrypto::lc_sym_setiv(self.sym_ctx, iv.as_ptr(),
						 iv.len())
		};
		if result < 0 {
			return Err(SymError::ProcessingError)
		}

		Ok(())
	}

	/// Symmetric encrypt
	///
	/// [plaintext] plaintext to be encrypted
	/// [ciphertext] buffer to be filled with ciphertext (can be the same
	///		 the plaintext buffer)
	pub fn encrypt(&mut self,
		       plaintext: &[u8],
		       ciphertext: &mut [u8]) ->
		Result<(), SymError> {
		if self.sym_ctx.is_null() {
			return Err(SymError::UninitializedContext)
		}
		if plaintext.len() != ciphertext.len() {
			return Err(SymError::ProcessingError)
		}

		unsafe {
			leancrypto::lc_sym_encrypt(
				self.sym_ctx, plaintext.as_ptr(),
				ciphertext.as_mut_ptr(), ciphertext.len())
		};

		Ok(())
	}

	/// AES KW encrypt
	///
	/// [plaintext] plaintext to be encrypted
	/// [ciphertext] buffer to be filled with ciphertext (can be the same
	///		 the plaintext buffer)
	pub fn kw_encrypt(&mut self,
			  plaintext: &[u8],
			  ciphertext: &mut [u8]) ->
		Result<(), SymError> {
		if self.sym_ctx.is_null() {
			return Err(SymError::UninitializedContext)
		}
		if plaintext.len() + 8 != ciphertext.len() {
			return Err(SymError::ProcessingError)
		}

		unsafe {
			leancrypto::lc_aes_kw_encrypt(
				self.sym_ctx, plaintext.as_ptr(),
				ciphertext.as_mut_ptr(), plaintext.len())
		};

		Ok(())
	}

	/// Symmetric decrypt
	///
	/// [ciphertext] ciphertext to be decrypted
	/// [plaintext] buffer to be filled with plaintext (can be the same
	///		the ciphertext buffer)
	pub fn decrypt(&mut self,
		       ciphertext: &[u8],
		       plaintext: &mut [u8]) ->
		Result<(), SymError> {
		if self.sym_ctx.is_null() {
			return Err(SymError::UninitializedContext)
		}
		if plaintext.len() != ciphertext.len() {
			return Err(SymError::ProcessingError)
		}

		unsafe {
			leancrypto::lc_sym_decrypt(
				self.sym_ctx, ciphertext.as_ptr(),
				plaintext.as_mut_ptr(), plaintext.len())
		};

		Ok(())
	}

	/// Symmetric decrypt
	///
	/// [ciphertext] ciphertext to be decrypted
	/// [plaintext] buffer to be filled with plaintext (can be the same
	///		the ciphertext buffer)
	pub fn kw_decrypt(&mut self,
			  ciphertext: &[u8],
			  plaintext: &mut [u8]) ->
		Result<(), SymError> {
		if self.sym_ctx.is_null() {
			return Err(SymError::UninitializedContext)
		}
		if plaintext.len() + 8 != ciphertext.len() {
			return Err(SymError::ProcessingError)
		}

		let result = unsafe {
			leancrypto::lc_aes_kw_decrypt(
				self.sym_ctx, ciphertext.as_ptr(),
				plaintext.as_mut_ptr(), ciphertext.len())
		};

		if result == -1*(leancrypto::EBADMSG as i32) {
			return Err(SymError::AuthenticationError)
		}
		if result < 0 {
			return Err(SymError::ProcessingError)
		}

		Ok(())
	}
}

/// This ensures the buffer is always freed
/// regardless of when it goes out of scope
impl Drop for lcr_sym {
	fn drop(&mut self) {
		if !self.sym_ctx.is_null() {
			unsafe { leancrypto::lc_sym_zero_free(self.sym_ctx); }
		}
	}
}
