/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
use crate::error::HkdfError;
use crate::lcr_hash::lcr_hash_type;

/// Leancrypto wrapper for lc_hkdf
pub struct lcr_hkdf {
	/// Context for init/update/final
	hkdf_ctx: *mut leancrypto::lc_hkdf_ctx,

	/// Leancrypto hash reference
	hash: lcr_hash_type
}

#[allow(dead_code)]
impl lcr_hkdf {
	pub fn new(hash_type: lcr_hash_type) -> Self {
		lcr_hkdf {
			hkdf_ctx: ptr::null_mut(),
			hash: hash_type
		}
	}

	fn lcr_type_mapping(&mut self) -> *const leancrypto::lc_hash {
		unsafe {
			match self.hash {
				lcr_hash_type::lcr_sha2_256 =>
					leancrypto::lc_sha256,
				lcr_hash_type::lcr_sha2_384 =>
					leancrypto::lc_sha384,
				lcr_hash_type::lcr_sha2_512 =>
					leancrypto::lc_sha512,
				lcr_hash_type::lcr_sha3_256 =>
					leancrypto::lc_sha3_256,
				lcr_hash_type::lcr_sha3_384 =>
					leancrypto::lc_sha3_384,
				lcr_hash_type::lcr_sha3_512 =>
					leancrypto::lc_sha3_512,
				lcr_hash_type::lcr_ascon_256 =>
					leancrypto::lc_ascon_256,
				lcr_hash_type::lcr_shake_128 =>
					leancrypto::lc_shake128,
				lcr_hash_type::lcr_shake_256 =>
					leancrypto::lc_shake256,
				lcr_hash_type::lcr_cshake_128 =>
					leancrypto::lc_cshake128,
				lcr_hash_type::lcr_cshake_256 =>
					leancrypto::lc_cshake256,
			}
		}
	}

	/// HKDF extract
	pub fn extract(&mut self, ikm: &[u8], salt: &[u8]) ->
		Result<(), HkdfError> {
		let mut result;

		if self.hkdf_ctx.is_null() {
			/* Allocate the hash context */
			result = unsafe {
				leancrypto::lc_hkdf_alloc(
					self.lcr_type_mapping(),
					&mut self.hkdf_ctx)
			};
		} else {
			return Err(HkdfError::ProcessingError);
		}

		// Error handle
		if result >= 0 {
			result = unsafe { leancrypto::lc_hkdf_extract(
				self.hkdf_ctx, ikm.as_ptr(), ikm.len(),
				salt.as_ptr(), salt.len()) };
			if result < 0 {
				return Err(HkdfError::ProcessingError);
			}
			Ok(())
		} else {
			Err(HkdfError::AllocationError)
		}
	}

	/// HKDF extract returning the PRK
	pub fn extract_prk(&mut self, ikm: &[u8], salt: &[u8], prk: &mut [u8]) ->
		Result<(), HkdfError> {
		let mut result = 0;

		if self.hkdf_ctx.is_null() {
			/* Allocate the hash context */
			result = unsafe {
				leancrypto::lc_hkdf_alloc(
					self.lcr_type_mapping(),
					&mut self.hkdf_ctx)
			};
		}

		// Error handle
		if result >= 0 {
			result = unsafe { leancrypto::lc_hkdf_extract_prk(
				self.hkdf_ctx, ikm.as_ptr(), ikm.len(),
				salt.as_ptr(), salt.len(), prk.as_mut_ptr(),
				prk.len()) };
			if result < 0 {
				return Err(HkdfError::ProcessingError);
			}
			Ok(())
		} else {
			Err(HkdfError::AllocationError)
		}
	}

	/// HKDF expand
	pub fn expand(&mut self, info: &[u8], dst: &mut [u8]) ->
		Result<(), HkdfError> {
		if self.hkdf_ctx.is_null() {
			return Err(HkdfError::UninitializedContext);
		}

		let result = unsafe { leancrypto::lc_hkdf_expand(
				      self.hkdf_ctx, info.as_ptr(), info.len(),
				      dst.as_mut_ptr(), dst.len()) };
		if result < 0 {
			return Err(HkdfError::ProcessingError);
		}
		Ok(())
	}

	/// HKDF expand using the given PRK
	pub fn expand_prk(&mut self, info: &[u8], prk: &[u8], dst: &mut [u8]) ->
		Result<(), HkdfError> {
		if self.hkdf_ctx.is_null() {
			return Err(HkdfError::UninitializedContext);
		}

		let result = unsafe { leancrypto::lc_hkdf_expand_prk(
				      self.hkdf_ctx, info.as_ptr(), info.len(),
				      prk.as_ptr(), prk.len(), dst.as_mut_ptr(),
				      dst.len()) };
		if result < 0 {
			return Err(HkdfError::ProcessingError);
		}
		Ok(())
	}
}

/// This ensures the buffer is always freed
/// regardless of when it goes out of scope
impl Drop for lcr_hkdf {
	fn drop(&mut self) {
		if !self.hkdf_ctx.is_null() {
			unsafe { leancrypto::lc_hkdf_zero_free(self.hkdf_ctx); }
		}
	}
}
