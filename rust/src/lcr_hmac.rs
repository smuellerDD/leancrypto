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
use crate::error::HashError;

pub enum lcr_hmac_type {
	lcr_sha2_256,
	lcr_sha2_384,
	lcr_sha2_512,
	lcr_sha3_224,
	lcr_sha3_256,
	lcr_sha3_384,
	lcr_sha3_512,
}

/// Leancrypto wrapper for lc_hmac
pub struct lcr_hmac {
	/// Context for init/update/final
	hmac_ctx: *mut leancrypto::lc_hmac_ctx,

	/// Leancrypto hmac reference
	hmac: lcr_hmac_type
}

#[allow(dead_code)]
impl lcr_hmac {
	pub fn new(hmac_type: lcr_hmac_type) -> Self {
		lcr_hmac {
			hmac_ctx: ptr::null_mut(),
			hmac: hmac_type
		}
	}

	fn lcr_type_mapping(&mut self) -> *const leancrypto::lc_hash {
		unsafe {
			match self.hmac {
				lcr_hmac_type::lcr_sha2_256 =>
					leancrypto::lc_sha256,
				lcr_hmac_type::lcr_sha2_384 =>
					leancrypto::lc_sha384,
				lcr_hmac_type::lcr_sha2_512 =>
					leancrypto::lc_sha512,
				lcr_hmac_type::lcr_sha3_224 =>
					leancrypto::lc_sha3_224,
				lcr_hmac_type::lcr_sha3_256 =>
					leancrypto::lc_sha3_256,
				lcr_hmac_type::lcr_sha3_384 =>
					leancrypto::lc_sha3_384,
				lcr_hmac_type::lcr_sha3_512 =>
					leancrypto::lc_sha3_512,
			}
		}
	}

	fn lcr_digestsize_mapping(&mut self) -> usize {
		match self.hmac {
			lcr_hmac_type::lcr_sha2_256 => 32,
			lcr_hmac_type::lcr_sha2_384 => 48,
			lcr_hmac_type::lcr_sha2_512 => 64,
			lcr_hmac_type::lcr_sha3_224 => 28,
			lcr_hmac_type::lcr_sha3_256 => 32,
			lcr_hmac_type::lcr_sha3_384 => 48,
			lcr_hmac_type::lcr_sha3_512 => 64,
		}
	}

	/// Create HMAC
	///
	/// [key] key used for HMAC
	/// [msg] holds the message to be digested
	/// [mac] Buffer to be filled with digest
	pub fn hmac(&mut self, key: &[u8], msg: &[u8], mac: &mut [u8]) ->
		Result<(), HashError> {
		if mac.len() < Self::lcr_digestsize_mapping(self) {
			return Err(HashError::ProcessingError)
		}

		unsafe {
			leancrypto::lc_hmac(self.lcr_type_mapping(),
					    key.as_ptr(), key.len(),
					    msg.as_ptr(), msg.len(),
					    mac.as_mut_ptr());
		}

		Ok(())
	}

	/// HMAC Init: Initializes message digest handle
	///
	/// [key] key used for HMAC
	pub fn init(&mut self, key: &[u8]) -> Result<(), HashError> {
		let mut result = 0;

		if self.hmac_ctx.is_null() {
			/* Allocate the hmac context */
			result = unsafe {
				leancrypto::lc_hmac_alloc(
					self.lcr_type_mapping(),
					&mut self.hmac_ctx)
			};
		}

		// Error handle
		if result >= 0 {
			result = unsafe {
				leancrypto::lc_hmac_init(self.hmac_ctx,
							 key.as_ptr(),
							 key.len())
			};
			if result < 0 {
				return Err(HashError::ProcessingError);
			}
			Ok(())
		} else {
			Err(HashError::AllocationError)
		}
	}

	/// HMAC Update: Insert data into message digest handle
	pub fn update(&mut self, msg: &[u8]) -> Result<(), HashError> {
		if self.hmac_ctx.is_null() {
			return Err(HashError::UninitializedContext);
		}

		unsafe {
			leancrypto::lc_hmac_update(self.hmac_ctx,
						   msg.as_ptr(), msg.len());
		}

		Ok(())
	}

	/// HMAC Final: Calculate message digest from message digest handle
	///
	/// [mac] Buffer to be filled with digest
	pub fn fini(&mut self, mac: &mut [u8]) -> Result<(), HashError> {
		if self.hmac_ctx.is_null() {
			return Err(HashError::UninitializedContext);
		}

		if mac.len() < Self::lcr_digestsize_mapping(self) {
			return Err(HashError::ProcessingError)
		}

		unsafe {
			leancrypto::lc_hmac_final(self.hmac_ctx,
						  mac.as_mut_ptr());
			leancrypto::lc_hmac_zero_free(self.hmac_ctx);
		}

		self.hmac_ctx = ptr::null_mut();

		Ok(())
	}

	/// Get the size of the message digest
	///
	/// [digestsize] Size of digest
	pub fn digestsize(&mut self) -> usize {
		Self::lcr_digestsize_mapping(self)
	}
}

/// This ensures the buffer is always freed
/// regardless of when it goes out of scope
impl Drop for lcr_hmac {
	fn drop(&mut self) {
		if !self.hmac_ctx.is_null() {
			unsafe { leancrypto::lc_hmac_zero_free(self.hmac_ctx); }
		}
	}
}
