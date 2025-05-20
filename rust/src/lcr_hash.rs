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

pub enum lcr_hash_type {
	lcr_sha2_256,
	lcr_sha2_384,
	lcr_sha2_512,
	lcr_sha3_256,
	lcr_sha3_384,
	lcr_sha3_512,
	lcr_ascon_256,
	lcr_shake_128,
	lcr_shake_256,
	lcr_cshake_128,
	lcr_cshake_256,
}

/// Leancrypto wrapper for lc_hash
pub struct lcr_hash {
	/// Context for init/update/final
	hash_ctx: *mut leancrypto::lc_hash_ctx,

	/// Leancrypto hash reference
	hash: lcr_hash_type
}

#[allow(dead_code)]
impl lcr_hash {
	pub fn new(hash_type: lcr_hash_type) -> Self {
		lcr_hash {
			hash_ctx: ptr::null_mut(),
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

	fn lcr_digestsize_mapping(&mut self) -> usize {
		match self.hash {
			lcr_hash_type::lcr_sha2_256 => 32,
			lcr_hash_type::lcr_sha2_384 => 48,
			lcr_hash_type::lcr_sha2_512 => 64,
			lcr_hash_type::lcr_sha3_256 => 32,
			lcr_hash_type::lcr_sha3_384 => 48,
			lcr_hash_type::lcr_sha3_512 => 64,
			lcr_hash_type::lcr_ascon_256 => 32,
			_ => 0,
		}
	}

	/// Create message digest
	///
	/// [msg] holds the message to be digested
	/// [digest] Buffer to be filled with digest
	pub fn digest(&mut self, msg: &[u8], digest: &mut [u8]) ->
		Result<(), HashError> {

		if digest.len() < Self::lcr_digestsize_mapping(self) {
			return Err(HashError::ProcessingError)
		}

		unsafe {
			leancrypto::lc_hash(self.lcr_type_mapping(),
					    msg.as_ptr(), msg.len(),
					    digest.as_mut_ptr())
		};

		Ok(())
	}

	/// Create XOF message digest
	///
	/// [msg] holds the message to be digested
	/// [digest] Buffer to be filled with digest
	pub fn xof(&mut self, msg: &[u8], digest: &mut [u8]) ->
		Result<(), HashError> {
		unsafe {
			leancrypto::lc_xof(self.lcr_type_mapping(),
					   msg.as_ptr(), msg.len(),
					   digest.as_mut_ptr(), digest.len())
		};

		Ok(())
	}

	/// cSHAKE Init: Initializes message digest handle
	///
	/// [n] N is a function-name bit string, used by NIST to define
	///	 functions based on cSHAKE. When no function other than cSHAKE
	///	 is desired, N is set to the empty string.
	/// [s] S is a customization bit string. The user selects this string
	///	 to define a variant of the function. When no customization is
	///	 desired, S is set to the empty string.
	pub fn cshake_init(&mut self, n: &[u8], s: &[u8]) ->
		Result<(), HashError> {
		let mut result = 0;

		if self.hash_ctx.is_null() {
			/* Allocate the hash context */
			result = unsafe {
				leancrypto::lc_hash_alloc(
					self.lcr_type_mapping(),
					&mut self.hash_ctx)
			};
		}

		// Error handle
		if result >= 0 {
			unsafe { leancrypto::lc_cshake_init(
				self.hash_ctx, n.as_ptr(), n.len(), s.as_ptr(),
				s.len()) };
			Ok(())
		} else {
			Err(HashError::AllocationError)
		}
	}

	/// Hash Init: Initializes message digest handle
	pub fn init(&mut self) -> Result<(), HashError> {
		let mut result = 0;

		if self.hash_ctx.is_null() {
			/* Allocate the hash context */
			result = unsafe {
				leancrypto::lc_hash_alloc(
					self.lcr_type_mapping(),
					&mut self.hash_ctx)
			};
		}

		// Error handle
		if result >= 0 {
			unsafe { leancrypto::lc_hash_init(self.hash_ctx) };
			Ok(())
		} else {
			Err(HashError::AllocationError)
		}
	}

	/// Hash Update: Insert data into message digest handle
	pub fn update(&mut self, msg: &[u8]) -> Result<(), HashError> {
		if self.hash_ctx.is_null() {
			return Err(HashError::UninitializedContext);
		}

		unsafe {
			leancrypto::lc_hash_update(self.hash_ctx,
						   msg.as_ptr(), msg.len())
		};

		Ok(())
	}

	/// Set the size of the message digest - this call is intended for SHAKE
	///
	/// [digestsize] Size of digest
	pub fn set_digestsize(&mut self, digestsize: usize) ->
		Result<(), HashError> {
		if self.hash_ctx.is_null() {
			return Err(HashError::UninitializedContext);
		}

		unsafe {
			leancrypto::lc_hash_set_digestsize(self.hash_ctx,
							   digestsize)
		};

		Ok(())
	}

	/// Get the size of the message digest
	///
	/// [digestsize] Size of digest
	pub fn digestsize(&mut self) -> usize {
		if !self.hash_ctx.is_null() {
			let digestsize = unsafe {
				leancrypto::lc_hash_digestsize(self.hash_ctx)
			};
			return digestsize;
		}

		Self::lcr_digestsize_mapping(self)
	}

	/// Hash Final: Calculate message digest from message digest handle
	///
	/// [digest] Buffer to be filled with digest
	pub fn fini(&mut self, digest: &mut [u8]) -> Result<(), HashError> {
		if self.hash_ctx.is_null() {
			return Err(HashError::UninitializedContext);
		}

		let digestsize = unsafe {
			leancrypto::lc_hash_digestsize(self.hash_ctx)
		};

		if digest.len() < digestsize {
			return Err(HashError::ProcessingError)
		}

		unsafe {
			leancrypto::lc_hash_final(self.hash_ctx,
						  digest.as_mut_ptr());
			// No zeroization to allow multiple squeezes
		};

		Ok(())
	}
}

/// This ensures the buffer is always freed
/// regardless of when it goes out of scope
impl Drop for lcr_hash {
	fn drop(&mut self) {
		if !self.hash_ctx.is_null() {
			unsafe { leancrypto::lc_hash_zero_free(self.hash_ctx); }
		}
	}
}
