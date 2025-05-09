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

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

//Disable warnings about problematic FFI types
#[allow(improper_ctypes)]
//Disable warnings about unused symbols from leancrypto
#[allow(dead_code)]
mod leancrypto {
	include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::ptr;
use crate::error::HashError;

pub enum lcr_hash_type {
	lcr_sha2_256,
	lcr_sha2_384,
	lcr_sha2_512,
	lcr_sha3_256,
	lcr_sha3_384,
	lcr_sha3_512,
}

/// Leancrypto wrapper for lc_hash
pub struct lcr_hash {
	/// Output digest
	digest: [u8; leancrypto::LC_SHA_MAX_SIZE_DIGEST as _],

	/// Context for init/update/final
	hash_ctx: *mut leancrypto::lc_hash_ctx,

	/// Leancrypto hash reference
	hash: lcr_hash_type
}

#[allow(dead_code)]
impl lcr_hash {
	pub fn new(hash_type: lcr_hash_type) -> Self {
		lcr_hash {
			digest: [0; leancrypto::LC_SHA3_512_SIZE_DIGEST as _],
			hash_ctx: ptr::null_mut(),
			hash: hash_type
		}
	}

	fn lcr_type_mapping(&mut self) -> *const leancrypto::lc_hash {
		unsafe {
			match self.hash {
				lcr_hash_type::lcr_sha2_256 => leancrypto::lc_sha256,
				lcr_hash_type::lcr_sha2_384 => leancrypto::lc_sha384,
				lcr_hash_type::lcr_sha2_512 => leancrypto::lc_sha512,
				lcr_hash_type::lcr_sha3_256 => leancrypto::lc_sha3_256,
				lcr_hash_type::lcr_sha3_384 => leancrypto::lc_sha3_384,
				lcr_hash_type::lcr_sha3_512 => leancrypto::lc_sha3_512,
			}
		}
	}

	/// Create message digest
	///
	/// [msg] holds the message to be digested
	pub fn digest(&mut self, msg: &[u8]) -> Result<(), HashError> {
		unsafe {
			leancrypto::lc_hash(self.lcr_type_mapping(),
					    msg.as_ptr(), msg.len(),
					    self.digest.as_mut_ptr());
		}

		Ok(())
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
						   msg.as_ptr(), msg.len());
		}

		Ok(())
	}

	/// Hash Final: Calculate message digest from message digest handle
	pub fn fini(&mut self) -> Result<(), HashError> {
		if self.hash_ctx.is_null() {
			return Err(HashError::UninitializedContext);
		}

		unsafe {
			leancrypto::lc_hash_final(self.hash_ctx,
						  self.digest.as_mut_ptr());
			leancrypto::lc_hash_zero_free(self.hash_ctx);
		}

		self.hash_ctx = ptr::null_mut();

		Ok(())
	}

	/// Method for safe immutable access to buffer
	pub fn as_slice(&self) -> &[u8] {
		&self.digest
	}

	/// Method for safe mutable access to buffer
	pub fn as_mut_slice(&mut self) -> &mut [u8] {
		&mut self.digest
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
