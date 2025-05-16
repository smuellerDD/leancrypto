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

use crate::ffi::leancrypto;
use crate::error::RngError;

#[derive(PartialEq)]
pub enum lcr_rng_type {
	lcr_seeded_rng,
	lcr_xdrbg256,
	lcr_xdrbg128,
	lcr_hash_drbg,
	lcr_hmac_drbg,
}

/// Leancrypto wrapper for lc_rng
pub struct lcr_rng {
	/// RNG context
	rng_ctx: *mut leancrypto::lc_rng_ctx,

	/// Leancrypto rng reference
	rng: lcr_rng_type,

	seeded: bool,
}

#[allow(dead_code)]
impl lcr_rng {
	/// Instantiate the RNG: by default, the seeded RNG is immediately
	/// available.
	pub fn new() -> Self {
		lcr_rng {
			rng_ctx: unsafe { leancrypto::lc_seeded_rng },
			rng: lcr_rng_type::lcr_seeded_rng,
			seeded: true,
		}
	}

	/// Set the RNG type
	///
	/// By default, teh seeded RNG is set. Therefore, this call is only
	/// needed, if the caller wants a deterministic RNG whose seeding
	/// is controlled entirely by the caller.
	///
	/// [rng_type] Type of the RNG
	pub fn set_type(&mut self, rng_type: lcr_rng_type) ->
		Result<(), RngError> {
		self.rng = rng_type;
		match self.rng {
			lcr_rng_type::lcr_seeded_rng => {
				self.rng_ctx = unsafe {
					leancrypto::lc_seeded_rng
				};
				self.seeded = true
			},
			lcr_rng_type::lcr_xdrbg256 => {
				unsafe {
					leancrypto::lc_xdrbg256_drng_alloc(&mut self.rng_ctx)
				};
				self.seeded = false
			},
			lcr_rng_type::lcr_xdrbg128 => {
				unsafe {
					leancrypto::lc_xdrbg128_drng_alloc(&mut self.rng_ctx)
				};
				self.seeded = false
			},
			lcr_rng_type::lcr_hash_drbg => {
				unsafe {
					leancrypto::lc_drbg_hash_alloc(&mut self.rng_ctx)
				};
				self.seeded = false
			},
			lcr_rng_type::lcr_hmac_drbg => {
				unsafe {
					leancrypto::lc_drbg_hmac_alloc(&mut self.rng_ctx)
				};
				self.seeded = false
			},

			// _ => {
			// 	self.seeded = false;
			// 	return Err(RngError::AllocationError)
			// }
		}

		Ok(())
	}

	/// Seed or reseed the RNG
	///
	/// [seed] Buffer holding the seed data
	/// [personalization_string] Optional buffer holding the
	/// personalization_string (when reseeding is requested, then this
	/// parameter is used as "additional info" string)
	pub fn seed(&mut self, seed: &[u8], personalization_string: &[u8]) ->
		Result<(), RngError> {
		if self.rng_ctx.is_null() {
			return Err(RngError::UninitializedContext);
		}

		let result = unsafe {
			leancrypto::lc_rng_seed(
				self.rng_ctx, seed.as_ptr(), seed.len(),
				personalization_string.as_ptr(),
				personalization_string.len())
		};

		if result < 0 {
			return Err(RngError::ProcessingError);
		}

		self.seeded = true;

		Ok(())
	}

	/// Generate random numbers
	///
	/// [additional_info] holds the additional information (may be null)
	/// [rng_len] size of the random number
	pub fn generate(&mut self, additional_info: &[u8], rng_len: usize) ->
		(Vec<u8>, Result<(), RngError>) {
		let mut rng = vec![0u8; rng_len];

		if self.rng_ctx.is_null() {
			return (rng, Err(RngError::UninitializedContext));
		}
		if !self.seeded {
			return (rng, Err(RngError::NotSeeded));
		}

		let result = unsafe {
			leancrypto::lc_rng_generate(
				self.rng_ctx, additional_info.as_ptr(),
				additional_info.len(), rng.as_mut_ptr(), rng.len())
		};

		if result < 0 {
			return (rng, Err(RngError::ProcessingError));
		}

		(rng, Ok(()))
	}
}

/// This ensures the RNG context is always freed
/// regardless of when it goes out of scope
impl Drop for lcr_rng {
	fn drop(&mut self) {
		if !self.rng_ctx.is_null() &&
		    self.rng != lcr_rng_type::lcr_seeded_rng {
			unsafe { leancrypto::lc_rng_zero_free(self.rng_ctx); }
		}
	}
}
