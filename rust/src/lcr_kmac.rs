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

pub enum lcr_kmac_type {
	lcr_kmac_128,
	lcr_kmac_256,
}

/// Leancrypto wrapper for lc_kmac
pub struct lcr_kmac {
	/// Context for init/update/final
	kmac_ctx: *mut leancrypto::lc_kmac_ctx,

	/// Leancrypto kmac reference
	kmac: lcr_kmac_type
}

#[allow(dead_code)]
impl lcr_kmac {
	pub fn new(kmac_type: lcr_kmac_type) -> Self {
		lcr_kmac {
			kmac_ctx: ptr::null_mut(),
			kmac: kmac_type
		}
	}

	fn lcr_type_mapping(&mut self) -> *const leancrypto::lc_hash {
		unsafe {
			match self.kmac {
				lcr_kmac_type::lcr_kmac_128 =>
					leancrypto::lc_cshake128,
				lcr_kmac_type::lcr_kmac_256 =>
					leancrypto::lc_cshake256,
			}
		}
	}

	/// Create KMAC
	///
	/// [key] key used for KMAC
	/// [s] Optional customization string
	/// [msg] holds the message to be digested
	/// [mac] Buffer to be filled with digest
	pub fn kmac(&mut self, key: &[u8], s: &[u8], msg: &[u8], mac: &mut [u8]) ->
		Result<(), HashError> {
		if mac.len() < 4 {
			return Err(HashError::ProcessingError)
		}

		unsafe {
			leancrypto::lc_kmac(self.lcr_type_mapping(),
					    key.as_ptr(), key.len(),
					    s.as_ptr(), s.len(),
					    msg.as_ptr(), msg.len(),
					    mac.as_mut_ptr(), mac.len());
		}

		Ok(())
	}

	/// Create KMAC XOF
	///
	/// [key] key used for KMAC
	/// [s] Optional customization string
	/// [msg] holds the message to be digested
	/// [mac] Buffer to be filled with digest
	pub fn kmac_xof(&mut self, key: &[u8], s: &[u8], msg: &[u8], mac: &mut [u8]) ->
		Result<(), HashError> {
		if mac.len() < 4 {
			return Err(HashError::ProcessingError)
		}

		unsafe {
			leancrypto::lc_kmac_xof(self.lcr_type_mapping(),
						key.as_ptr(), key.len(),
						s.as_ptr(), s.len(),
						msg.as_ptr(), msg.len(),
						mac.as_mut_ptr(), mac.len());
		}

		Ok(())
	}

	/// KMAC Init: Initializes message digest handle
	///
	/// [key] key used for KMAC
	/// [s] Optional customization string
	pub fn init(&mut self, key: &[u8], s: &[u8]) -> Result<(), HashError> {
		let mut result = 0;

		if self.kmac_ctx.is_null() {
			/* Allocate the kmac context */
			result = unsafe {
				leancrypto::lc_kmac_alloc(
					self.lcr_type_mapping(),
					&mut self.kmac_ctx, 0)
			};
		}

		// Error handle
		if result >= 0 {
			unsafe {
				leancrypto::lc_kmac_init(self.kmac_ctx,
							 key.as_ptr(),
							 key.len(),
							 s.as_ptr(), s.len())
			};
			Ok(())
		} else {
			Err(HashError::AllocationError)
		}
	}

	/// KMAC Update: Insert data into message digest handle
	pub fn update(&mut self, msg: &[u8]) -> Result<(), HashError> {
		if self.kmac_ctx.is_null() {
			return Err(HashError::UninitializedContext);
		}

		unsafe {
			leancrypto::lc_kmac_update(self.kmac_ctx,
						   msg.as_ptr(), msg.len());
		}

		Ok(())
	}

	/// KMAC Final: Calculate message digest from message digest handle
	///
	/// [mac] Buffer to be filled with digest
	pub fn fini(&mut self, mac: &mut [u8]) -> Result<(), HashError> {
		if self.kmac_ctx.is_null() {
			return Err(HashError::UninitializedContext);
		}

		if mac.len() < 4 {
			return Err(HashError::ProcessingError)
		}

		unsafe {
			leancrypto::lc_kmac_final(self.kmac_ctx,
						  mac.as_mut_ptr(),
						  mac.len());
			leancrypto::lc_kmac_zero_free(self.kmac_ctx);
		}

		self.kmac_ctx = ptr::null_mut();

		Ok(())
	}

	/// KMAC XOF Final: Calculate message digest from message digest handle
	///
	/// [mac] Buffer to be filled with digest
	pub fn fini_xof(&mut self, mac: &mut [u8]) -> Result<(), HashError> {
		if self.kmac_ctx.is_null() {
			return Err(HashError::UninitializedContext);
		}

		unsafe {
			leancrypto::lc_kmac_final_xof(self.kmac_ctx,
						      mac.as_mut_ptr(),
						      mac.len());
			// Do not free the handle as we may squeeze more
		}

		Ok(())
	}
}

/// This ensures the buffer is always freed
/// regardless of when it goes out of scope
impl Drop for lcr_kmac {
	fn drop(&mut self) {
		if !self.kmac_ctx.is_null() {
			unsafe { leancrypto::lc_kmac_zero_free(self.kmac_ctx); }
		}
	}
}
