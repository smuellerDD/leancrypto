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

use crate::ffi::leancrypto;
use crate::error::KdfError;
use crate::lcr_hash::lcr_hash_type;

/// Leancrypto wrapper for lc_pbkdf2
pub struct lcr_pbkdf2 {
	/// Leancrypto hash reference
	hash: lcr_hash_type
}

#[allow(dead_code)]
impl lcr_pbkdf2 {
	pub fn new(hash_type: lcr_hash_type) -> Self {
		lcr_pbkdf2 {
			hash: hash_type
		}
	}

	/// Mapping of lcr_hash_type to leancrypto message digest
	/// implementation type
	///
	/// # Returns
	///
	/// * Returns leancrypto message digest implementation type
	fn lcr_type_mapping(
		&mut self
	) -> *const leancrypto::lc_hash {
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

	/// PBKDF2 derive
	///
	/// # Arguments
	///
	/// * `pw` buffer with password
	/// * `salt` buffer with salt
	/// * `count` iteration count
	/// * `key` key buffer to be filled with derived key material
	///
	/// # Returns
	///
	/// * Returns Ok() on success or KdfError on error
	pub fn derive(
		&mut self,
		pw: &[u8],
		salt: &[u8],
		count: u32,
		key: &mut [u8]
	) -> Result<(), KdfError> {

		let result = unsafe {
			leancrypto::lc_pbkdf2(self.lcr_type_mapping(),
					      pw.as_ptr(), pw.len(),
					      salt.as_ptr(), salt.len(), count,
					      key.as_mut_ptr(), key.len())
		};
		if result < 0 {
			return Err(KdfError::ProcessingError);
		}
		Ok(())
	}
}
