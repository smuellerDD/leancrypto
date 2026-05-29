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

use crate::error::KdfError;
use crate::ffi::leancrypto;
use crate::lcr_hash::{lcr_hash_type, lcr_hash_type_mapping};
use std::ptr;

/// Leancrypto wrapper for lc_kbkdf
pub struct lcr_kbkdf_ctr {
    /// Leancrypto hash reference
    hash: lcr_hash_type,
}

#[allow(dead_code)]
impl lcr_kbkdf_ctr {
    pub fn new(hash_type: lcr_hash_type) -> Self {
        lcr_kbkdf_ctr { hash: hash_type }
    }

    /// SP800-108 CTR-KDF derive
    ///
    /// # Arguments
    ///
    /// * `key` buffer with password
    /// * `label` buffer with arbitrary formatted label
    /// * `dst` destination buffer to be filled with derived key material
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or KdfError on error
    pub fn derive(
        &mut self,
        key: &[u8],
        label: &[u8],
        dst: &mut [u8],
    ) -> Result<(), KdfError> {
        /*
         * &[].as_ptr() returns 0x1 and not a NULL pointer
         */
        let mut keyptr = key.as_ptr();
        if key.len() == 0 {
            keyptr = ptr::null();
        }
        let mut labelptr = label.as_ptr();
        if label.len() == 0 {
            labelptr = ptr::null();
        }

        let result = unsafe {
            leancrypto::lc_kdf_ctr(
                lcr_hash_type_mapping(self.hash),
                keyptr,
                key.len(),
                labelptr,
                label.len(),
                dst.as_mut_ptr(),
                dst.len(),
            )
        };
        if result < 0 {
            return Err(KdfError::ProcessingError);
        }
        Ok(())
    }
}
