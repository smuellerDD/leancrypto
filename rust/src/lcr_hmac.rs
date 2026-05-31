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

use crate::error::HashError;
use crate::ffi::leancrypto;
use crate::lcr_hash::{
    lcr_hash_digestsize_mapping, lcr_hash_type, lcr_hash_type_mapping,
};
use std::ptr;
use std::sync::atomic;

pub struct lcr_hmac_key {
    /// Immutable context of key
    hmac_key: leancrypto::lc_hmac_key,

    /// Leancrypto hash reference
    hmac: lcr_hash_type,
}

#[allow(dead_code)]
impl lcr_hmac_key {
    pub fn new(hmac_type: lcr_hash_type) -> Self {
        lcr_hmac_key {
            hmac_key: unsafe { std::mem::zeroed() },
            hmac: hmac_type,
        }
    }

    /// HMAC Init: Initializes message digest handle
    ///
    /// # Arguments
    ///
    /// * `key` HMAC key to be set
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn init(
        &mut self,
        key: &[u8],
    ) -> Result<(), HashError> {
        let result = unsafe {
            leancrypto::lc_hmac_setkey(
                &mut self.hmac_key,
                lcr_hash_type_mapping(self.hmac),
                key.as_ptr(),
                key.len(),
            )
        };
        if result < 0 {
            return Err(HashError::ProcessingError);
        }
        Ok(())
    }

    /// Return HMAC key
    ///
    /// # Returns
    ///
    /// * HMAC key
    pub fn get_hmac_key(&self) -> &leancrypto::lc_hmac_key {
        return &self.hmac_key;
    }
}

/// This ensures the buffer is always freed
/// regardless of when it goes out of scope
impl Drop for lcr_hmac_key {
    fn drop(&mut self) {
        let /*mut*/ key: leancrypto::lc_hmac_key = unsafe {
			std::mem::zeroed()
		};

        unsafe { std::ptr::write_volatile(&mut self.hmac_key, key) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

/// Leancrypto wrapper for lc_hmac
pub struct lcr_hmac {
    /// Context for init/update/final
    hmac_ctx: *mut leancrypto::lc_hmac_ctx,

    /// Leancrypto hmac reference
    hmac: lcr_hash_type,
}

#[allow(dead_code)]
impl lcr_hmac {
    pub fn new(hmac_type: lcr_hash_type) -> Self {
        lcr_hmac {
            hmac_ctx: ptr::null_mut(),
            hmac: hmac_type,
        }
    }

    /// Create HMAC
    ///
    /// # Arguments
    ///
    /// * `key` key used for HMAC
    /// * `msg` holds the message to be digested
    /// * `mac` Buffer to be filled with digest
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn hmac(
        &mut self,
        key: &[u8],
        msg: &[u8],
        mac: &mut [u8],
    ) -> Result<(), HashError> {
        if mac.len() < lcr_hash_digestsize_mapping(self.hmac) {
            return Err(HashError::ProcessingError);
        }

        unsafe {
            leancrypto::lc_hmac(
                lcr_hash_type_mapping(self.hmac),
                key.as_ptr(),
                key.len(),
                msg.as_ptr(),
                msg.len(),
                mac.as_mut_ptr(),
            );
        }

        Ok(())
    }

    /// HMAC Init: Initializes message digest handle
    ///
    /// # Arguments
    ///
    /// * `key` key used for HMAC
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn init(
        &mut self,
        key: &[u8],
    ) -> Result<(), HashError> {
        let mut result = 0;

        if self.hmac_ctx.is_null() {
            /* Allocate the hmac context */
            result = unsafe {
                leancrypto::lc_hmac_alloc(
                    lcr_hash_type_mapping(self.hmac),
                    &mut self.hmac_ctx,
                )
            };
        }

        // Error handle
        if result >= 0 {
            result = unsafe {
                leancrypto::lc_hmac_init(self.hmac_ctx, key.as_ptr(), key.len())
            };
            if result < 0 {
                return Err(HashError::ProcessingError);
            }
            Ok(())
        } else {
            Err(HashError::AllocationError)
        }
    }

    /// HMAC Init: Initializes message digest handle
    ///
    /// # Arguments
    ///
    /// * `key` key used for HMAC
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn init_with_hmac_key(
        &mut self,
        key: &lcr_hmac_key,
    ) -> Result<(), HashError> {
        let mut result = 0;

        if self.hmac_ctx.is_null() {
            /* Allocate the hmac context */
            result = unsafe {
                leancrypto::lc_hmac_alloc(
                    lcr_hash_type_mapping(self.hmac),
                    &mut self.hmac_ctx,
                )
            };
        }

        // Error handle
        if result >= 0 {
            result = unsafe {
                leancrypto::lc_hmac_init_with_hmac_key(
                    self.hmac_ctx,
                    key.get_hmac_key(),
                )
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
    ///
    /// # Arguments
    ///
    /// * `msg` holds the message to be digested
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn update(
        &mut self,
        msg: &[u8],
    ) -> Result<(), HashError> {
        if self.hmac_ctx.is_null() {
            return Err(HashError::UninitializedContext);
        }

        unsafe {
            leancrypto::lc_hmac_update(self.hmac_ctx, msg.as_ptr(), msg.len());
        }

        Ok(())
    }

    /// HMAC Final: Calculate message digest from message digest handle
    ///
    /// # Arguments
    ///
    /// * `mac` Buffer to be filled with digest
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn fini(
        &mut self,
        mac: &mut [u8],
    ) -> Result<(), HashError> {
        if self.hmac_ctx.is_null() {
            return Err(HashError::UninitializedContext);
        }

        if mac.len() < lcr_hash_digestsize_mapping(self.hmac) {
            return Err(HashError::ProcessingError);
        }

        unsafe {
            leancrypto::lc_hmac_final(self.hmac_ctx, mac.as_mut_ptr());
            leancrypto::lc_hmac_zero_free(self.hmac_ctx);
        }

        self.hmac_ctx = ptr::null_mut();

        Ok(())
    }

    /// Get the size of the message digest
    ///
    /// # Returns
    ///
    /// * Returns digest size
    pub fn digestsize(&mut self) -> usize {
        lcr_hash_digestsize_mapping(self.hmac)
    }
}

/// This ensures the buffer is always freed
/// regardless of when it goes out of scope
impl Drop for lcr_hmac {
    fn drop(&mut self) {
        if !self.hmac_ctx.is_null() {
            unsafe {
                leancrypto::lc_hmac_zero_free(self.hmac_ctx);
            }
        }
    }
}
