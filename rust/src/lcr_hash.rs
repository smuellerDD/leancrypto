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

pub const LC_SHA_MAX_SIZE_DIGEST: usize =
    leancrypto::LC_SHA_MAX_SIZE_DIGEST as usize;

#[derive(Copy, Clone)]
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

/// Mapping of lcr_hash_type to leancrypto message digest
/// implementation type
///
/// # Returns
///
/// * Returns leancrypto message digest implementation type
pub fn lcr_hash_type_mapping(
    hash: lcr_hash_type
) -> *const leancrypto::lc_hash {
    unsafe {
        match hash {
            lcr_hash_type::lcr_sha2_256 => leancrypto::lc_sha256,
            lcr_hash_type::lcr_sha2_384 => leancrypto::lc_sha384,
            lcr_hash_type::lcr_sha2_512 => leancrypto::lc_sha512,
            lcr_hash_type::lcr_sha3_256 => leancrypto::lc_sha3_256,
            lcr_hash_type::lcr_sha3_384 => leancrypto::lc_sha3_384,
            lcr_hash_type::lcr_sha3_512 => leancrypto::lc_sha3_512,
            lcr_hash_type::lcr_ascon_256 => leancrypto::lc_ascon_256,
            lcr_hash_type::lcr_shake_128 => leancrypto::lc_shake128,
            lcr_hash_type::lcr_shake_256 => leancrypto::lc_shake256,
            lcr_hash_type::lcr_cshake_128 => leancrypto::lc_cshake128,
            lcr_hash_type::lcr_cshake_256 => leancrypto::lc_cshake256,
        }
    }
}

/// Mapping of lcr_hash_type to digest size
///
/// # Returns
///
/// * Returns digest size
pub fn lcr_hash_digestsize_mapping(hash: lcr_hash_type) -> usize {
    match hash {
        lcr_hash_type::lcr_sha2_256 => {
            leancrypto::LC_SHA256_SIZE_DIGEST as usize
        }
        lcr_hash_type::lcr_sha2_384 => {
            leancrypto::LC_SHA384_SIZE_DIGEST as usize
        }
        lcr_hash_type::lcr_sha2_512 => {
            leancrypto::LC_SHA512_SIZE_DIGEST as usize
        }
        lcr_hash_type::lcr_sha3_256 => {
            leancrypto::LC_SHA3_256_SIZE_DIGEST as usize
        }
        lcr_hash_type::lcr_sha3_384 => {
            leancrypto::LC_SHA3_384_SIZE_DIGEST as usize
        }
        lcr_hash_type::lcr_sha3_512 => {
            leancrypto::LC_SHA3_512_SIZE_DIGEST as usize
        }
        lcr_hash_type::lcr_ascon_256 => {
            leancrypto::LC_ASCON_HASH_DIGESTSIZE as usize
        }
        _ => 0,
    }
}

/// Leancrypto wrapper for lc_hash
pub struct lcr_hash {
    /// Context for init/update/final
    hash_ctx: leancrypto::lc_hash_ctx,

    /// Leancrypto hash reference
    hash: lcr_hash_type,

    hash_ctx_init: bool,
}

#[allow(dead_code)]
impl lcr_hash {
    pub fn new(hash_type: lcr_hash_type) -> Self {
        lcr_hash {
            hash_ctx: unsafe { std::mem::zeroed() },
            hash: hash_type,
            hash_ctx_init: false,
        }
    }

    /// Initialize the context if not already initialized
    fn ctx_initialize(&mut self) -> Result<(), HashError> {
        if !self.hash_ctx_init {
            let result = unsafe {
                leancrypto::lc_hash_set_ctx(
                    lcr_hash_type_mapping(self.hash),
                    &mut self.hash_ctx,
                )
            };
            if result < 0 {
                return Err(HashError::ProcessingError);
            }
            self.hash_ctx_init = true;
        }

        Ok(())
    }

    /// Create message digest
    ///
    /// # Arguments
    ///
    /// * `msg` holds the message to be digested
    /// * `digest` Buffer to be filled with digest
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn digest(
        &mut self,
        msg: &[u8],
        digest: &mut [u8],
    ) -> Result<(), HashError> {
        if digest.len() < lcr_hash_digestsize_mapping(self.hash) {
            return Err(HashError::ProcessingError);
        }

        let result = unsafe {
            leancrypto::lc_hash(
                lcr_hash_type_mapping(self.hash),
                msg.as_ptr(),
                msg.len(),
                digest.as_mut_ptr(),
            )
        };
        if result < 0 {
            return Err(HashError::ProcessingError);
        }

        Ok(())
    }

    /// Create XOF message digest
    ///
    /// # Arguments
    ///
    /// * `msg` holds the message to be digested
    /// * `digest` Buffer to be filled with digest
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn xof(
        &mut self,
        msg: &[u8],
        digest: &mut [u8],
    ) -> Result<(), HashError> {
        let result = unsafe {
            leancrypto::lc_xof(
                lcr_hash_type_mapping(self.hash),
                msg.as_ptr(),
                msg.len(),
                digest.as_mut_ptr(),
                digest.len(),
            )
        };
        if result < 0 {
            return Err(HashError::ProcessingError);
        }

        Ok(())
    }

    /// cSHAKE Init: Initializes message digest handle
    ///
    /// # Arguments
    ///
    /// * `n` N is a function-name bit string, used by NIST to define
    ///	  functions based on cSHAKE. When no function other than cSHAKE
    ///	  is desired, N is set to the empty string.
    /// * `s` S is a customization bit string. The user selects this string
    ///	  to define a variant of the function. When no customization is
    ///	  desired, S is set to the empty string.
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn cshake_init(
        &mut self,
        n: &[u8],
        s: &[u8],
    ) -> Result<(), HashError> {
        self.ctx_initialize()?;

        // Error handle
        let result = unsafe {
            leancrypto::lc_cshake_init(
                &mut self.hash_ctx,
                n.as_ptr(),
                n.len(),
                s.as_ptr(),
                s.len(),
            )
        };
        if result < 0 {
            return Err(HashError::ProcessingError);
        }
        Ok(())
    }

    /// Hash Init: Initializes message digest handle
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn init(&mut self) -> Result<(), HashError> {
        self.ctx_initialize()?;

        // Error handle
        let result = unsafe { leancrypto::lc_hash_init(&mut self.hash_ctx) };
        if result < 0 {
            return Err(HashError::ProcessingError);
        }
        Ok(())
    }

    /// Hash Update: Insert data into message digest handle
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
        unsafe {
            leancrypto::lc_hash_update(
                &mut self.hash_ctx,
                msg.as_ptr(),
                msg.len(),
            )
        };

        Ok(())
    }

    /// Set the size of the message digest - this call is intended for SHAKE
    ///
    /// # Arguments
    ///
    /// * `digestsize` Size of digest
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn set_digestsize(
        &mut self,
        digestsize: usize,
    ) -> Result<(), HashError> {
        unsafe {
            leancrypto::lc_hash_set_digestsize(&mut self.hash_ctx, digestsize)
        };

        Ok(())
    }

    /// Get the size of the message digest
    ///
    /// # Returns
    ///
    /// * Returns digest size
    pub fn digestsize(&mut self) -> usize {
        match self.ctx_initialize() {
            Err(_) => return 0,
            Ok(v) => v,
        };

        let digestsize =
            unsafe { leancrypto::lc_hash_digestsize(&mut self.hash_ctx) };
        return digestsize;
    }

    /// Hash Final: Calculate message digest from message digest handle
    ///
    /// # Arguments
    ///
    /// * `digest` Buffer to be filled with digest
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or HashError on error
    pub fn fini(
        &mut self,
        digest: &mut [u8],
    ) -> Result<(), HashError> {
        let digestsize =
            unsafe { leancrypto::lc_hash_digestsize(&mut self.hash_ctx) };

        if digest.len() < digestsize {
            return Err(HashError::ProcessingError);
        }

        unsafe {
            leancrypto::lc_hash_final(&mut self.hash_ctx, digest.as_mut_ptr());
            // No zeroization to allow multiple squeezes
        };

        Ok(())
    }
}

/*
 * Implementing the empty send trait is considered to be appropriate.
 *
 * The send trait is used for automatically duplicating the lcr_hash struct.
 * As part of it, the lc_hash_ctx->hash pointer is to be copied. As this
 * pointer is a static pointer that is always valid in leancrypto. Thus,
 * a simply duplication of the pointer is sufficient. Hence, an empty send
 * trait is considered appropriate.
 */
unsafe impl Send for lcr_hash {}
unsafe impl Sync for lcr_hash {}

impl Clone for lcr_hash {
    fn clone(&self) -> Self {
        // Clone the entire hash context state
        let mut state = self.hash_ctx.clone();

        // Adjust the memory pointer
        let _res = unsafe {
            leancrypto::lc_hash_set_ctx(
                lcr_hash_type_mapping(self.hash),
                &mut state,
            )
        };

        // Create a new object
        Self {
            hash_ctx: state,
            hash: self.hash,
            hash_ctx_init: true,
        }
    }
}

/// This ensures the buffer is always freed
/// regardless of when it goes out of scope
impl Drop for lcr_hash {
    fn drop(&mut self) {
        unsafe {
            leancrypto::lc_hash_zero(&mut self.hash_ctx);
        }
    }
}
