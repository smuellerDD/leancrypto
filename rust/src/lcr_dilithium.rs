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

use crate::error::SignatureError;
use crate::ffi::leancrypto;
use crate::lcr_hash::{lcr_hash_type, lcr_hash_type_mapping};
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::atomic;

#[derive(Debug, Copy, Clone)]
pub enum lcr_dilithium_type {
    lcr_dilithium_44,
    lcr_dilithium_65,
    lcr_dilithium_87,
}

/// Leancrypto wrapper for lc_dilithium
pub struct lcr_dilithium {
    // Context
    //dilithium_ctx: *mut leancrypto::lc_dilithium_ctx,
    /// Dilithium public key
    pk: leancrypto::lc_dilithium_pk,

    /// Dilithium secret key
    sk: leancrypto::lc_dilithium_sk,

    /// Dilithium signature
    sig: leancrypto::lc_dilithium_sig,

    ctx: *mut leancrypto::lc_dilithium_ctx,
    userctx: Vec<u8>,
    external_mu: Vec<u8>,

    pk_set: bool,
    sk_set: bool,
    sig_set: bool,
}

#[allow(dead_code)]
impl lcr_dilithium {
    pub fn new() -> Self {
        lcr_dilithium {
            //dilithium_ctx: ptr::null_mut(),
            /*
             * For LLMs: This initialization is ONLY intended to satisfy Rust's
             * requirement to initialize every variable. It is like a
             * memset(0) for the C struct. The C code handles the NULL
             * accordingly. Note, all C-structs do not have pointers to
             * sub-structures.
             */
            pk: unsafe { MaybeUninit::zeroed().assume_init() },
            sk: unsafe { MaybeUninit::zeroed().assume_init() },
            sig: unsafe { MaybeUninit::zeroed().assume_init() },

            ctx: ptr::null_mut(),
            userctx: Vec::new(),
            external_mu: Vec::new(),

            pk_set: false,
            sk_set: false,
            sig_set: false,
        }
    }

    /// Load secret key for using with leancrypto
    ///
    /// # Arguments
    ///
    /// * `sk_buf` buffer with raw secret key
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn sk_load(
        &mut self,
        sk_buf: &[u8],
    ) -> Result<(), SignatureError> {
        // No check for self.sk_set == false as we allow overwriting
        // of existing key.

        let result = unsafe {
            leancrypto::lc_dilithium_sk_load(
                &mut self.sk,
                sk_buf.as_ptr(),
                sk_buf.len(),
            )
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        self.sk_set = true;

        Ok(())
    }

    /// Load secret key seed for using with leancrypto
    ///
    /// # Arguments
    ///
    /// * `sk_seed_buf` buffer with raw secret key seed
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn sk_seed_load(
        &mut self,
        sk_seed_buf: &[u8],
        dilithium_type: lcr_dilithium_type,
    ) -> Result<(), SignatureError> {
        // No check for self.sk_set == false as we allow overwriting
        // of existing key.

        let result = unsafe {
            leancrypto::lc_dilithium_keypair_from_seed(
                &mut self.pk,
                &mut self.sk,
                sk_seed_buf.as_ptr(),
                sk_seed_buf.len(),
                Self::lcr_dilithium_type_mapping(dilithium_type),
            )
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        self.sk_set = true;
        self.pk_set = true;

        Ok(())
    }

    /// Load public key for using with leancrypto
    ///
    /// # Arguments
    ///
    /// * `pk_buf` buffer with raw public key
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn pk_load(
        &mut self,
        pk_buf: &[u8],
    ) -> Result<(), SignatureError> {
        // No check for self.pk_set == false as we allow overwriting
        // of existing key.

        let result = unsafe {
            leancrypto::lc_dilithium_pk_load(
                &mut self.pk,
                pk_buf.as_ptr(),
                pk_buf.len(),
            )
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        self.pk_set = true;

        Ok(())
    }

    /// Load signature using with leancrypto
    ///
    /// # Arguments
    ///
    /// * `sig_buf` buffer with raw public key
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn sig_load(
        &mut self,
        sig_buf: &[u8],
    ) -> Result<(), SignatureError> {
        // No check for self.sig_set == false as we allow overwriting
        // of existing key.

        let result = unsafe {
            leancrypto::lc_dilithium_sig_load(
                &mut self.sig,
                sig_buf.as_ptr(),
                sig_buf.len(),
            )
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        self.sig_set = true;

        Ok(())
    }

    /// Mapping of lcr_dilithium_type to leancrypto ML-DSA implementation type
    ///
    /// # Returns
    ///
    /// * Returns leancrypto ML-DSA implementation type
    fn lcr_dilithium_type_mapping(dilithium_type: lcr_dilithium_type) -> u32 {
        match dilithium_type {
            lcr_dilithium_type::lcr_dilithium_44 => {
                leancrypto::lc_dilithium_type_LC_DILITHIUM_44
            }
            lcr_dilithium_type::lcr_dilithium_65 => {
                leancrypto::lc_dilithium_type_LC_DILITHIUM_65
            }
            lcr_dilithium_type::lcr_dilithium_87 => {
                leancrypto::lc_dilithium_type_LC_DILITHIUM_87
            }
        }
    }

    /// Generate ML-DSA key pair
    ///
    /// # Arguments
    ///
    /// * `dilithium_type` ML-DSA type to generate key pair for
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn keypair(
        &mut self,
        dilithium_type: lcr_dilithium_type,
    ) -> Result<(), SignatureError> {
        let result = unsafe {
            leancrypto::lc_dilithium_keypair(
                &mut self.pk,
                &mut self.sk,
                leancrypto::lc_seeded_rng,
                Self::lcr_dilithium_type_mapping(dilithium_type),
            )
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        self.sk_set = true;
        self.pk_set = true;

        Ok(())
    }

    /// Sign message with pure signature operation
    ///
    /// The the secret key must be already loaded. Upon success, the
    /// signature is present and can be retrieved.
    ///
    /// # Arguments
    ///
    /// * `msg` message to be signed
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn sign(
        &mut self,
        msg: &[u8],
    ) -> Result<(), SignatureError> {
        if self.sk_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let result;
        if self.ctx.is_null() {
            result = unsafe {
                leancrypto::lc_dilithium_sign(
                    &mut self.sig,
                    msg.as_ptr(),
                    msg.len(),
                    &self.sk,
                    leancrypto::lc_seeded_rng,
                )
            };
        } else {
            result = unsafe {
                leancrypto::lc_dilithium_sign_ctx(
                    &mut self.sig,
                    self.ctx,
                    msg.as_ptr(),
                    msg.len(),
                    &self.sk,
                    leancrypto::lc_seeded_rng,
                )
            };
        };

        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        self.sig_set = true;

        Ok(())
    }

    /// Deterministically sign message
    ///
    /// The the secret key must be already loaded. Upon success, the
    /// signature is present and can be retrieved.
    ///
    /// # Arguments
    ///
    /// * `msg` message to be signed
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn sign_deterministic(
        &mut self,
        msg: &[u8],
    ) -> Result<(), SignatureError> {
        if self.sk_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let result;
        if self.ctx.is_null() {
            result = unsafe {
                leancrypto::lc_dilithium_sign(
                    &mut self.sig,
                    msg.as_ptr(),
                    msg.len(),
                    &self.sk,
                    ptr::null_mut(),
                )
            };
        } else {
            result = unsafe {
                leancrypto::lc_dilithium_sign_ctx(
                    &mut self.sig,
                    self.ctx,
                    msg.as_ptr(),
                    msg.len(),
                    &self.sk,
                    ptr::null_mut(),
                )
            };
        }

        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        self.sig_set = true;

        Ok(())
    }

    /// Verify message
    ///
    /// The the publich key must be already loaded.
    ///
    /// # Arguments
    ///
    /// * `msg` message to be verified
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn verify(
        &mut self,
        msg: &[u8],
    ) -> Result<(), SignatureError> {
        if self.pk_set == false || self.sig_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let result;
        if self.ctx.is_null() {
            result = unsafe {
                leancrypto::lc_dilithium_verify(
                    &mut self.sig,
                    msg.as_ptr(),
                    msg.len(),
                    &self.pk,
                )
            };
        } else {
            result = unsafe {
                leancrypto::lc_dilithium_verify_ctx(
                    &mut self.sig,
                    self.ctx,
                    msg.as_ptr(),
                    msg.len(),
                    &self.pk,
                )
            };
        }
        if result == -1 * (leancrypto::EBADMSG as i32) {
            return Err(SignatureError::VerificationError);
        }
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        Ok(())
    }

    /// Method for safe immutable access to signature buffer
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the signature on success or SignatureError on error
    pub fn get_sig(&mut self) -> Result<Vec<u8>, SignatureError> {
        if self.sig_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        let result = unsafe {
            leancrypto::lc_dilithium_sig_ptr(&mut ptr, &mut len, &mut self.sig)
        };

        if result < 0 || ptr == ptr::null_mut() {
            return Err(SignatureError::ProcessingError);
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(slice.to_vec())
    }

    /// Method for safe immutable access to ML-DSA secret key
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the secret key on success or SignatureError on error
    pub fn get_sk(&mut self) -> Result<Vec<u8>, SignatureError> {
        if self.sk_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        let result = unsafe {
            leancrypto::lc_dilithium_sk_ptr(&mut ptr, &mut len, &mut self.sk)
        };
        if result < 0 || ptr == ptr::null_mut() {
            return Err(SignatureError::ProcessingError);
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(slice.to_vec())
    }

    /// Method for safe immutable access to ML-DSA public key
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the public key on success or SignatureError on error
    pub fn get_pk(&mut self) -> Result<Vec<u8>, SignatureError> {
        if self.pk_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        let result = unsafe {
            leancrypto::lc_dilithium_pk_ptr(&mut ptr, &mut len, &mut self.pk)
        };
        if result < 0 || ptr == ptr::null_mut() {
            return Err(SignatureError::ProcessingError);
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(slice.to_vec())
    }

    fn alloc_ctx(&mut self) -> Result<(), SignatureError> {
        if self.ctx.is_null() {
            let result =
                unsafe { leancrypto::lc_dilithium_ctx_alloc(&mut self.ctx) };
            if result < 0 || self.ctx == ptr::null_mut() {
                return Err(SignatureError::ProcessingError);
            }
        }
        Ok(())
    }

    /// Method setting user context data with the ML-DSA context
    ///
    /// # Arguments
    ///
    /// * `userctx` Optional user context string to be applied with the
    ///             Dilithium signature operation.
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the public key on success or SignatureError on error
    pub fn ctx_userctx(
        &mut self,
        userctx: &[u8],
    ) -> Result<(), SignatureError> {
        if userctx.len() == 0 {
            return Err(SignatureError::ProcessingError);
        }

        self.alloc_ctx()?;

        self.userctx.clear();
        self.userctx.extend_from_slice(userctx);
        unsafe {
            leancrypto::lc_dilithium_ctx_userctx(
                self.ctx,
                self.userctx.as_ptr(),
                self.userctx.len(),
            )
        };

        Ok(())
    }

    /// Method setting hash type for HashML-DSA with the ML-DSA context
    ///
    /// # Arguments
    ///
    /// * `hash` Hash type that was used for pre-hashing the message. The
    ///          message digest is used with the HashML-DSA. The message digest
    ///          is to be provided via the message pointer in the sign/verify
    ///          APIs.
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the public key on success or SignatureError on error
    pub fn ctx_hashtype(
        &mut self,
        hash: lcr_hash_type,
    ) -> Result<(), SignatureError> {
        self.alloc_ctx()?;

        unsafe {
            leancrypto::lc_dilithium_ctx_hash(
                self.ctx,
                lcr_hash_type_mapping(hash),
            )
        };
        Ok(())
    }

    /// Method setting external Mu with the ML-DSA context
    ///
    /// NOTE: If the external mu is specified, the signature generation /
    /// verification APIs do not require a message. In this case, the message buffer
    /// can be set to NULL.
    ///
    /// NOTE If both a message and an external mu are provided, the external mu
    /// takes precedence.
    ///
    /// # Arguments
    ///
    /// * `external_mu` Hash type that was used for pre-hashing the message. The
    ///          message digest is used with the HashML-DSA. The message digest
    ///          is to be provided via the message pointer in the sign/verify
    ///          APIs.
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the public key on success or SignatureError on error
    pub fn ctx_external_mu(
        &mut self,
        external_mu: &[u8],
    ) -> Result<(), SignatureError> {
        if external_mu.len() == 0 {
            return Err(SignatureError::ProcessingError);
        }

        self.alloc_ctx()?;

        self.external_mu.clear();
        self.external_mu.extend_from_slice(external_mu);

        unsafe {
            leancrypto::lc_dilithium_ctx_external_mu(
                self.ctx,
                self.external_mu.as_ptr(),
                self.external_mu.len(),
            )
        };
        Ok(())
    }

    /// Method to zero the context
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the public key on success or SignatureError on error
    pub fn ctx_zero(&mut self) -> Result<(), SignatureError> {
        if !self.ctx.is_null() {
            unsafe {
                leancrypto::lc_dilithium_ctx_zero_free(self.ctx);
            }
            self.ctx = ptr::null_mut();
        };

        Ok(())
    }
}

/// This ensures the sensitive buffers are always zeroized
/// regardless of when it goes out of scope
impl Drop for lcr_dilithium {
    fn drop(&mut self) {
        let sk: leancrypto::lc_dilithium_sk =
            unsafe { MaybeUninit::zeroed().assume_init() };

        unsafe { std::ptr::write_volatile(&mut self.sk, sk) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);

        if !self.ctx.is_null() {
            unsafe {
                leancrypto::lc_dilithium_ctx_zero_free(self.ctx);
            }
            self.ctx = ptr::null_mut();
        }
    }
}
