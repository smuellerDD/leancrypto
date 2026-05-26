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
use std::ptr;
use std::sync::atomic;

pub enum lcr_sphincs_type {
    lcr_sphincs_shake_256s,
    lcr_sphincs_shake_256f,
    lcr_sphincs_shake_192s,
    lcr_sphincs_shake_192f,
    lcr_sphincs_shake_128s,
    lcr_sphincs_shake_128f,
}

/// Leancrypto wrapper for lc_sphincs
pub struct lcr_sphincs {
    // Context
    //sphincs_ctx: *mut leancrypto::lc_sphincs_ctx,
    /// Dilithium public key
    pk: leancrypto::lc_sphincs_pk,

    /// Dilithium secret key
    sk: leancrypto::lc_sphincs_sk,

    /// Dilithium signature
    sig: leancrypto::lc_sphincs_sig,

    pk_set: bool,
    sk_set: bool,
    sig_set: bool,
}

#[allow(dead_code)]
impl lcr_sphincs {
    pub fn new() -> Self {
        lcr_sphincs {
            //sphincs_ctx: ptr::null_mut(),
            pk: unsafe { std::mem::zeroed() },
            sk: unsafe { std::mem::zeroed() },
            sig: unsafe { std::mem::zeroed() },
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
            leancrypto::lc_sphincs_sk_load(
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
            leancrypto::lc_sphincs_pk_load(
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

    /// Define that the public key is to be used for small signature type
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn pk_set_keytype_small(&mut self) -> Result<(), SignatureError> {
        if self.pk_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let result = unsafe {
            leancrypto::lc_sphincs_pk_set_keytype_small(&mut self.pk)
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        Ok(())
    }

    /// Define that the public key is to be used for fast signature type
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn pk_set_keytype_fast(&mut self) -> Result<(), SignatureError> {
        if self.pk_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let result =
            unsafe { leancrypto::lc_sphincs_pk_set_keytype_fast(&mut self.pk) };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        Ok(())
    }

    /// Define that the secret key is to be used for small signature type
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn sk_set_keytype_small(&mut self) -> Result<(), SignatureError> {
        if self.sk_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let result = unsafe {
            leancrypto::lc_sphincs_sk_set_keytype_small(&mut self.sk)
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        Ok(())
    }

    /// Define that the secret key is to be used for fast signature type
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn sk_set_keytype_fast(&mut self) -> Result<(), SignatureError> {
        if self.sk_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let result =
            unsafe { leancrypto::lc_sphincs_sk_set_keytype_fast(&mut self.sk) };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

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
            leancrypto::lc_sphincs_sig_load(
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

    /// Mapping of lcr_sphincs_type to leancrypto ML-DSA implementation type
    ///
    /// # Returns
    ///
    /// * Returns leancrypto ML-DSA implementation type
    fn lcr_sphincs_type_mapping(sphincs_type: lcr_sphincs_type) -> u32 {
        match sphincs_type {
            lcr_sphincs_type::lcr_sphincs_shake_256s => {
                leancrypto::lc_sphincs_type_LC_SPHINCS_SHAKE_256s
            }
            lcr_sphincs_type::lcr_sphincs_shake_256f => {
                leancrypto::lc_sphincs_type_LC_SPHINCS_SHAKE_256f
            }
            lcr_sphincs_type::lcr_sphincs_shake_192s => {
                leancrypto::lc_sphincs_type_LC_SPHINCS_SHAKE_192s
            }
            lcr_sphincs_type::lcr_sphincs_shake_192f => {
                leancrypto::lc_sphincs_type_LC_SPHINCS_SHAKE_192f
            }
            lcr_sphincs_type::lcr_sphincs_shake_128s => {
                leancrypto::lc_sphincs_type_LC_SPHINCS_SHAKE_128s
            }
            lcr_sphincs_type::lcr_sphincs_shake_128f => {
                leancrypto::lc_sphincs_type_LC_SPHINCS_SHAKE_128f
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
        sphincs_type: lcr_sphincs_type,
    ) -> Result<(), SignatureError> {
        let result = unsafe {
            leancrypto::lc_sphincs_keypair(
                &mut self.pk,
                &mut self.sk,
                leancrypto::lc_seeded_rng,
                Self::lcr_sphincs_type_mapping(sphincs_type),
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

        let result = unsafe {
            leancrypto::lc_sphincs_sign(
                &mut self.sig,
                msg.as_ptr(),
                msg.len(),
                &self.sk,
                leancrypto::lc_seeded_rng,
            )
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

        let result = unsafe {
            leancrypto::lc_sphincs_sign(
                &mut self.sig,
                msg.as_ptr(),
                msg.len(),
                &self.sk,
                ptr::null_mut(),
            )
        };
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

        let result = unsafe {
            leancrypto::lc_sphincs_verify(
                &mut self.sig,
                msg.as_ptr(),
                msg.len(),
                &self.pk,
            )
        };
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
    pub fn get_sig(&mut self) -> Result<&[u8], SignatureError> {
        if self.sig_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        let result = unsafe {
            leancrypto::lc_sphincs_sig_ptr(&mut ptr, &mut len, &mut self.sig)
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(&slice)
    }

    /// Method for safe immutable access to ML-DSA secret key
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the secret key on success or SignatureError on error
    pub fn get_sk(&mut self) -> Result<&[u8], SignatureError> {
        if self.sk_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        let result = unsafe {
            leancrypto::lc_sphincs_sk_ptr(&mut ptr, &mut len, &mut self.sk)
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(&slice)
    }

    /// Method for safe immutable access to ML-DSA public key
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the public key on success or SignatureError on error
    pub fn get_pk(&mut self) -> Result<&[u8], SignatureError> {
        if self.pk_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        let result = unsafe {
            leancrypto::lc_sphincs_pk_ptr(&mut ptr, &mut len, &mut self.pk)
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError);
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(&slice)
    }
}

/// This ensures the sensitive buffers are always zeroized
/// regardless of when it goes out of scope
impl Drop for lcr_sphincs {
    fn drop(&mut self) {
        let sk: leancrypto::lc_sphincs_sk = unsafe { std::mem::zeroed() };

        unsafe { std::ptr::write_volatile(&mut self.sk, sk) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}
