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
use crate::SecretKey::SecretKey;
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::atomic;

/// Leancrypto wrapper for lc_ed448
pub struct lcr_ed448 {
    // Context
    //ed448_ctx: *mut leancrypto::lc_ed448_ctx,
    /// ED448 public key
    pk: leancrypto::lc_ed448_pk,

    /// ED448 secret key
    sk: leancrypto::lc_ed448_sk,

    /// ED448 signature
    sig: leancrypto::lc_ed448_sig,

    pk_set: bool,
    sk_set: bool,
    sig_set: bool,
}

#[allow(dead_code)]
impl lcr_ed448 {
    pub fn new() -> Self {
        lcr_ed448 {
            //ed448_ctx: ptr::null_mut(),
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
            pk_set: false,
            sk_set: false,
            sig_set: false,
        }
    }

    /// Enable the ED448 support in leancrypto (by default, it is disabled)
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn enable(&self) -> Result<(), SignatureError> {
        let result =
            unsafe { leancrypto::lc_init(leancrypto::LC_INIT_NON_PQC_ENABLED) };
        if result < 0 {
            return Err(SignatureError::ProcessingError(result));
        }
        Ok(())
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
            leancrypto::lc_ed448_sk_load(
                &mut self.sk,
                sk_buf.as_ptr(),
                sk_buf.len(),
            )
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError(result));
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
            leancrypto::lc_ed448_pk_load(
                &mut self.pk,
                pk_buf.as_ptr(),
                pk_buf.len(),
            )
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError(result));
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
            leancrypto::lc_ed448_sig_load(
                &mut self.sig,
                sig_buf.as_ptr(),
                sig_buf.len(),
            )
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError(result));
        }

        self.sig_set = true;

        Ok(())
    }

    /// Generate ED448 key pair
    ///
    /// # Arguments
    ///
    /// * `dilithium_type` ED448 type to generate key pair for
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or SignatureError on error
    pub fn keypair(&mut self) -> Result<(), SignatureError> {
        let result = unsafe {
            leancrypto::lc_ed448_keypair(
                &mut self.pk,
                &mut self.sk,
                leancrypto::lc_seeded_rng,
            )
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError(result));
        }

        self.sk_set = true;
        self.pk_set = true;

        Ok(())
    }

    /// Sign message
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
            leancrypto::lc_ed448_sign(
                &mut self.sig,
                msg.as_ptr(),
                msg.len(),
                &self.sk,
                leancrypto::lc_seeded_rng,
            )
        };
        if result < 0 {
            return Err(SignatureError::ProcessingError(result));
        }

        self.sig_set = true;

        Ok(())
    }

    /// Verify message with pure signature operation
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
            leancrypto::lc_ed448_verify(
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
            return Err(SignatureError::ProcessingError(result));
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
            leancrypto::lc_ed448_sig_ptr(&mut ptr, &mut len, &mut self.sig)
        };
        if result < 0 || ptr == ptr::null_mut() {
            return Err(SignatureError::ProcessingError(result));
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(slice.to_vec())
    }

    /// Method for safe immutable access to ED448 secret key
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the secret key on success or SignatureError on error
    pub fn get_sk(&mut self) -> Result<SecretKey, SignatureError> {
        if self.sk_set == false {
            return Err(SignatureError::UninitializedContext);
        }

        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        let result = unsafe {
            leancrypto::lc_ed448_sk_ptr(&mut ptr, &mut len, &mut self.sk)
        };
        if result < 0 || ptr == ptr::null_mut() {
            return Err(SignatureError::ProcessingError(result));
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        Ok(SecretKey::new(slice))
    }

    /// Method for safe immutable access to ED448 public key
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
            leancrypto::lc_ed448_pk_ptr(&mut ptr, &mut len, &mut self.pk)
        };
        if result < 0 || ptr == ptr::null_mut() {
            return Err(SignatureError::ProcessingError(result));
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(slice.to_vec())
    }
}

/// This ensures the sensitive buffers are always zeroized
/// regardless of when it goes out of scope
impl Drop for lcr_ed448 {
    fn drop(&mut self) {
        let /*mut*/ sk: leancrypto::lc_ed448_sk = unsafe {
			std::mem::zeroed()
		};

        unsafe { std::ptr::write_volatile(&mut self.sk, sk) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}
