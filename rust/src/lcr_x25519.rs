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

use crate::error::X25519Error;
use crate::ffi::leancrypto;
use std::ptr;
use std::sync::atomic;

/// Leancrypto wrapper for lc_x25519
pub struct lcr_x25519 {
    /// X25519 shared secret
    ss: leancrypto::lc_x25519_ss,

    /// X25519 public key
    pk: leancrypto::lc_x25519_pk,

    /// X25519 secret key
    sk: leancrypto::lc_x25519_sk,

    /// X25519 public key of remote entity
    pk_remote: leancrypto::lc_x25519_pk,

    pk_set: bool,
    sk_set: bool,
    ss_set: bool,
    pk_remote_set: bool,
}

#[allow(dead_code)]
impl lcr_x25519 {
    pub fn new() -> Self {
        lcr_x25519 {
            pk: unsafe { std::mem::zeroed() },
            sk: unsafe { std::mem::zeroed() },
            ss: unsafe { std::mem::zeroed() },
            pk_remote: unsafe { std::mem::zeroed() },
            pk_set: false,
            sk_set: false,
            ss_set: false,
            pk_remote_set: false,
        }
    }

    /// Enable the X25519 support in leancrypto (by default, it is disabled)
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X25519Error on error
    pub fn enable(&self) -> Result<(), X25519Error> {
        let result =
            unsafe { leancrypto::lc_init(leancrypto::LC_INIT_NON_PQC_ENABLED) };
        if result < 0 {
            return Err(X25519Error::ProcessingError);
        }
        Ok(())
    }

    /// Generate hybrid X25519 key pair
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X25519Error on error
    pub fn keypair(&mut self) -> Result<(), X25519Error> {
        let result = unsafe {
            leancrypto::lc_x25519_keypair(
                &mut self.pk,
                &mut self.sk,
                leancrypto::lc_seeded_rng,
            )
        };

        if result < 0 {
            return Err(X25519Error::ProcessingError);
        }

        self.sk_set = true;
        self.pk_set = true;

        Ok(())
    }

    /// Shared secret generation
    ///
    /// The remote public key and the secret key must be already loaded.
    /// Upon success, the shared secret is present and can be retrieved.
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X25519Error on error
    pub fn shared_secret(&mut self) -> Result<(), X25519Error> {
        if self.sk_set == false || self.pk_remote_set == false {
            return Err(X25519Error::UninitializedContext);
        }

        let result = unsafe {
            leancrypto::lc_x25519_ss(&mut self.ss, &self.pk_remote, &self.sk)
        };

        if result < 0 {
            return Err(X25519Error::ProcessingError);
        }

        self.ss_set = true;

        Ok(())
    }

    /// Load public key for using with leancrypto
    ///
    /// # Arguments
    ///
    /// * `pk_buf` buffer with X25519 raw public key
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X25519Error on error
    pub fn pk_load(
        &mut self,
        pk_buf: &[u8],
    ) -> Result<(), X25519Error> {
        // No check for self.pk_set == false as we allow overwriting
        // of existing key.

        let result = unsafe {
            leancrypto::lc_x25519_pk_load(
                &mut self.pk,
                pk_buf.as_ptr(),
                pk_buf.len(),
            )
        };
        if result < 0 {
            return Err(X25519Error::ProcessingError);
        }

        self.pk_set = true;

        Ok(())
    }

    /// Load secret key for using with leancrypto
    ///
    /// # Arguments
    ///
    /// * `sk_buf` buffer with X25519 raw public key
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X25519Error on error
    pub fn sk_load(
        &mut self,
        sk_buf: &[u8],
    ) -> Result<(), X25519Error> {
        // No check for self.sk_set == false as we allow overwriting
        // of existing key.
        let result = unsafe {
            leancrypto::lc_x25519_sk_load(
                &mut self.sk,
                sk_buf.as_ptr(),
                sk_buf.len(),
            )
        };
        if result < 0 {
            return Err(X25519Error::ProcessingError);
        }

        self.sk_set = true;

        Ok(())
    }

    /// Load remote public key for using with leancrypto
    ///
    /// # Arguments
    ///
    /// * `pk_buf` buffer with remote X25519 raw public key
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X25519Error on error
    pub fn pk_remote_load(
        &mut self,
        pk_buf: &[u8],
    ) -> Result<(), X25519Error> {
        // No check for self.pk_remote_set == false as we allow
        // overwriting of existing key.

        let result = unsafe {
            leancrypto::lc_x25519_pk_load(
                &mut self.pk_remote,
                pk_buf.as_ptr(),
                pk_buf.len(),
            )
        };
        if result < 0 {
            return Err(X25519Error::ProcessingError);
        }

        self.pk_remote_set = true;

        Ok(())
    }

    /// Load remote public key for using with leancrypto
    ///
    /// # Arguments
    ///
    /// * `ss_buf` buffer with raw X25519 shared secret
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X25519Error on error
    pub fn ss_load(
        &mut self,
        ss_buf: &[u8],
    ) -> Result<(), X25519Error> {
        // No check for self.ss_set == false as we allow overwriting
        // of existing key.

        let result = unsafe {
            leancrypto::lc_x25519_ss_load(
                &mut self.ss,
                ss_buf.as_ptr(),
                ss_buf.len(),
            )
        };
        if result < 0 {
            return Err(X25519Error::ProcessingError);
        }

        self.ss_set = true;

        Ok(())
    }

    /// Method for safe immutable access to X25519 remote public key
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the public key on success or X25519Error on error
    pub fn get_pk_remote(&mut self) -> Result<&[u8], X25519Error> {
        if self.pk_remote_set == false {
            return Err(X25519Error::UninitializedContext);
        }

        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        let result = unsafe {
            leancrypto::lc_x25519_pk_ptr(
                &mut ptr,
                &mut len,
                &mut self.pk_remote,
            )
        };
        if result < 0 {
            return Err(X25519Error::ProcessingError);
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(&slice)
    }

    /// Method for safe immutable access to X25519 secret key
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the secret key on success or X25519Error on error
    pub fn get_sk(&mut self) -> Result<&[u8], X25519Error> {
        if self.sk_set == false {
            return Err(X25519Error::UninitializedContext);
        }

        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        let result = unsafe {
            leancrypto::lc_x25519_sk_ptr(&mut ptr, &mut len, &mut self.sk)
        };
        if result < 0 {
            return Err(X25519Error::ProcessingError);
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(&slice)
    }

    /// Method for safe immutable access to X25519 public key
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the public key on success or X25519Error on error
    pub fn get_pk(&mut self) -> Result<&[u8], X25519Error> {
        if self.pk_set == false {
            return Err(X25519Error::UninitializedContext);
        }

        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        let result = unsafe {
            leancrypto::lc_x25519_pk_ptr(&mut ptr, &mut len, &mut self.pk)
        };
        if result < 0 {
            return Err(X25519Error::ProcessingError);
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(&slice)
    }

    /// Method for safe immutable access to X25519 shared secret
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the shared secret on success or X25519Error on error
    pub fn get_ss(&mut self) -> Result<&[u8], X25519Error> {
        if self.ss_set == false {
            return Err(X25519Error::UninitializedContext);
        }

        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        let result = unsafe {
            leancrypto::lc_x25519_ss_ptr(&mut ptr, &mut len, &mut self.ss)
        };
        if result < 0 {
            return Err(X25519Error::ProcessingError);
        }

        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(&slice)
    }
}

/// This ensures the sensitive buffers are always zeroized
/// regardless of when it goes out of scope
impl Drop for lcr_x25519 {
    fn drop(&mut self) {
        let sk: leancrypto::lc_x25519_sk = unsafe { std::mem::zeroed() };

        unsafe { std::ptr::write_volatile(&mut self.sk, sk) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);

        let pk_remote: leancrypto::lc_x25519_pk = unsafe { std::mem::zeroed() };

        unsafe { std::ptr::write_volatile(&mut self.pk_remote, pk_remote) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);

        let ss: leancrypto::lc_x25519_ss = unsafe { std::mem::zeroed() };

        unsafe { std::ptr::write_volatile(&mut self.ss, ss) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}
