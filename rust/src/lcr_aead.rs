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

use crate::error::AeadError;
use crate::ffi::leancrypto;
use std::ptr;

pub enum lcr_aead_type {
    lcr_ascon_128,
    lcr_ascon_keccak_256,
    lcr_ascon_keccak_512,
    lcr_aes_cbc_sha2_512,
    lcr_aes_cbc_cshake256,
    lcr_chacha20_poly1305,
    lcr_aes_gcm,
}

/// Leancrypto wrapper for lc_aead
pub struct lcr_aead {
    /// Context for init/update/final
    aead_ctx: *mut leancrypto::lc_aead_ctx,

    /// Leancrypto AEAD reference
    aead: lcr_aead_type,
}

#[allow(dead_code)]
impl lcr_aead {
    pub fn new(aead_type: lcr_aead_type) -> Self {
        lcr_aead {
            aead_ctx: ptr::null_mut(),
            aead: aead_type,
        }
    }

    fn lcr_aead_alloc(&mut self) -> i32 {
        match self.aead {
            lcr_aead_type::lcr_ascon_128 => unsafe {
                leancrypto::lc_al_alloc(&mut self.aead_ctx)
            },
            lcr_aead_type::lcr_ascon_keccak_256 => unsafe {
                leancrypto::lc_ak_alloc(
                    leancrypto::lc_sha3_256,
                    &mut self.aead_ctx,
                )
            },
            lcr_aead_type::lcr_ascon_keccak_512 => unsafe {
                leancrypto::lc_ak_alloc(
                    leancrypto::lc_sha3_512,
                    &mut self.aead_ctx,
                )
            },
            lcr_aead_type::lcr_aes_cbc_sha2_512 => unsafe {
                leancrypto::lc_sh_alloc(
                    leancrypto::lc_aes_cbc,
                    leancrypto::lc_sha512,
                    &mut self.aead_ctx,
                )
            },
            lcr_aead_type::lcr_aes_cbc_cshake256 => unsafe {
                leancrypto::lc_kh_alloc(
                    leancrypto::lc_aes_cbc,
                    leancrypto::lc_cshake256,
                    &mut self.aead_ctx,
                )
            },
            lcr_aead_type::lcr_chacha20_poly1305 => unsafe {
                leancrypto::lc_chacha20_poly1305_alloc(&mut self.aead_ctx)
            },
            lcr_aead_type::lcr_aes_gcm => unsafe {
                leancrypto::lc_aes_gcm_alloc(&mut self.aead_ctx)
            },
        }
    }

    /// Set key and IV for AEAD context
    ///
    /// # Arguments
    ///
    /// * `key` key used for AEAD
    /// * `iv` IV to be used for the AEAD operation
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or AeadError on error
    pub fn setkey(
        &mut self,
        key: &[u8],
        iv: &[u8],
    ) -> Result<(), AeadError> {
        if self.aead_ctx.is_null() {
            let result = self.lcr_aead_alloc();

            if result < 0 {
                return Err(AeadError::UninitializedContext);
            }
        }

        let result = unsafe {
            leancrypto::lc_aead_setkey(
                self.aead_ctx,
                key.as_ptr(),
                key.len(),
                iv.as_ptr(),
                iv.len(),
            )
        };
        if result < 0 {
            return Err(AeadError::ProcessingError);
        }

        Ok(())
    }

    /// AEAD one-shot encrypt
    ///
    /// # Arguments
    ///
    /// * `plaintext` plaintext to be encrypted
    /// * `ciphertext` buffer to be filled with ciphertext (can be the same
    ///		   the plaintext buffer)
    /// * `aad` AAD to be used for encryption
    /// * `tag` Buffer to be filled with the generated tag
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or AeadError on error
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
        aad: &[u8],
        tag: &mut [u8],
    ) -> Result<(), AeadError> {
        if self.aead_ctx.is_null() {
            return Err(AeadError::UninitializedContext);
        }
        if plaintext.len() > 0 && plaintext.len() != ciphertext.len() {
            return Err(AeadError::ProcessingError);
        }

        /*
         * &[].as_ptr() returns 0x1 and not a NULL pointer
         */
        let mut ptptr = plaintext.as_ptr();
        if plaintext.len() == 0 {
            ptptr = ptr::null();
        }
        let mut ctptr = ciphertext.as_mut_ptr();
        if ciphertext.len() == 0 {
            ctptr = ptr::null_mut();
        }
        let mut aadptr = aad.as_ptr();
        if aad.len() == 0 {
            aadptr = ptr::null_mut();
        }

        let result = unsafe {
            leancrypto::lc_aead_encrypt(
                self.aead_ctx,
                ptptr,
                ctptr,
                ciphertext.len(),
                aadptr,
                aad.len(),
                tag.as_mut_ptr(),
                tag.len(),
            )
        };

        if result < 0 {
            return Err(AeadError::ProcessingError);
        }

        Ok(())
    }

    /// AEAD initialize encrypt for stream operation
    ///
    /// # Arguments
    ///
    /// * `aad` AAD to be used for encryption
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or AeadError on error
    pub fn enc_init(
        &mut self,
        aad: &[u8],
    ) -> Result<(), AeadError> {
        if self.aead_ctx.is_null() {
            return Err(AeadError::UninitializedContext);
        }

        let result = unsafe {
            leancrypto::lc_aead_enc_init(self.aead_ctx, aad.as_ptr(), aad.len())
        };

        if result < 0 {
            return Err(AeadError::ProcessingError);
        }

        Ok(())
    }

    /// AEAD stream mode encryption of plaintext
    ///
    /// # Arguments
    ///
    /// * `plaintext` plaintext to be encrypted
    /// * `ciphertext` buffer to be filled with ciphertext (can be the same
    ///		   the plaintext buffer)
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or AeadError on error
    pub fn enc_update(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), AeadError> {
        if self.aead_ctx.is_null() {
            return Err(AeadError::UninitializedContext);
        }
        if plaintext.len() != ciphertext.len() {
            return Err(AeadError::ProcessingError);
        }

        let result = unsafe {
            leancrypto::lc_aead_enc_update(
                self.aead_ctx,
                plaintext.as_ptr(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
            )
        };

        if result < 0 {
            return Err(AeadError::ProcessingError);
        }

        Ok(())
    }

    /// AEAD stream mode encryption finalization - calculation of tag
    ///
    /// # Arguments
    ///
    /// * `tag` Buffer to be filled with the generated tag
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or AeadError on error
    pub fn enc_final(
        &mut self,
        tag: &mut [u8],
    ) -> Result<(), AeadError> {
        if self.aead_ctx.is_null() {
            return Err(AeadError::UninitializedContext);
        }

        let result = unsafe {
            leancrypto::lc_aead_enc_final(
                self.aead_ctx,
                tag.as_mut_ptr(),
                tag.len(),
            )
        };

        if result < 0 {
            return Err(AeadError::ProcessingError);
        }

        Ok(())
    }

    /// AEAD one-shot decrypt
    ///
    /// # Arguments
    ///
    /// * `ciphertext` ciphertext to be decrypted
    /// * `plaintext` buffer to be filled with plaintext (can be the same
    ///		  the plaintext buffer)
    /// * `aad` AAD to be used for encryption
    /// * `tag` Buffer to be filled with the generated tag
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or AeadError on error
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
        aad: &[u8],
        tag: &[u8],
    ) -> Result<(), AeadError> {
        if self.aead_ctx.is_null() {
            return Err(AeadError::UninitializedContext);
        }
        if ciphertext.len() > 0 && plaintext.len() != ciphertext.len() {
            return Err(AeadError::ProcessingError);
        }

        /*
         * &[].as_ptr() returns 0x1 and not a NULL pointer
         */
        let mut ctptr = ciphertext.as_ptr();
        if ciphertext.len() == 0 {
            ctptr = ptr::null();
        }
        let mut ptptr = plaintext.as_mut_ptr();
        if ciphertext.len() == 0 {
            ptptr = ptr::null_mut();
        }
        let mut aadptr = aad.as_ptr();
        if aad.len() == 0 {
            aadptr = ptr::null();
        }

        let result = unsafe {
            leancrypto::lc_aead_decrypt(
                self.aead_ctx,
                ctptr,
                ptptr,
                plaintext.len(),
                aadptr,
                aad.len(),
                tag.as_ptr(),
                tag.len(),
            )
        };

        if result == -1 * (leancrypto::EBADMSG as i32) {
            return Err(AeadError::AuthenticationError);
        }
        if result < 0 {
            return Err(AeadError::ProcessingError);
        }

        Ok(())
    }

    /// AEAD initialize decrypt for stream operation
    ///
    /// # Arguments
    ///
    /// * `aad` AAD to be used for decryption
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or AeadError on error
    pub fn dec_init(
        &mut self,
        aad: &[u8],
    ) -> Result<(), AeadError> {
        if self.aead_ctx.is_null() {
            return Err(AeadError::UninitializedContext);
        }

        let result = unsafe {
            leancrypto::lc_aead_dec_init(self.aead_ctx, aad.as_ptr(), aad.len())
        };
        if result < 0 {
            return Err(AeadError::ProcessingError);
        }

        Ok(())
    }

    /// AEAD stream mode decryption of plaintext
    ///
    /// # Arguments
    ///
    /// * `ciphertext` ciphertext to be decrypted
    /// * `plaintext` buffer to be filled with plaintext (can be the same
    ///		  the plaintext buffer)
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or AeadError on error
    pub fn dec_update(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), AeadError> {
        if self.aead_ctx.is_null() {
            return Err(AeadError::UninitializedContext);
        }
        if plaintext.len() != ciphertext.len() {
            return Err(AeadError::ProcessingError);
        }

        let result = unsafe {
            leancrypto::lc_aead_dec_update(
                self.aead_ctx,
                ciphertext.as_ptr(),
                plaintext.as_mut_ptr(),
                plaintext.len(),
            )
        };
        if result < 0 {
            return Err(AeadError::ProcessingError);
        }

        Ok(())
    }

    /// AEAD stream mode decryption finalization - verification of tag
    ///
    /// # Arguments
    ///
    /// * `tag` Buffer to be filled with the generated tag
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or AeadError on error
    pub fn dec_final(
        &mut self,
        tag: &[u8],
    ) -> Result<(), AeadError> {
        if self.aead_ctx.is_null() {
            return Err(AeadError::UninitializedContext);
        }

        let result = unsafe {
            leancrypto::lc_aead_dec_final(
                self.aead_ctx,
                tag.as_ptr(),
                tag.len(),
            )
        };

        if result == -1 * (leancrypto::EBADMSG as i32) {
            return Err(AeadError::AuthenticationError);
        }
        if result < 0 {
            return Err(AeadError::ProcessingError);
        }

        Ok(())
    }
}

/// This ensures the buffer is always freed
/// regardless of when it goes out of scope
impl Drop for lcr_aead {
    fn drop(&mut self) {
        if !self.aead_ctx.is_null() {
            unsafe {
                leancrypto::lc_aead_zero_free(self.aead_ctx);
            }
        }
    }
}
