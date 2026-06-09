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

use crate::error::X509Error;
use crate::ffi::leancrypto;
use std::ffi::CString;
use std::fmt;
use std::ptr;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug)]
pub enum lcr_x509_key_type {
    lcr_unknown,
    lcr_dilithium_44,
    lcr_dilithium_65,
    lcr_dilithium_87,
    lcr_dilithium_44_ed25519,
    lcr_dilithium_65_ed25519,
    lcr_dilithium_87_ed448,
    lcr_sphincs_shake_256s,
    lcr_sphincs_shake_256f,
    lcr_sphincs_shake_192s,
    lcr_sphincs_shake_192f,
    lcr_sphincs_shake_128s,
    lcr_sphincs_shake_128f,
    lcr_ed25519,
    lcr_ed448,
}

#[derive(Debug)]
pub struct lcr_x509_key {
    /// Key type
    key_type: lcr_x509_key_type,

    /// Buffer memory holding the actual public/private key
    x509_key_data: *mut leancrypto::lc_x509_key_data,

    /// Secret key information
    pkcs8_sk: leancrypto::lc_pkcs8_message,
    sk_der_key: Vec<u8>,
    has_sk: bool,

    /// Public key information
    x509_cert: leancrypto::lc_x509_certificate,
    cert_der: Vec<u8>,
    has_pk: bool,
    has_certificate: bool,

    subject_email: Vec<CString>,
    subject_cn: Vec<CString>,
    subject_ou: Vec<CString>,
    subject_o: Vec<CString>,
    subject_st: Vec<CString>,
    subject_c: Vec<CString>,

    issuer_email: Vec<CString>,
    issuer_cn: Vec<CString>,
    issuer_ou: Vec<CString>,
    issuer_o: Vec<CString>,
    issuer_st: Vec<CString>,
    issuer_c: Vec<CString>,

    san_ip: Vec<u8>,
    san_email: Vec<CString>,
    san_dns: Vec<CString>,
    skid: Vec<u8>,
    akid: Vec<u8>,
    serial: Vec<u8>,

    eku: Vec<CString>,
    keyusage: Vec<CString>,
}

#[allow(dead_code)]
impl lcr_x509_key {
    pub fn new() -> Self {
        lcr_x509_key {
            key_type: lcr_x509_key_type::lcr_unknown,
            x509_key_data: ptr::null_mut(),

            pkcs8_sk: unsafe { std::mem::zeroed() },
            sk_der_key: Vec::new(),
            has_sk: false,

            x509_cert: unsafe { std::mem::zeroed() },
            cert_der: Vec::new(),
            has_pk: false,
            has_certificate: false,

            subject_email: Vec::new(),
            subject_cn: Vec::new(),
            subject_ou: Vec::new(),
            subject_o: Vec::new(),
            subject_st: Vec::new(),
            subject_c: Vec::new(),

            issuer_email: Vec::new(),
            issuer_cn: Vec::new(),
            issuer_ou: Vec::new(),
            issuer_o: Vec::new(),
            issuer_st: Vec::new(),
            issuer_c: Vec::new(),

            san_ip: Vec::new(),
            san_email: Vec::new(),
            san_dns: Vec::new(),
            skid: Vec::new(),
            akid: Vec::new(),
            serial: Vec::new(),

            eku: Vec::new(),
            keyusage: Vec::new(),
        }
    }

    pub fn key_type(&self) -> lcr_x509_key_type {
        self.key_type
    }

    pub fn get_self(&self) -> &lcr_x509_key {
        return self;
    }

    /// Enable the ED25519 support in leancrypto (by default, it is disabled)
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn enable(&self) -> Result<(), X509Error> {
        let result =
            unsafe { leancrypto::lc_init(leancrypto::LC_INIT_NON_PQC_ENABLED) };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Allocate key data structure
    fn alloc_key_data(&mut self) -> Result<(), X509Error> {
        let mut result = 0;

        if self.x509_key_data.is_null() {
            /* Allocate the hash context */
            result = unsafe {
                leancrypto::lc_x509_keypair_data_alloc(
                    &mut self.x509_key_data,
                    0,
                )
            };
        }
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        result = unsafe {
            leancrypto::lc_pkcs8_set_privkey(
                &mut self.pkcs8_sk,
                self.x509_key_data,
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        Ok(())
    }

    /// Generate asymmetric key pair
    ///
    /// # Arguments
    ///
    /// * `lcr_x509_key_type` Asymmetric key pair to be generated
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn key_pair_generation(
        &mut self,
        key_type: lcr_x509_key_type,
    ) -> Result<(), X509Error> {
        self.alloc_key_data()?;

        self.key_type = key_type;

        let lcr_x509_key_type: u32 = match key_type {
            lcr_x509_key_type::lcr_dilithium_44 => {
                leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44
            }
            lcr_x509_key_type::lcr_dilithium_65 => {
                leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65
            }
            lcr_x509_key_type::lcr_dilithium_87 => {
                leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87
            }
            lcr_x509_key_type::lcr_dilithium_44_ed25519 => {
                leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44_ED25519
            }
            lcr_x509_key_type::lcr_dilithium_65_ed25519 => {
                leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65_ED25519
            }
            // lcr_x509_key_type::lcr_dilithium_87_ed25519 =>
            // 	leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87_ED25519,
            // lcr_x509_key_type::lcr_dilithium_44_ed448 =>
            // 	leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44_ED448,
            // lcr_x509_key_type::lcr_dilithium_65_ed448 =>
            // 	leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65_ED448,
            lcr_x509_key_type::lcr_dilithium_87_ed448 => {
                leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87_ED448
            }
            lcr_x509_key_type::lcr_sphincs_shake_256s => {
                leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_256S
            }
            lcr_x509_key_type::lcr_sphincs_shake_256f => {
                leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_256F
            }
            lcr_x509_key_type::lcr_sphincs_shake_192s => {
                leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_192S
            }
            lcr_x509_key_type::lcr_sphincs_shake_192f => {
                leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_192F
            }
            lcr_x509_key_type::lcr_sphincs_shake_128s => {
                leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_128S
            }
            lcr_x509_key_type::lcr_sphincs_shake_128f => {
                leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_128F
            }
            lcr_x509_key_type::lcr_ed25519 => {
                leancrypto::lc_sig_types_LC_SIG_ED25519
            }
            lcr_x509_key_type::lcr_ed448 => {
                leancrypto::lc_sig_types_LC_SIG_ED448
            }
            _ => 0,
        };

        let result = unsafe {
            leancrypto::lc_x509_keypair_gen(
                &mut self.x509_cert,
                self.x509_key_data,
                lcr_x509_key_type,
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        self.has_sk = true;
        self.has_pk = true;

        Ok(())
    }

    /// Generate PKCS#8 DER blob holding the private key
    ///
    /// See leancrypto C-API: lc_pkcs8_encode
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success holding the PKCS#8 DER buffer or X509Error
    ///   on error
    pub fn pkcs8_encode(&mut self) -> Result<&Vec<u8>, X509Error> {
        self.key_is_usable()?;

        let mut pkcs8_size: usize = 0;

        /* Get the length of the memory to allocate */
        let result = unsafe {
            leancrypto::lc_pkcs8_encode(
                &self.pkcs8_sk,
                ptr::null_mut(),
                &mut pkcs8_size,
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        self.sk_der_key = Vec::with_capacity(pkcs8_size);
        let orig_size = pkcs8_size;

        let result = unsafe {
            leancrypto::lc_pkcs8_encode(
                &self.pkcs8_sk,
                self.sk_der_key.as_mut_ptr(),
                &mut pkcs8_size,
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        /* Set vector to to consumed length */
        unsafe { self.sk_der_key.set_len(orig_size - pkcs8_size) }

        Ok(&self.sk_der_key)
    }

    /// Method for safe immutable access to public key
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the public key on success or X509Error on error
    pub fn get_pk(&mut self) -> Result<Vec<u8>, X509Error> {
        self.key_is_usable()?;

        let mut pk_size: usize = 0;

        /* Get the length of the memory to allocate */
        let result = unsafe {
            leancrypto::lc_x509_keypair_pk(
                self.x509_key_data,
                ptr::null_mut(),
                &mut pk_size,
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        let mut pk_der_key = Vec::with_capacity(pk_size);
        let orig_size = pk_size;

        let result = unsafe {
            leancrypto::lc_x509_keypair_pk(
                self.x509_key_data,
                pk_der_key.as_mut_ptr(),
                &mut pk_size,
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        /* Set vector to to consumed length */
        unsafe { pk_der_key.set_len(orig_size - pk_size) }

        Ok(pk_der_key)
    }

    /// Load private key formatted as PKCS8 DER blob
    ///
    /// Wrapper around pkcs8_decode
    ///
    /// NOTE that the caller must keep `signer` valid for as long as
    /// the returned data is valid.
    /// # Arguments
    ///
    /// * `sk_der_key` buffer with DER secret key
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn pkcs8_decode(
        &mut self,
        sk_der_key: &[u8],
    ) -> Result<(), X509Error> {
        /*
         * Copy the DER blob into local storage as the pkcs8_sk is only
         * set of pointers into the DER structure.
         */
        self.sk_der_key = Vec::from(sk_der_key);

        self.alloc_key_data()?;

        let result = unsafe {
            leancrypto::lc_pkcs8_decode(
                &mut self.pkcs8_sk,
                self.sk_der_key.as_ptr(),
                self.sk_der_key.len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        let mut key_type: u32 = 0;
        let result = unsafe {
            leancrypto::lc_pkcs8_key_type(&mut key_type, &self.pkcs8_sk)
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        self.key_type = match key_type {
            leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44 => {
                lcr_x509_key_type::lcr_dilithium_44
            }
            leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65 => {
                lcr_x509_key_type::lcr_dilithium_65
            }
            leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87 => {
                lcr_x509_key_type::lcr_dilithium_87
            }
            leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44_ED25519 => {
                lcr_x509_key_type::lcr_dilithium_44_ed25519
            }
            leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65_ED25519 => {
                lcr_x509_key_type::lcr_dilithium_65_ed25519
            }
            // leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87_ED25519 =>
            //	lcr_x509_key_type::lcr_dilithium_87_ed25519,
            // leancrypto::lc_sig_types_LC_SIG_DILITHIUM_44_ED448 =>
            //	lcr_x509_key_type::lcr_dilithium_44_ed448,
            // leancrypto::lc_sig_types_LC_SIG_DILITHIUM_65_ED448 =>
            //	lcr_x509_key_type::lcr_dilithium_65_ed448,
            leancrypto::lc_sig_types_LC_SIG_DILITHIUM_87_ED448 => {
                lcr_x509_key_type::lcr_dilithium_87_ed448
            }
            leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_256S => {
                lcr_x509_key_type::lcr_sphincs_shake_256s
            }
            leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_256F => {
                lcr_x509_key_type::lcr_sphincs_shake_256f
            }
            leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_192S => {
                lcr_x509_key_type::lcr_sphincs_shake_192s
            }
            leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_192F => {
                lcr_x509_key_type::lcr_sphincs_shake_192f
            }
            leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_128S => {
                lcr_x509_key_type::lcr_sphincs_shake_128s
            }
            leancrypto::lc_sig_types_LC_SIG_SPHINCS_SHAKE_128F => {
                lcr_x509_key_type::lcr_sphincs_shake_128f
            }
            leancrypto::lc_sig_types_LC_SIG_ED25519 => {
                lcr_x509_key_type::lcr_ed25519
            }
            leancrypto::lc_sig_types_LC_SIG_ED448 => {
                lcr_x509_key_type::lcr_ed448
            }
            _ => lcr_x509_key_type::lcr_unknown,
        };

        self.has_sk = true;
        Ok(())
    }

    /// Does the key object contain the secret key and is therefore usable?
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn key_is_usable(&self) -> Result<(), X509Error> {
        if self.has_sk == false {
            return Err(X509Error::UninitializedContext);
        }
        Ok(())
    }

    /// Method for safe immutable access to secret key
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the secret key on success or X509Error on error
    pub fn get_sk(&self) -> Result<leancrypto::lc_pkcs8_message, X509Error> {
        if !self.has_sk {
            return Err(X509Error::UninitializedContext);
        }
        Ok(self.pkcs8_sk)
    }

    /// Load a X.509 DER certificate and decode it
    ///
    /// See leancrypto C-API: lc_x509_cert_decode
    ///
    /// NOTE that the caller must keep `der_certificate` valid for as long as
    /// the returned data is valid.
    ///
    /// # Arguments
    ///
    /// * `der_certificate` buffer with DER formatted X.509 certificate
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the certificate key on success or X509Error on error
    pub fn cert_decode(
        &mut self,
        der_certificate: &[u8],
    ) -> Result<(), X509Error> {
        /*
         * Copy the DER blob into local storage as the pkcs8_sk is only
         * set of pointers into the DER structure.
         */
        self.cert_der = Vec::from(der_certificate);

        let result = unsafe {
            leancrypto::lc_x509_cert_decode(
                &mut self.x509_cert,
                self.cert_der.as_ptr(),
                self.cert_der.len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        self.has_pk = true;
        self.has_certificate = true;
        Ok(())
    }

    /// Does the key object contain the certificate and is therefore usable?
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_is_usable(&self) -> Result<(), X509Error> {
        if self.has_certificate == false {
            return Err(X509Error::UninitializedContext);
        }
        Ok(())
    }

    /// Method for safe immutable access the DER blob with the X.509
    /// certificate
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the certificate on success or X509Error on error
    pub fn get_cert(
        &self
    ) -> Result<leancrypto::lc_x509_certificate, X509Error> {
        if !self.has_certificate {
            return Err(X509Error::UninitializedContext);
        }
        Ok(self.x509_cert)
    }

    fn cert_configurable(&self) -> Result<(), X509Error> {
        if self.has_certificate {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 certificate signer
    ///
    /// See leancrypto C-API: lc_x509_cert_set_signer
    ///
    /// NOTE that the caller must keep `signer` valid for as long as
    /// the returned data is valid.
    ///
    /// # Arguments
    ///
    /// * `signer` Signer key
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_signer(
        &mut self,
        signer: &lcr_x509_key,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let result = unsafe {
            leancrypto::lc_x509_cert_set_signer(
                &mut self.x509_cert,
                signer.x509_key_data,
                &signer.x509_cert,
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 certificate extended key usage
    ///
    /// See leancrypto C-API: lc_x509_cert_set_eku
    ///
    /// # Arguments
    ///
    /// * `eku` String with extended key usage
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_eku(
        &mut self,
        eku: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(eku) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };

        self.eku.push(s);

        let s = self.eku.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_eku(&mut self.x509_cert, s.as_ptr())
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 certificate extended key usage based on integer
    ///
    /// See leancrypto C-API: lc_x509_cert_set_eku_val
    ///
    /// # Arguments
    ///
    /// * `eku` Integer with extended key usage
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_eku_val(
        &mut self,
        eku: u16,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let result = unsafe {
            leancrypto::lc_x509_cert_set_eku_val(&mut self.x509_cert, eku)
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 certificate key usage
    ///
    /// See leancrypto C-API: lc_x509_cert_set_keyusage
    ///
    /// # Arguments
    ///
    /// * `keyusage` String with key usage
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_keyusage(
        &mut self,
        keyusage: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(keyusage) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };

        self.keyusage.push(s);

        let s = self.keyusage.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_keyusage(
                &mut self.x509_cert,
                s.as_ptr(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 certificate key usage based on integer
    ///
    /// See leancrypto C-API: lc_x509_cert_set_keyusage_val
    ///
    /// # Arguments
    ///
    /// * `keyusage` Integer with key usage
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_keyusage_val(
        &mut self,
        keyusage: u16,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let result = unsafe {
            leancrypto::lc_x509_cert_set_keyusage_val(
                &mut self.x509_cert,
                keyusage,
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 certificate CA property
    ///
    /// See leancrypto C-API: lc_x509_cert_set_ca
    ///
    /// # Arguments
    ///
    /// * `keyusage` Integer with key usage
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_ca(&mut self) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let result =
            unsafe { leancrypto::lc_x509_cert_set_ca(&mut self.x509_cert) };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 set the signer's subject as certificate's issuer
    ///
    /// This call is intended as a final sanity check before a
    /// certificate_generation.
    ///
    /// See leancrypto C-API: lc_x509_cert_check_issuer_ca
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_check_issuer_ca(&mut self) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let result = unsafe {
            leancrypto::lc_x509_cert_check_issuer_ca(&mut self.x509_cert)
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 maximum path length
    ///
    /// See leancrypto C-API: lc_x509_cert_set_ca_pathlen
    ///
    /// # Arguments
    ///
    /// * `pathlen` Integer with the path length
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_ca_pathlen(
        &mut self,
        pathlen: u32,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let result = unsafe {
            leancrypto::lc_x509_cert_set_ca_pathlen(
                &mut self.x509_cert,
                pathlen,
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 email as SAN
    ///
    /// See leancrypto C-API: lc_x509_cert_set_san_email
    ///
    /// # Arguments
    ///
    /// * `email` string with email
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_san_email(
        &mut self,
        email: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(email) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.san_email.push(s);

        let s = self.san_email.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_san_email(
                &mut self.x509_cert,
                s.as_ptr(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 Full Qualified Domain Name as SAN
    ///
    /// See leancrypto C-API: lc_x509_cert_set_san_dns
    ///
    /// # Arguments
    ///
    /// * `dns` string with FQDN
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_san_dns(
        &mut self,
        dns: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(dns) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.san_dns.push(s);

        let s = self.san_dns.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_san_dns(
                &mut self.x509_cert,
                s.as_ptr(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 Full Qualified Domain Name as SAN
    ///
    /// See leancrypto C-API: lc_x509_cert_set_san_ip
    ///
    /// # Arguments
    ///
    /// * `ip` buffer with binary representation of IP address
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_san_ip(
        &mut self,
        ip: &[u8],
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;
        self.san_ip.extend_from_slice(ip);

        let result = unsafe {
            leancrypto::lc_x509_cert_set_san_ip(
                &mut self.x509_cert,
                self.san_ip.as_ptr(),
                self.san_ip.len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 SKID
    ///
    /// See leancrypto C-API: lc_x509_cert_set_skid
    ///
    /// # Arguments
    ///
    /// * `skid` buffer with SKID
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_skid(
        &mut self,
        skid: &[u8],
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;
        self.skid.extend_from_slice(skid);

        let result = unsafe {
            leancrypto::lc_x509_cert_set_skid(
                &mut self.x509_cert,
                self.skid.as_ptr(),
                self.skid.len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 AKID
    ///
    /// See leancrypto C-API: lc_x509_cert_set_akid
    ///
    /// # Arguments
    ///
    /// * `akid` buffer with AKID
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_akid(
        &mut self,
        akid: &[u8],
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;
        self.akid.extend_from_slice(akid);

        let result = unsafe {
            leancrypto::lc_x509_cert_set_akid(
                &mut self.x509_cert,
                self.akid.as_ptr(),
                self.akid.len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 validity time - start time
    ///
    /// See leancrypto C-API: lc_x509_cert_set_valid_from
    ///
    /// # Arguments
    ///
    /// * `time` time since Epoch
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_valid_from(
        &mut self,
        time: i64,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let result = unsafe {
            leancrypto::lc_x509_cert_set_valid_from(&mut self.x509_cert, time)
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 validity time - end time
    ///
    /// See leancrypto C-API: lc_x509_cert_set_valid_to
    ///
    /// # Arguments
    ///
    /// * `time` time since Epoch
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_valid_to(
        &mut self,
        time: i64,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let result = unsafe {
            leancrypto::lc_x509_cert_set_valid_to(&mut self.x509_cert, time)
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 subject CN
    ///
    /// See leancrypto C-API: lc_x509_cert_set_subject_cn
    ///
    /// # Arguments
    ///
    /// * `cn` CN string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_subject_cn(
        &mut self,
        cn: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(cn) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.subject_cn.push(s);

        let s = self.subject_cn.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_subject_cn(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 subject email
    ///
    /// See leancrypto C-API: lc_x509_cert_set_subject_email
    ///
    /// # Arguments
    ///
    /// * `email` Email string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_subject_email(
        &mut self,
        email: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(email) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.subject_email.push(s);

        let s = self.subject_email.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_subject_email(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 subject OU
    ///
    /// See leancrypto C-API: lc_x509_cert_set_subject_ou
    ///
    /// # Arguments
    ///
    /// * `ou` OU string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_subject_ou(
        &mut self,
        ou: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(ou) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.subject_ou.push(s);

        let s = self.subject_ou.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_subject_ou(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 subject O
    ///
    /// See leancrypto C-API: lc_x509_cert_set_subject_o
    ///
    /// # Arguments
    ///
    /// * `o` O string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_subject_o(
        &mut self,
        o: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(o) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.subject_o.push(s);

        let s = self.subject_o.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_subject_o(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 subject ST
    ///
    /// See leancrypto C-API: lc_x509_cert_set_subject_st
    ///
    /// # Arguments
    ///
    /// * `st` ST string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_subject_st(
        &mut self,
        st: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(st) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.subject_st.push(s);

        let s = self.subject_st.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_subject_st(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 subject C
    ///
    /// See leancrypto C-API: lc_x509_cert_set_subject_c
    ///
    /// # Arguments
    ///
    /// * `c` C string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_subject_c(
        &mut self,
        c: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(c) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.subject_c.push(s);

        let s = self.subject_c.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_subject_c(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 issuer CN
    ///
    /// See leancrypto C-API: lc_x509_cert_set_issuer_cn
    ///
    /// # Arguments
    ///
    /// * `cn` CN string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_issuer_cn(
        &mut self,
        cn: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(cn) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.issuer_cn.push(s);

        let s = self.issuer_cn.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_issuer_cn(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 issuer email
    ///
    /// See leancrypto C-API: lc_x509_cert_set_issuer_email
    ///
    /// # Arguments
    ///
    /// * `email` Email string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_issuer_email(
        &mut self,
        email: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(email) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.issuer_email.push(s);

        let s = self.issuer_email.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_issuer_email(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 issuer OU
    ///
    /// See leancrypto C-API: lc_x509_cert_set_issuer_ou
    ///
    /// # Arguments
    ///
    /// * `ou` OU string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_issuer_ou(
        &mut self,
        ou: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(ou) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.issuer_ou.push(s);

        let s = self.issuer_ou.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_issuer_ou(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 issuer O
    ///
    /// See leancrypto C-API: lc_x509_cert_set_issuer_o
    ///
    /// # Arguments
    ///
    /// * `o` O string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_issuer_o(
        &mut self,
        o: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(o) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.issuer_o.push(s);

        let s = self.issuer_o.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_issuer_o(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 issuer ST
    ///
    /// See leancrypto C-API: lc_x509_cert_set_issuer_st
    ///
    /// # Arguments
    ///
    /// * `st` ST string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_issuer_st(
        &mut self,
        st: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(st) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.issuer_st.push(s);

        let s = self.issuer_st.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_issuer_st(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 issuer C
    ///
    /// See leancrypto C-API: lc_x509_cert_set_issuer_c
    ///
    /// # Arguments
    ///
    /// * `c` C string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_issuer_c(
        &mut self,
        c: &str,
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;

        let s = match CString::new(c) {
            Err(_) => return Err(X509Error::ProcessingError)?,
            Ok(res) => res,
        };
        self.issuer_c.push(s);

        let s = self.issuer_c.last().unwrap();
        let result = unsafe {
            leancrypto::lc_x509_cert_set_issuer_c(
                &mut self.x509_cert,
                s.as_ptr(),
                s.as_bytes().len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Set X.509 serial number
    ///
    /// See leancrypto C-API: lc_x509_cert_set_serial
    ///
    /// # Arguments
    ///
    /// * `serial` serial string
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn cert_set_serial(
        &mut self,
        serial: &[u8],
    ) -> Result<(), X509Error> {
        self.cert_configurable()?;
        self.serial.extend_from_slice(serial);

        let result = unsafe {
            leancrypto::lc_x509_cert_set_serial(
                &mut self.x509_cert,
                self.serial.as_ptr(),
                self.serial.len(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Generate a X.509 DER blob from the set certificate properties
    ///
    /// See leancrypto C-API: lc_x509_cert_encode
    ///
    /// # Returns
    ///
    /// * Returns Ok() with the certificate on success or X509Error on error
    pub fn cert_encode(&mut self) -> Result<&Vec<u8>, X509Error> {
        self.cert_configurable()?;
        self.key_is_usable()?;

        let mut cert_size: usize = 0;

        /* Get the length of the memory to allocate */
        let result = unsafe {
            leancrypto::lc_x509_cert_encode(
                &self.x509_cert,
                ptr::null_mut(),
                &mut cert_size,
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        self.cert_der = Vec::with_capacity(cert_size);
        let orig_size = cert_size;

        let result = unsafe {
            leancrypto::lc_x509_cert_encode(
                &self.x509_cert,
                self.cert_der.as_mut_ptr(),
                &mut cert_size,
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        /* Set vector to to consumed length */
        unsafe { self.cert_der.set_len(orig_size - cert_size) }

        self.has_certificate = true;

        Ok(&self.cert_der)
    }
}

/*
 * Sync and Send do not need a special consideration. Even though
 * lcr_x509_key::pkcs8_sk contains pointers, the pointers all to the buffer
 * lcr_x509_key::sk_der_key which is a private buffer. Therefore, the whole memory
 * and the pointers into it are managed and released jointly without any special
 * considerations.
 */
unsafe impl Sync for lcr_x509_key {}
unsafe impl Send for lcr_x509_key {}

impl fmt::Debug for leancrypto::lc_x509_certificate {
    fn fmt(
        &self,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        write!(f, "lc_x509_certificate")
    }
}

impl Drop for lcr_x509_key {
    fn drop(&mut self) {
        self.sk_der_key.zeroize();
        self.has_sk = false;
        unsafe {
            leancrypto::lc_x509_keypair_data_zero_free(self.x509_key_data)
        };

        self.cert_der.zeroize();
        self.has_pk = false;
        self.has_certificate = false;
    }
}

/// Leancrypto wrapper for the Leancrypto X.509 API
pub struct lcr_x509 {}

#[allow(dead_code)]
impl lcr_x509 {
    pub fn new() -> Self {
        lcr_x509 {}
    }

    /// Enable the ED25519 support in leancrypto (by default, it is disabled)
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn enable(&self) -> Result<(), X509Error> {
        let result =
            unsafe { leancrypto::lc_init(leancrypto::LC_INIT_NON_PQC_ENABLED) };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }
        Ok(())
    }

    /// Verify message
    ///
    /// The the publich key must be already loaded.
    ///
    /// # Arguments
    ///
    /// * `x509_key` public key to be used for verification
    /// * `signature` signature to be verified
    /// * `message` message to be verified
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn verify(
        &mut self,
        x509_key: &lcr_x509_key,
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), X509Error> {
        x509_key.cert_is_usable()?;

        let cert_res = x509_key.get_cert();
        let cert = match cert_res {
            Ok(cert_blob) => cert_blob,
            Err(error) => return Err(error),
        };

        let result = unsafe {
            leancrypto::lc_x509_signature_verify(
                signature.as_ptr(),
                signature.len(),
                &cert,
                message.as_ptr(),
                message.len(),
                ptr::null_mut(),
            )
        };
        if result < 0 {
            return Err(X509Error::VerifyError);
        }

        Ok(())
    }

    /// Verify another certificate with a signer
    ///
    /// The the publich key must be already loaded.
    ///
    /// # Arguments
    ///
    /// * `signer` signer certificate
    /// * `cert` certificate to be verified
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success or X509Error on error
    pub fn verify_certificate(
        &mut self,
        signer: &lcr_x509_key,
        cert: &lcr_x509_key,
    ) -> Result<(), X509Error> {
        signer.cert_is_usable()?;
        cert.cert_is_usable()?;

        Err(X509Error::UninitializedContext)
        //Ok(())
    }

    /// Sign message
    ///
    /// # Arguments
    ///
    /// * `x509_key` private key
    /// * `message` message to be signed
    ///
    /// # Returns
    ///
    /// * Returns Ok() on success with the signature buffer or X509Error on
    ///   error
    pub fn sign(
        &mut self,
        x509_key: &lcr_x509_key,
        message: &[u8],
    ) -> Result<Vec<u8>, X509Error> {
        let pkcs8_res = x509_key.get_sk();
        let pkcs8 = match pkcs8_res {
            Ok(pkcs8_blob) => pkcs8_blob,
            Err(error) => return Err(error),
        };

        let mut siglen = 0;
        let result = unsafe {
            leancrypto::lc_pkcs8_get_signature_size_from_sk(&mut siglen, &pkcs8)
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        let mut signature = vec![0; siglen];
        let result = unsafe {
            leancrypto::lc_pkcs8_signature_gen(
                signature.as_mut_ptr(),
                &mut siglen,
                &pkcs8,
                message.as_ptr(),
                message.len(),
                ptr::null_mut(),
            )
        };
        if result < 0 {
            return Err(X509Error::ProcessingError);
        }

        Ok(signature)
    }
}
