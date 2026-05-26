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

use core::fmt;
use leancrypto_sys::{lcr_dilithium::lcr_dilithium, lcr_ed25519::lcr_ed25519};
use rustls::pki_types::alg_id;

use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{
        AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
    },
};

/// A [WebPkiSupportedAlgorithms] value defining the supported signature algorithms.
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms =
    WebPkiSupportedAlgorithms {
        all: &[ML_DSA_87, ML_DSA_65, ML_DSA_44, ED25519],
        mapping: &[
            (SignatureScheme::ML_DSA_87, &[ML_DSA_87]),
            (SignatureScheme::ML_DSA_65, &[ML_DSA_65]),
            (SignatureScheme::ML_DSA_44, &[ML_DSA_44]),
            #[cfg(feature = "nonpqc")]
            (SignatureScheme::ED25519, &[ED25519]),
        ],
    };

/// ML-DSA-87
pub(crate) static ML_DSA_87: &dyn SignatureVerificationAlgorithm =
    &LeancryptoAlgorithm {
        display_name: "ML_DSA_87",
        public_key_alg_id: alg_id::ML_DSA_87,
        signature_alg_id: alg_id::ML_DSA_87,
    };

/// ML-DSA-65
pub(crate) static ML_DSA_65: &dyn SignatureVerificationAlgorithm =
    &LeancryptoAlgorithm {
        display_name: "ML_DSA_65",
        public_key_alg_id: alg_id::ML_DSA_65,
        signature_alg_id: alg_id::ML_DSA_65,
    };

/// ML-DSA-44
pub(crate) static ML_DSA_44: &dyn SignatureVerificationAlgorithm =
    &LeancryptoAlgorithm {
        display_name: "ML_DSA_44",
        public_key_alg_id: alg_id::ML_DSA_44,
        signature_alg_id: alg_id::ML_DSA_44,
    };

/// ED25519
#[cfg(feature = "nonpqc")]
pub(crate) static ED25519: &dyn SignatureVerificationAlgorithm =
    &LeancryptoAlgorithm {
        display_name: "ED25519",
        public_key_alg_id: alg_id::ED25519,
        signature_alg_id: alg_id::ED25519,
    };

struct LeancryptoAlgorithm {
    display_name: &'static str,
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
}

impl fmt::Debug for LeancryptoAlgorithm {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(
            f,
            "rustls_leancrypto Signature Verification Algorithm: {}",
            self.display_name
        )
    }
}

impl SignatureVerificationAlgorithm for LeancryptoAlgorithm {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        match self.public_key_alg_id {
            alg_id::ML_DSA_44 | alg_id::ML_DSA_65 | alg_id::ML_DSA_87 => {
                let mut dilithium = lcr_dilithium::new();
                dilithium
                    .pk_load(&public_key)
                    .map_err(|_| InvalidSignature)?;
                dilithium
                    .sig_load(&signature)
                    .map_err(|_| InvalidSignature)?;
                dilithium.verify(&message).map_err(|_| InvalidSignature)?;
            }
            #[cfg(feature = "nonpqc")]
            alg_id::ED25519 => {
                let mut ed25519 = lcr_ed25519::new();
                ed25519.enable().map_err(|_| InvalidSignature)?;
                ed25519.pk_load(&public_key).map_err(|_| InvalidSignature)?;
                ed25519.sig_load(&signature).map_err(|_| InvalidSignature)?;
                ed25519.verify(&message).map_err(|_| InvalidSignature)?;
            }
            _ => todo!(),
        };

        Ok(())
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leancrypto_algorithm_debug() {
        #[cfg(feature = "nonpqc")]
        assert_eq!(
            format!("{:?}", ED25519),
            "rustls_leancrypto Signature Verification Algorithm: ED25519"
        );
        assert_eq!(
            format!("{:?}", ML_DSA_87),
            "rustls_leancrypto Signature Verification Algorithm: ML_DSA_87"
        );
        assert_eq!(
            format!("{:?}", ML_DSA_65),
            "rustls_leancrypto Signature Verification Algorithm: ML_DSA_65"
        );
        assert_eq!(
            format!("{:?}", ML_DSA_44),
            "rustls_leancrypto Signature Verification Algorithm: ML_DSA_44"
        );
    }
}
