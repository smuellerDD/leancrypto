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

use crate::aead;
use crate::hash::{SHA256, SHA384};
use crate::hkdf::Hkdf;
use crate::quic;
use leancrypto_sys::lcr_hash::lcr_hash_type;
use rustls::crypto::CipherSuiteCommon;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage,
    PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError,
    make_tls13_aad,
};

use rustls::{
    CipherSuite, ConnectionTrafficSecrets, Error, SupportedCipherSuite,
    Tls13CipherSuite,
};

/// The TLS1.3 ciphersuite `TLS_CHACHA20_POLY1305_SHA256`
#[cfg(not(feature = "fips"))]
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

#[cfg(not(feature = "fips"))]
pub static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: &Tls13CipherSuite =
    &Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &Hkdf(lcr_hash_type::lcr_sha2_256),
        aead_alg: &aead::Algorithm::ChaCha20Poly1305,
        quic: Some(&quic::KeyBuilder {
            packet_algo: aead::Algorithm::ChaCha20Poly1305,
            header_algo: quic::HeaderProtectionAlgorithm::ChaCha20,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
            confidentiality_limit: u64::MAX,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
            integrity_limit: 1 << 36,
        }),
    };

/// The TLS1.3 ciphersuite `TLS_AES_256_GCM_SHA384`
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &Hkdf(lcr_hash_type::lcr_sha2_384),
        aead_alg: &aead::Algorithm::Aes256Gcm,
        quic: Some(&quic::KeyBuilder {
            packet_algo: aead::Algorithm::Aes256Gcm,
            header_algo: quic::HeaderProtectionAlgorithm::Aes256,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
            confidentiality_limit: 1 << 23,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
            integrity_limit: 1 << 52,
        }),
    });

/// The TLS1.3 ciphersuite `TLS_AES_128_GCM_SHA256`
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_AES_128_GCM_SHA256_INTERNAL);

pub static TLS13_AES_128_GCM_SHA256_INTERNAL: &Tls13CipherSuite =
    &Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &Hkdf(lcr_hash_type::lcr_sha2_256),
        aead_alg: &aead::Algorithm::Aes128Gcm,
        quic: Some(&quic::KeyBuilder {
            packet_algo: aead::Algorithm::Aes128Gcm,
            header_algo: quic::HeaderProtectionAlgorithm::Aes128,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
            confidentiality_limit: 1 << 23,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
            integrity_limit: 1 << 52,
        }),
    };

struct Tls13Crypter {
    algo: aead::Algorithm,
    key: AeadKey,
    iv: Iv,
}

impl Tls13AeadAlgorithm for aead::Algorithm {
    fn encrypter(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Crypter {
            algo: *self,
            key,
            iv,
        })
    }

    fn decrypter(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Crypter {
            algo: *self,
            key,
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(match self {
            aead::Algorithm::Aes128Gcm => {
                ConnectionTrafficSecrets::Aes128Gcm { key, iv }
            }
            aead::Algorithm::Aes256Gcm => {
                ConnectionTrafficSecrets::Aes256Gcm { key, iv }
            }
            //#[cfg(all(chacha, not(feature = "fips")))]
            aead::Algorithm::ChaCha20Poly1305 => {
                ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
            }
        })
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl MessageEncrypter for Tls13Crypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let aad = make_tls13_aad(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let tag = self.algo.encrypt_in_place(
            self.key.as_ref(),
            &Nonce::new(&self.iv, seq).0,
            &aad,
            payload.as_mut(),
        )?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            rustls::ContentType::ApplicationData,
            // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
            // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
            rustls::ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(
        &self,
        payload_len: usize,
    ) -> usize {
        payload_len + 1 + aead::TAG_LEN
    }
}

impl MessageDecrypter for Tls13Crypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let aad = make_tls13_aad(payload.len());
        let plaintext_len = self.algo.decrypt_in_place(
            self.key.as_ref(),
            &Nonce::new(&self.iv, seq).0,
            &aad,
            payload.as_mut(),
        )?;
        // Remove the tag from the end of the payload.
        payload.truncate(plaintext_len);
        msg.into_tls13_unpadded_message()
    }
}
