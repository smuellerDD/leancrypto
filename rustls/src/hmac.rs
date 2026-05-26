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

use leancrypto_sys::lcr_hmac::{lcr_hmac, lcr_hmac_key, lcr_hmac_type};
use rustls::Error;
use rustls::crypto;
use rustls::crypto::hmac::{Key, Tag};

#[allow(dead_code)]
pub(crate) static HMAC_SHA256: Hmac = Hmac(lcr_hmac_type::lcr_sha2_256);
#[allow(dead_code)]
pub(crate) static HMAC_SHA384: Hmac = Hmac(lcr_hmac_type::lcr_sha2_384);
#[allow(dead_code)] // Only used for TLS 1.2 prf test, and aws-lc-rs HPKE suites.
pub(crate) static HMAC_SHA512: Hmac = Hmac(lcr_hmac_type::lcr_sha2_512);

pub(crate) struct Hmac(pub lcr_hmac_type);

struct HmacKey {
    key: lcr_hmac_key,
    hash: lcr_hmac_type,
}

impl rustls::crypto::hmac::Hmac for Hmac {
    fn with_key(
        &self,
        key: &[u8],
    ) -> Box<dyn Key> {
        let mut hmac_key = lcr_hmac_key::new(self.0);
        let _ = hmac_key.init(key).map_err(|e| {
            Error::General(format!("lc:HMAC: initializtion error: {e}"))
        });

        Box::new(HmacKey {
            key: hmac_key,
            hash: self.0,
        })
    }

    fn hash_output_len(&self) -> usize {
        let mut hmac = lcr_hmac::new(self.0);
        hmac.digestsize()
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl Key for HmacKey {
    fn sign(
        &self,
        data: &[&[u8]],
    ) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    fn sign_concat(
        &self,
        first: &[u8],
        middle: &[&[u8]],
        last: &[u8],
    ) -> Tag {
        let mut hmac = lcr_hmac::new(self.hash);

        let _ = hmac.init_with_hmac_key(&self.key).map_err(|e| {
            Error::General(format!("lc:HMAC: initializtion error: {e}"))
        });

        let _ = hmac
            .update(first)
            .map_err(|e| Error::General(format!("lc:HMAC: update error: {e}")));
        for d in middle {
            let _ = hmac.update(d).map_err(|e| {
                Error::General(format!("lc:HMAC: update error: {e}"))
            });
        }
        let _ = hmac
            .update(last)
            .map_err(|e| Error::General(format!("lc:HMAC: update error: {e}")));

        let mut mac = vec![0u8; hmac.digestsize()];
        let _ = hmac.fini(&mut mac).map_err(|e| {
            Error::General(format!("lc:HMAC: finalization error: {e}"))
        });

        crypto::hmac::Tag::new(mac.as_ref())
    }

    fn tag_len(&self) -> usize {
        let mut hmac = lcr_hmac::new(self.hash);
        hmac.digestsize()
    }
}
