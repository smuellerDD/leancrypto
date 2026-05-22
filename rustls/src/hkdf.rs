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

use crate::hmac::Hmac;
use leancrypto_sys::{
	lcr_hash::{ lcr_hash, lcr_hash_type },
	lcr_hmac::lcr_hmac_type,
	lcr_hkdf::lcr_hkdf
};
use leancrypto_sys::lcr_hash::lcr_hash_type as HashAlgorithm;

use rustls::crypto::hmac::{Hmac as _, Tag};
use rustls::crypto::tls13::{
	Hkdf as RustlsHkdf, HkdfExpander as RustlsHkdfExpander, OkmBlock,
	OutputLengthError,
};
use zeroize::Zeroize;

const MAX_DIGEST_SIZE: usize = leancrypto_sys::lcr_hash::LC_SHA_MAX_SIZE_DIGEST;

/// HKDF implementation using HMAC with the specified Hash Algorithm
pub(crate) struct Hkdf(pub(crate) HashAlgorithm);

struct HkdfExpander {
	private_key: [u8; MAX_DIGEST_SIZE],
	size: usize,
	hash: HashAlgorithm,
}

impl RustlsHkdf for Hkdf {
	fn extract_from_zero_ikm(
		&self,
		salt: Option<&[u8]>
	) -> Box<dyn RustlsHkdfExpander> {
		let mut hash = lcr_hash::new(self.0);
		let hash_size = hash.digestsize();
		let secret = [0u8; MAX_DIGEST_SIZE];
		self.extract_from_secret(salt, &secret[..hash_size])
	}

	fn extract_from_secret(
		&self,
		salt: Option<&[u8]>,
		secret: &[u8],
	) -> Box<dyn RustlsHkdfExpander> {
		let mut hash = lcr_hash::new(self.0);
		let hash_size = hash.digestsize();
		let mut private_key = [0u8; MAX_DIGEST_SIZE];
		let mut hkdf = lcr_hkdf::new(self.0);
		let _ = if let Some(salt) = salt {
			hkdf.extract_prk(&secret, &salt,
					 &mut private_key[..hash_size])
		} else {
			hkdf.extract_prk(&secret,
					 [0u8; MAX_DIGEST_SIZE][..hash_size].as_ref(),
					 &mut private_key[..hash_size])
		};

		Box::new(HkdfExpander {
			private_key,
			size: hash_size,
			hash: self.0,
		})
	}

	fn expander_for_okm(
		&self,
		okm: &OkmBlock
	) -> Box<dyn RustlsHkdfExpander> {
		let okm = okm.as_ref();
		let mut private_key = [0u8; MAX_DIGEST_SIZE];
		private_key[..okm.len()].copy_from_slice(okm);
		Box::new(HkdfExpander {
			private_key,
			size: okm.len(),
			hash: self.0,
		})
	}

	fn hmac_sign(
		&self,
		key: &OkmBlock,
		message: &[u8]
	) -> Tag {
		let hmac_type = match self.0 {
			lcr_hash_type::lcr_sha2_256 =>
				lcr_hmac_type::lcr_sha2_256,
			lcr_hash_type::lcr_sha2_384 =>
				lcr_hmac_type::lcr_sha2_384,
			lcr_hash_type::lcr_sha2_512 =>
				lcr_hmac_type::lcr_sha2_512,
			lcr_hash_type::lcr_sha3_256 =>
				lcr_hmac_type::lcr_sha3_256,
			lcr_hash_type::lcr_sha3_384 =>
				lcr_hmac_type::lcr_sha3_384,
			lcr_hash_type::lcr_sha3_512 =>
				lcr_hmac_type::lcr_sha3_512,
			_ => todo!()
		};
		Hmac(hmac_type).with_key(key.as_ref()).sign(&[message])
	}

	fn fips(&self) -> bool {
		crate::fips::enabled()
	}
}

impl RustlsHkdfExpander for HkdfExpander {
	fn expand_slice(
		&self,
		info: &[&[u8]],
		output: &mut [u8]
	) -> Result<(), OutputLengthError> {
		let mut hkdf = lcr_hkdf::new(self.hash);
		let total_len: usize = info.iter().map(|s| s.len()).sum();
		let mut result = Vec::with_capacity(total_len);

		for s in info {
			result.extend_from_slice(s);
		}

		hkdf.expand_prk(&result, &self.private_key[..self.size], output)
			.map_err(|_| OutputLengthError)?;
		Ok(())
	}

	fn expand_block(
		&self,
		info: &[&[u8]]
	) -> OkmBlock {
		let mut output = [0u8; MAX_DIGEST_SIZE];
		let len = self.hash_len();

		self.expand_slice(info, &mut output[..len])
			.expect("HDKF-Expand failed");
		OkmBlock::new(&output[..len])
	}

	fn hash_len(&self) -> usize {
		let mut hash = lcr_hash::new(self.hash);
		hash.digestsize()
	}
}

impl Drop for HkdfExpander {
	fn drop(&mut self) {
		self.private_key.zeroize();
	}
}

#[cfg(test)]
mod test {
	use rustls::crypto::tls13::Hkdf;
	use wycheproof::{TestResult, hkdf::TestName};

	fn test_hkdf(hkdf: &dyn Hkdf, test_name: TestName) {
		let test_set = wycheproof::hkdf::TestSet::load(test_name).unwrap();

		for test_group in test_set.test_groups {
			for test in test_group.tests {
				dbg!(&test);

				let prk_expander = hkdf.extract_from_secret(Some(&test.salt), &test.ikm);

				let mut okm = vec![0; test.size];
				let res = prk_expander.expand_slice(&[&test.info], &mut okm);

				match &test.result {
					TestResult::Acceptable | TestResult::Valid => {
						assert!(res.is_ok());
						assert_eq!(okm[..], test.okm[..], "Failed test: {}", test.comment);
					}
					TestResult::Invalid => {
						dbg!(&res);
						assert!(res.is_err(), "Failed test: {}", test.comment)
					}
				}
			}
		}
	}

	#[test]
	fn hkdf_sha256() {
		let suite = crate::cipher_suite::TLS13_AES_128_GCM_SHA256;
		let hkdf = suite.tls13().unwrap().hkdf_provider;
		test_hkdf(hkdf, TestName::HkdfSha256);
	}

	#[test]
	fn hkdf_sha384() {
		let suite = crate::cipher_suite::TLS13_AES_256_GCM_SHA384;
		let hkdf = suite.tls13().unwrap().hkdf_provider;
		test_hkdf(hkdf, TestName::HkdfSha384);
	}
}
