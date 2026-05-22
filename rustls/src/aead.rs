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

use leancrypto_sys::lcr_aead::lcr_aead;
use leancrypto_sys::lcr_aead::lcr_aead_type;
use rustls::Error;
use rustls::crypto::cipher::NONCE_LEN;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Algorithm {
	Aes128Gcm,
	Aes256Gcm,
	#[cfg(not(feature = "fips"))]
	ChaCha20Poly1305,
}

/// The tag length is 16 bytes for all supported ciphers.
pub(crate) const TAG_LEN: usize = 16;

impl Algorithm {
	fn leancrypto_cipher(self) -> lcr_aead_type {
		match self {
			Self::Aes128Gcm => lcr_aead_type::lcr_aes_gcm,
			Self::Aes256Gcm => lcr_aead_type::lcr_aes_gcm,
			#[cfg(not(feature = "fips"))]
			Self::ChaCha20Poly1305 => lcr_aead_type::lcr_chacha20_poly1305,
		}
	}

	pub(crate) fn key_size(self) -> usize {
		match self {
			Self::Aes128Gcm => 16,
			Self::Aes256Gcm => 32,
			#[cfg(not(feature = "fips"))]
			Self::ChaCha20Poly1305 => 32,
		}
	}

	/// Encrypts data in place and returns the tag.
	pub(crate) fn encrypt_in_place(
		self,
		key: &[u8],
		nonce: &[u8; NONCE_LEN],
		aad: &[u8],
		data: &mut [u8],
	) -> Result<[u8; TAG_LEN], Error> {
		// One-shot encrypt
		let mut aead = lcr_aead::new(self.leancrypto_cipher());
		aead.setkey(key, nonce).
			map_err(|e| Error::General(format!("lc:AEAD: setkey error: {e}")))?;

		let mut tag = [0u8; TAG_LEN];

		aead.encrypt(&[], data, aad, &mut tag).
			map_err(|e| Error::General(format!("lc:AEAD: encryption error: {e}")))?;
		Ok(tag)
	}

	/// Decrypts in place, verifying the tag and returns the length of the
	/// plaintext.
	/// The data is expected to be in the form of [ciphertext, tag].
	pub(crate) fn decrypt_in_place(
		self,
		key: &[u8],
		nonce: &[u8; NONCE_LEN],
		aad: &[u8],
		data: &mut [u8],
	) -> Result<usize, Error> {
		let payload_len = data.len();
		if payload_len < TAG_LEN {
			return Err(Error::DecryptError);
		}
		let plaintext_len = payload_len - TAG_LEN;
		let (ciphertext, tag) = data.split_at_mut(plaintext_len);

		// One-shot decrypt
		let mut aead = lcr_aead::new(self.leancrypto_cipher());
		aead.setkey(key, nonce).
			map_err(|e| Error::General(format!("lc:AEAD: setkey error: {e}")))?;
		aead.decrypt(&[], ciphertext, aad, tag).
			map_err(|e| Error::General(format!("lc:AEAD: decryption error: {e}")))?;

		Ok(plaintext_len)
	}
}

#[cfg(test)]
mod test {
	use wycheproof::{TestResult, aead::TestFlag};

	fn test_aead(alg: super::Algorithm) {
		let test_name = match alg {
			super::Algorithm::Aes128Gcm | super::Algorithm::Aes256Gcm => {
				wycheproof::aead::TestName::AesGcm
			}
			#[cfg(not(feature = "fips"))]
			super::Algorithm::ChaCha20Poly1305 => wycheproof::aead::TestName::ChaCha20Poly1305,
		};
		let test_set = wycheproof::aead::TestSet::load(test_name).unwrap();

		let mut counter = 0;

		for group in test_set
			.test_groups
			.into_iter()
			.filter(|group| group.key_size == 8 * alg.key_size())
			.filter(|group| group.nonce_size == 96)
		{
			for test in group.tests {
				counter += 1;
				let mut iv_bytes = [0u8; 12];
				iv_bytes.copy_from_slice(&test.nonce[0..12]);

				let mut actual_ciphertext = test.pt.to_vec();
				let actual_tag = alg
					.encrypt_in_place(&test.key, &iv_bytes, &test.aad, &mut actual_ciphertext)
					.unwrap();

				match &test.result {
					TestResult::Invalid => {
						if test.flags.iter().any(|flag| *flag == TestFlag::ModifiedTag) {
							assert_ne!(
								actual_tag[..],
								test.tag[..],
								"Expected incorrect tag. Id {}: {}",
								test.tc_id,
								test.comment
							);
						}
					}
					TestResult::Valid | TestResult::Acceptable => {
						assert_eq!(
							actual_ciphertext[..],
							test.ct[..],
							"Test case failed {}: {}",
							test.tc_id,
							test.comment
						);
						assert_eq!(
							actual_tag[..],
							test.tag[..],
							"Test case failed {}: {}",
							test.tc_id,
							test.comment
						);
					}
				}

				let mut data = test.ct.to_vec();
				data.extend_from_slice(&test.tag);
				let res = alg.decrypt_in_place(&test.key, &iv_bytes, &test.aad, &mut data);

				match &test.result {
					TestResult::Invalid => {
						assert!(res.is_err());
					}
					TestResult::Valid | TestResult::Acceptable => {
						assert_eq!(res, Ok(test.pt.len()));
						assert_eq!(&data[..res.unwrap()], &test.pt[..]);
					}
				}
			}
		}

		// Ensure we ran some tests.
		assert!(counter > 50);
	}

	#[test]
	fn test_aes_128() {
		test_aead(super::Algorithm::Aes128Gcm);
	}

	#[test]
	fn test_aes_256() {
		test_aead(super::Algorithm::Aes256Gcm);
	}

	#[cfg(not(feature = "fips"))]
	#[test]
	fn test_chacha() {
		test_aead(super::Algorithm::ChaCha20Poly1305);
	}
}
