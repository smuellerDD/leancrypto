use leancrypto_sys::lcr_hmac::lcr_hmac;
use leancrypto_sys::lcr_hmac::lcr_hmac_key;
use leancrypto_sys::lcr_hmac::lcr_hmac_type;
use rustls::crypto;
use rustls::crypto::hmac::{Key, Tag};
use rustls::{Error};

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
	fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
		let mut hmac_key = lcr_hmac_key::new(self.0);
		let _ = hmac_key.init(key).
			map_err(|e| Error::General(format!("lc:HMAC: initializtion error: {e}")));

		Box::new(HmacKey {
			key: hmac_key,
			hash: self.0
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
	fn sign(&self, data: &[&[u8]]) -> Tag {
		self.sign_concat(&[], data, &[])
	}

	fn sign_concat(
		&self,
		first: &[u8],
		middle: &[&[u8]],
		last: &[u8]
	) -> Tag {
		let mut hmac = lcr_hmac::new(self.hash);

		let _ = hmac.init_with_hmac_key(&self.key).
			map_err(|e| Error::General(format!("lc:HMAC: initializtion error: {e}")));

		let _ = hmac.update(first).
			map_err(|e| Error::General(format!("lc:HMAC: update error: {e}")));
		for d in middle {
			let _ = hmac.update(d).
				map_err(|e| Error::General(format!("lc:HMAC: update error: {e}")));
		}
		let _ = hmac.update(last).
			map_err(|e| Error::General(format!("lc:HMAC: update error: {e}")));

		let mut mac = vec![0u8; hmac.digestsize()];
		let _ = hmac.fini(&mut mac).
			map_err(|e| Error::General(format!("lc:HMAC: finalization error: {e}")));

		crypto::hmac::Tag::new(mac.as_ref())
	}

	fn tag_len(&self) -> usize {
		let mut hmac = lcr_hmac::new(self.hash);
		hmac.digestsize()
	}
}
