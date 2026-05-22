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

use leancrypto_sys::lcr_x25519::lcr_x25519;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};

/// `KXGroup`` for X25519
#[derive(Debug)]
struct X25519KxGroup {}

struct X25519KeyExchange {
	private_key: lcr_x25519,
	public_key: Vec<u8>,
}

/// X25519 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
pub const X25519: &dyn SupportedKxGroup = &X25519KxGroup {};

impl SupportedKxGroup for X25519KxGroup {
	fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
		let mut x25519 = lcr_x25519::new();

		x25519.enable().
			map_err(|e| Error::General(format!("lc:X25519: enabling algorithm error:  {e}")))?;

		x25519.keypair().
			map_err(|e| Error::General(format!("lc:X25519: key pair generation error: {e}")))?;

		let pk_slice = match x25519.get_pk() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:X25519: pub key extraction error: {e}")))
			}
		};
		let public_key = pk_slice.to_vec();

		Ok(Box::new(X25519KeyExchange {
			private_key: x25519,
			public_key: public_key,
		}) as Box<dyn ActiveKeyExchange>)
	}

	fn name(&self) -> NamedGroup {
		NamedGroup::X25519
	}
}

impl ActiveKeyExchange for X25519KeyExchange {
	fn complete(
		self: Box<Self>,
		peer_pub_key: &[u8]
	) -> Result<SharedSecret, Error> {
		let mut x25519 = self.private_key;

		/* import remote public key */
		x25519.pk_remote_load(peer_pub_key).
			map_err(|e| Error::General(format!("lc:X25519: loading remote pub key error: {e}")))?;

		/* generate shared secret */
		x25519.shared_secret().
			map_err(|e| Error::General(format!("lc:X25519: shared secret generation error: {e}")))?;

		/* Export shared secret */
		let ss_slice = match x25519.get_ss() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:X25519: shared secret extraction error: {e}")))
			}
		};
		let ss = ss_slice.to_vec();

		Ok(SharedSecret::from(ss.as_slice()))
	}

	fn pub_key(&self) -> &[u8] {
		&self.public_key
	}

	fn group(&self) -> NamedGroup {
		NamedGroup::X25519
	}
}

#[cfg(test)]
mod test {
	use rustls::crypto::ActiveKeyExchange;

	use super::X25519KeyExchange;

	#[test]
	fn x25519() {
		let test_set = wycheproof::xdh::TestSet::load(wycheproof::xdh::TestName::X25519).unwrap();
		for test_group in &test_set.test_groups {
			for test in &test_group.tests {
				let mut x25519 = leancrypto_sys::lcr_x25519::lcr_x25519::new();
				let result = x25519.enable();
				assert_eq!(result, Ok(()));

				let _ = x25519.sk_load(&test.private_key);
				let kx = X25519KeyExchange {
					private_key: x25519,
					public_key: Vec::new(),
				};

				let res = Box::new(kx).complete(&test.public_key);

				match res {
					Ok(sharedsecret) => {
						assert_eq!(
							sharedsecret.secret_bytes(),
							&test.shared_secret[..],
							"Derived incorrect secret: {:?}",
							test
						);
					}
					Err(e) => {
						panic!("Test failed: {:?}. Error {:?}", test, e);
					}
				}
			}
		}
	}
}
