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

//! Key Encapsulation Mechanism (KEM) key exchange groups.
use leancrypto_sys::lcr_kyber::{ lcr_kyber, lcr_kyber_type };
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, ProtocolVersion};

/// This is the [MLKEM] key exchange.
///
/// ML-KEM-768
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement
pub const MLKEM768: &dyn SupportedKxGroup = &KxGroup {
	named_group: NamedGroup::MLKEM768,
	algorithm_name: lcr_kyber_type::lcr_kyber_768,
};

/// This is the [MLKEM] key exchange.
///
/// ML-KEM-1024
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement
pub const MLKEM1024: &dyn SupportedKxGroup = &KxGroup {
	named_group: NamedGroup::MLKEM1024,
	algorithm_name: lcr_kyber_type::lcr_kyber_1024,
};

/// A key exchange group based on a key encapsulation mechanism.
#[derive(Debug, Copy, Clone)]
struct KxGroup {
	named_group: NamedGroup,
	algorithm_name: lcr_kyber_type,
}

struct KeyExchange {
	priv_key: lcr_kyber,
	pub_key: Vec<u8>,
	group: KxGroup,
}

impl KxGroup {
	/// [KxGroup::start] but returns a concrete `KeyExchange` instead of a trait object.
	fn start_internal(&self) -> Result<KeyExchange, Error> {
		let mut kyber = lcr_kyber::new();

		/*
		 * Generate the ephemeral ML-KEM key pairs.
		 */
		kyber.keypair(self.algorithm_name).
			map_err(|e| Error::General(format!("lc:MLKEM: key pair generation error: {e}")))?;

		/*
		 * Extract the public key
		 */
		let pk_slice = match kyber.get_pk() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM: public key extraction error: {e}")))
			}
		};
		let public_key = pk_slice.to_vec();

		Ok(KeyExchange {
			priv_key: kyber,
			pub_key: public_key,
			group: *self,
		})
	}
}

impl SupportedKxGroup for KxGroup {
	fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
		self.start_internal()
		.map(|kx| Box::new(kx) as Box<dyn ActiveKeyExchange>)
	}

	fn name(&self) -> NamedGroup {
		self.named_group
	}

	fn usable_for_version(&self, version: ProtocolVersion) -> bool {
		version == ProtocolVersion::TLSv1_3
	}

	fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
		None
	}

	/*
	 * Start the key establishment operation - initiator side
	 */
	fn start_and_complete(
		&self,
		peer_pub_key: &[u8],
	) -> Result<rustls::crypto::CompletedKeyExchange, Error> {
		let mut kyber = lcr_kyber::new();

		/*
		 * Load the local public key data
		 */
		kyber.pk_load(peer_pub_key).
			map_err(|e| Error::General(format!("lc:MLKEM: loading local pub key error: {e}")))?;

		/*
		 * Generate the actual key establishment data sent to the peer.
		 */
		kyber.encapsulate().
			map_err(|e| Error::General(format!("lc:MLKEM: encapsulation error: {e}")))?;

		/*
		 * Get the generated shared secret data.
		 */
		let ct_slice = match kyber.get_ct() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM: ciphertext extraction error: {e}")))
			}
		};
		let ct = ct_slice.to_vec();

		let ss_slice = match kyber.get_ss() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM shared secret extraction error: {e}")))
			}
		};

		Ok(CompletedKeyExchange {
			group: self.named_group,
			pub_key: ct,
			secret: SharedSecret::from(ss_slice),
		})
	}

	fn fips(&self) -> bool {
		crate::fips::enabled()
	}
}

impl ActiveKeyExchange for KeyExchange {

	/*
	 * Complete the key establishment operation - receiver side
	 */
	fn complete(
		self: Box<Self>,
		peer_pub_key: &[u8]
	) -> Result<SharedSecret, Error> {
		let mut kyber = self.priv_key;

		/*
		 * Load the received remote key agreement data into context.
		 */
		kyber.ct_load(peer_pub_key).
			map_err(|e| Error::General(format!("lc:MLKEM: loading ciphertext error: {e}")))?;

		/*
		 * Perform the decapsulation of the received data to obtain the
		 * shared secret.
		 */
		kyber.decapsulate().
			map_err(|e| Error::General(format!("lc:MLKEM: decapsulation error: {e}")))?;

		/*
		 * Extract the just calculated shared secret.
		 */
		let ss_slice = match kyber.get_ss() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM: shared secret extraction error: {e}")))
			}
		};

		Ok(SharedSecret::from(ss_slice))
	}

	fn pub_key(&self) -> &[u8] {
		&self.pub_key
	}

	fn group(&self) -> NamedGroup {
		self.group.named_group
	}
}
