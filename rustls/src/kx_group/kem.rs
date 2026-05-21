//! Key Encapsulation Mechanism (KEM) key exchange groups.
use leancrypto_sys::lcr_kyber::lcr_kyber;
use leancrypto_sys::lcr_kyber::lcr_kyber_type;
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

		kyber.keypair(self.algorithm_name).
			map_err(|e| Error::General(format!("lc:MLKEM-X25519: key pair generation error: {e}")))?;

		let pk_slice = match kyber.get_pk() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM-X25519: public key extraction error: {e}")))
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

	fn start_and_complete(
		&self,
		peer_pub_key: &[u8],
	) -> Result<rustls::crypto::CompletedKeyExchange, Error> {
		let mut kyber = lcr_kyber::new();

		kyber.pk_load(peer_pub_key).
			map_err(|e| Error::General(format!("lc:MLKEM-X25519: loading local pub key error: {e}")))?;

		kyber.encapsulate().
			map_err(|e| Error::General(format!("lc:MLKEM-X25519: encapsulation error: {e}")))?;

		let ct_slice = match kyber.get_ct() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM-X25519: ciphertext extraction error: {e}")))
			}
		};
		let ct = ct_slice.to_vec();

		let ss_slice = match kyber.get_ss() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM-X25519 shared secret extraction error: {e}")))
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
	fn complete(
		self: Box<Self>,
		peer_pub_key: &[u8]
	) -> Result<SharedSecret, Error> {
		let mut kyber = self.priv_key;

		kyber.ct_load(peer_pub_key).
			map_err(|e| Error::General(format!("lc:MLKEM-X25519: loading ciphertext error: {e}")))?;

		kyber.decapsulate().
			map_err(|e| Error::General(format!("lc:MLKEM-X25519: decapsulation error: {e}")))?;

		let ss_slice = match kyber.get_ss() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM-X25519: shared secret extraction error: {e}")))
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
