//! Key Encapsulation Mechanism (KEM) key exchange groups.
use leancrypto_sys::lcr_kyber::lcr_kyber;
use leancrypto_sys::lcr_kyber::lcr_kyber_type;
use leancrypto_sys::lcr_kyber_x25519::lcr_kyber_x25519;
use leancrypto_sys::lcr_kyber_x25519::lcr_kyber_x25519_type;
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

/******************************************************************************/

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>
pub const X25519MLKEM768: &dyn SupportedKxGroup = &KxGroupX25519 {
	named_group: NamedGroup::X25519MLKEM768,
	algorithm_name: lcr_kyber_x25519_type::lcr_kyber_768,
};

/// A key exchange group based on a key encapsulation mechanism.
#[derive(Debug, Copy, Clone)]
struct KxGroupX25519 {
	named_group: NamedGroup,
	algorithm_name: lcr_kyber_x25519_type,
}

struct KeyExchangeX25519 {
	priv_key: lcr_kyber_x25519,
	pub_key: Vec<u8>,
	group: KxGroupX25519,
}

impl KxGroupX25519 {
	/// [KxGroup::start] but returns a concrete `KeyExchange` instead of a trait object.
	fn start_internal(&self) -> Result<KeyExchangeX25519, Error> {
		let mut kyber_x25519 = lcr_kyber_x25519::new();

		kyber_x25519.keypair(self.algorithm_name).
			map_err(|e| Error::General(format!("lc:MLKEM-X25519: key pair generation error: {e}")))?;

		let (pk_slice, pk_x25519_slice) = match kyber_x25519.get_pk() {
			Ok((ret1, ret2)) => (ret1, ret2),
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM-X25519: public key extraction error: {e}")))
			}
		};
		let mut public_key = vec![];
		public_key.extend_from_slice(pk_slice);
		public_key.extend_from_slice(pk_x25519_slice);
		Ok(KeyExchangeX25519 {
			priv_key: kyber_x25519,
			pub_key: public_key,
			group: *self,
		})
	}
}

impl SupportedKxGroup for KxGroupX25519 {
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
		let mut kyber_x25519 = lcr_kyber_x25519::new();

		kyber_x25519.pk_load(&peer_pub_key[..peer_pub_key.len() - 32],
				     &peer_pub_key[peer_pub_key.len() - 32..]).
			map_err(|e| Error::General(format!("lc:MLKEM-X25519: loading local pub key error: {e}")))?;

		kyber_x25519.encapsulate().
			map_err(|e| Error::General(format!("lc:MLKEM-X25519: encapsulation error: {e}")))?;

		let (ct_slice, ct_x25519_slice) = match kyber_x25519.get_ct() {
			Ok((ret1, ret2)) => (ret1, ret2),
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM-X25519: ciphertext extraction error: {e}")))
			}
		};
		let mut ct = vec![];
		ct.extend_from_slice(ct_slice);
		ct.extend_from_slice(ct_x25519_slice);

		let (ss_slice, ss_x25519_slice) = match kyber_x25519.get_ss() {
			Ok((ret1, ret2)) => (ret1, ret2),
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM-X25519 shared secret extraction error: {e}")))
			}
		};
		let mut ss = vec![];
		ss.extend_from_slice(ss_slice);
		ss.extend_from_slice(ss_x25519_slice);

		Ok(CompletedKeyExchange {
			group: self.named_group,
			pub_key: ct,
			secret: SharedSecret::from(ss),
		})
	}

	fn fips(&self) -> bool {
		crate::fips::enabled()
	}
}

impl ActiveKeyExchange for KeyExchangeX25519 {
	fn complete(
		self: Box<Self>,
		peer_pub_key: &[u8]
	) -> Result<SharedSecret, Error> {
		let mut kyber_x25519 = self.priv_key;

		kyber_x25519.ct_load(&peer_pub_key[..peer_pub_key.len() - 32],
				     &peer_pub_key[peer_pub_key.len() - 32..]).
			map_err(|e| Error::General(format!("lc:MLKEM-X25519: loading ciphertext error: {e}")))?;

		kyber_x25519.decapsulate().
			map_err(|e| Error::General(format!("lc:MLKEM-X25519: decapsulation error: {e}")))?;

		let (ss_slice, ss_x25519_slice) = match kyber_x25519.get_ss() {
			Ok((ret1, ret2)) => (ret1, ret2),
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM-X25519 shared secret extraction error: {e}")))
			}
		};
		let mut ss = vec![];
		ss.extend_from_slice(ss_slice);
		ss.extend_from_slice(ss_x25519_slice);

		Ok(SharedSecret::from(ss))
	}

	fn pub_key(&self) -> &[u8] {
		&self.pub_key
	}

	fn group(&self) -> NamedGroup {
		self.group.named_group
	}
}
