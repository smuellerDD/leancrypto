//! Key Encapsulation Mechanism (KEM) key exchange groups.
use leancrypto_sys::lcr_kyber::lcr_kyber;
use leancrypto_sys::lcr_kyber::lcr_kyber_type;
use leancrypto_sys::lcr_x25519::lcr_x25519;
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

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>
pub const X25519MLKEM768: &dyn SupportedKxGroup = &X25519HybridKxGroup(KxGroup {
    named_group: NamedGroup::X25519MLKEM768,
    algorithm_name: lcr_kyber_type::lcr_kyber_768,
});

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

		let (pk_slice, result) = kyber.get_pk();
		result.map_err(|e| Error::General(format!("lc:MLKEM-X25519: public key extraction error: {e}")))?;

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

#[derive(Debug, Copy, Clone)]
struct X25519HybridKxGroup(KxGroup);

struct X25519HybridKeyExchange {
	inner: KeyExchange,
	x25519_priv_key: lcr_x25519,
	x25519_pub_key: Vec<u8>,
}

impl SupportedKxGroup for X25519HybridKxGroup {
	fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
		let inner = self.0.start_internal()?;

		//ML-KEM
		//let pqc_pub_key = inner.pub_key();

		//X25519
		let mut x25519 = lcr_x25519::new();

		x25519.enable()
			.map_err(|e| Error::General(format!("lc:X25519: enabling error: {e}")))?;
		x25519.keypair().
			map_err(|e| Error::General(format!("lc:X25519: key pair generation error: {e}")))?;

		let x25519_pk_slice = match x25519.get_pk() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:X25519: pub key extraction error: {e}")))
			}
		};

		let x25519_pk = x25519_pk_slice.to_vec();

		Ok(
			Box::new(X25519HybridKeyExchange {
				inner,
				x25519_priv_key: x25519,
				x25519_pub_key: x25519_pk,
			}) as Box<dyn ActiveKeyExchange>)
	}

	fn name(&self) -> NamedGroup {
		self.0.named_group
	}

	fn usable_for_version(&self, version: ProtocolVersion) -> bool {
		self.0.usable_for_version(version)
	}

	fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
		None
	}

	fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, Error> {
		self.0.start_and_complete(peer_pub_key)
	}

	fn fips(&self) -> bool {
		crate::fips::enabled()
	}
}

impl ActiveKeyExchange for X25519HybridKeyExchange {
	fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
		//TODO is this only the Kyber CT or the CT || X25519 Pubkey?
		Box::new(self.inner).complete(peer_pub_key)
	}

	fn pub_key(&self) -> &[u8] {
		//TODO is this only the Kyber CT or the CT || X25519 Pubkey?
		&self.inner.pub_key
	}

	fn group(&self) -> NamedGroup {
		self.inner.group.named_group
	}

	fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
		Some((NamedGroup::X25519, &self.x25519_pub_key))
	}

	fn complete_hybrid_component(
		self: Box<Self>,
		peer_pub_key: &[u8],
	) -> Result<SharedSecret, Error> {
		let mut x25519 = self.x25519_priv_key;

		let result = x25519.pk_remote_load(peer_pub_key);
		result.map_err(|e| Error::General(format!("lc:MLKEM-X25519: loading remote pub key error: {e}")))?;

		x25519.shared_secret().
			map_err(|e| Error::General(format!("lc:MLKEM-X25519: shared secret generation error: {e}")))?;

		let ss_slice = match x25519.get_ss() {
			Ok(ret) => ret,
			Err(e) => {
				return Err(Error::General(format!("lc:MLKEM-X25519: shared secret extraction error: {e}")))
			}
		};

		let ss = ss_slice.to_vec();
		Ok(SharedSecret::from(ss.as_slice()))
	}
}
