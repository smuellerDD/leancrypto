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

/*
 * Code developed by using fragments from OpenSSL rustls and AWS rustls provider
 */
use crate::aead;
use leancrypto_sys::lcr_sym::{ lcr_sym, lcr_sym_type };
use rustls::{
	Error,
	crypto::cipher::{AeadKey, Iv, Nonce},
	quic,
};

pub(crate) struct KeyBuilder {
	pub(crate) packet_algo: aead::Algorithm,
	pub(crate) header_algo: HeaderProtectionAlgorithm,
	pub(crate) confidentiality_limit: u64,
	pub(crate) integrity_limit: u64,
}

/// A QUIC packet protection key.
struct PacketKey {
	algo: aead::Algorithm,
	key: AeadKey,
	iv: Iv,
	confidentiality_limit: u64,
	integrity_limit: u64,
}

/// A QUIC header protection algorithm.
#[derive(Debug, Clone, Copy)]
pub(crate) enum HeaderProtectionAlgorithm {
	Aes128,
	Aes256,
	#[cfg(not(feature = "fips"))]
	ChaCha20,
}

pub(crate) struct HeaderProtectionKey {
	algo: HeaderProtectionAlgorithm,
	key: AeadKey,
}

/// The Sample length is 16 bytes for all supported ciphers.
const SAMPLE_LEN: usize = 16;

impl quic::Algorithm for KeyBuilder {
	fn packet_key(
		&self,
		key: AeadKey,
		iv: Iv
	) -> Box<dyn quic::PacketKey> {
		Box::new(PacketKey {
			algo: self.packet_algo,
			key,
			iv,
			confidentiality_limit: self.confidentiality_limit,
			integrity_limit: self.integrity_limit,
		})
	}

	fn header_protection_key(
		&self,
		key: AeadKey
	) -> Box<dyn quic::HeaderProtectionKey> {
		Box::new(HeaderProtectionKey {
			algo: self.header_algo,
			key,
		})
	}

	fn aead_key_len(&self) -> usize {
		self.packet_algo.key_size()
	}

	fn fips(&self) -> bool {
		crate::fips::enabled()
	}
}

impl quic::PacketKey for PacketKey {
	fn encrypt_in_place(
		&self,
		packet_number: u64,
		header: &[u8],
		payload: &mut [u8],
	) -> Result<quic::Tag, Error> {
		let tag = self.algo.encrypt_in_place(
			self.key.as_ref(),
			&Nonce::new(&self.iv, packet_number).0,
			header,
			payload,
		)?;
		Ok(quic::Tag::from(tag.as_ref()))
	}

	fn decrypt_in_place<'a>(
		&self,
		packet_number: u64,
		header: &[u8],
		payload: &'a mut [u8],
	) -> Result<&'a [u8], Error> {
		let plaintext_len = self.algo.decrypt_in_place(
			self.key.as_ref(),
			&Nonce::new(&self.iv, packet_number).0,
			header,
			payload,
		)?;
		Ok(&payload[..plaintext_len])
	}

	fn tag_len(&self) -> usize {
		aead::TAG_LEN
	}

	fn confidentiality_limit(&self) -> u64 {
		self.confidentiality_limit
	}

	fn integrity_limit(&self) -> u64 {
		self.integrity_limit
	}
}

impl quic::HeaderProtectionKey for HeaderProtectionKey {
	fn encrypt_in_place(
		&self,
		sample: &[u8],
		first: &mut u8,
		packet_number: &mut [u8],
	) -> Result<(), Error> {
		// Implement https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
		let mask = self.mask(sample)?;

		let (first_mask, packet_number_mask) =
			mask.split_first().expect("mask is 5 bytes long");
		if packet_number_mask.len() < packet_number.len() {
			return Err(Error::General("packet number exceeds 4 bytes".into()));
		}
		let packet_number_length = (*first & 0x03) + 1;
		if (*first & 0x80) == 0x80 {
			// Long header: 4 bits masked
			*first ^= first_mask & 0x0f;
		} else {
			// Short header: 5 bits masked
			*first ^= first_mask & 0x1f;
		}

		packet_number
			.iter_mut()
			.zip(packet_number_mask)
			.take(packet_number_length as usize)
			.for_each(|(packet_number_byte, mask)| *packet_number_byte ^= mask);

		Ok(())
	}

	fn decrypt_in_place(
		&self,
		sample: &[u8],
		first: &mut u8,
		packet_number: &mut [u8],
	) -> Result<(), Error> {
		// Reverse https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
		let mask = self.mask(sample)?;

		let (first_mask, packet_number_mask) = mask.split_first().expect("mask is 5 bytes long");
		if packet_number_mask.len() < packet_number.len() {
			return Err(Error::General("packet number exceeds 4 bytes".into()));
		}
		if (*first & 0x80) == 0x80 {
			// Long header: 4 bits masked
			*first ^= first_mask & 0x0f;
		} else {
			// Short header: 5 bits masked
			*first ^= first_mask & 0x1f;
		}
		// When decrypting, determine the packet number length *after* unmasking the first byte.
		let packet_number_length = (*first & 0x03) + 1;

		packet_number
			.iter_mut()
			.zip(packet_number_mask)
			.take(packet_number_length as usize)
			.for_each(|(packet_number_byte, mask)| *packet_number_byte ^= mask);
		Ok(())
	}

	fn sample_len(&self) -> usize {
		SAMPLE_LEN
	}
}

impl HeaderProtectionAlgorithm {
	fn leancrypto_cipher(self) -> lcr_sym_type {
		match self {
			HeaderProtectionAlgorithm::Aes128 =>
				lcr_sym_type::lcr_aes_cbc,
			HeaderProtectionAlgorithm::Aes256 =>
				lcr_sym_type::lcr_aes_cbc,
			#[cfg(not(feature = "fips"))]
			HeaderProtectionAlgorithm::ChaCha20 =>
				lcr_sym_type::lcr_chacha20,
		}
	}
}

impl HeaderProtectionKey {
	fn mask(
		&self,
		sample: &[u8]
	) -> Result<[u8; 5], Error> {
		let mut mask = [0; 5];
		let sym_type: lcr_sym_type = self.algo.leancrypto_cipher();
		let mut ct: [u8; 16] = [0; 16];

		let mut sym = lcr_sym::new(sym_type);
		sym.setkey(self.key.as_ref())
			.map_err(|e| Error::General(format!("leancrypto error: {e}")))?;
		match self.algo {
			#[cfg(not(feature = "fips"))]
			HeaderProtectionAlgorithm::ChaCha20 => {
				// https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.4
				sym.setiv(&sample)
					.map_err(|e| Error::General(format!("leancrypto error: {e}")))?;
				sym.encrypt(&[0; 5], &mut ct[..5])
					.map_err(|e| Error::General(format!("leancrypto error: {e}")))?;
			}
			HeaderProtectionAlgorithm::Aes128 |
			HeaderProtectionAlgorithm::Aes256 => {
				// https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.3
				// Set NULL-buffer as IV -> as we have one block this yields ECB
				sym.setiv(&ct)
					.map_err(|e| Error::General(format!("leancrypto error: {e}")))?;
				sym.encrypt(sample, &mut ct)
					.map_err(|e| Error::General(format!("leancrypto error: {e}")))?;
			}
		}
		mask.copy_from_slice(&ct[..5]);
		Ok(mask)
	}
}

#[cfg(test)]
mod test {
	use rustls::{
		Side,
		quic::{Keys, Version},
	};

	use super::super::tls13::TLS13_AES_128_GCM_SHA256_INTERNAL;

	// Taken from rustls: Copyright (c) 2016 Joseph Birr-Pixton <jpixton@gmail.com>
	#[test]
	fn initial_test_vector_v2() {
		// https://www.ietf.org/archive/id/draft-ietf-quic-v2-10.html#name-sample-packet-protection-2
		let icid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
		let server = Keys::initial(
			Version::V2,
			TLS13_AES_128_GCM_SHA256_INTERNAL,
			TLS13_AES_128_GCM_SHA256_INTERNAL.quic.unwrap(),
			&icid,
			Side::Server,
		);
		let mut server_payload = [
			0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x40, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03,
			0x03, 0xee, 0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63, 0x2e, 0x96, 0x67, 0x78,
			0x25, 0xdd, 0xf7, 0x39, 0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d, 0xc5, 0x43,
			0x0b, 0x9a, 0x04, 0x5a, 0x12, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
			0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94, 0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0,
			0x8a, 0x60, 0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10, 0x81, 0x28, 0x7c, 0x83,
			0x4d, 0x53, 0x11, 0xbc, 0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00, 0x02, 0x03,
			0x04,
		];
		let mut server_header = [
			0xd1, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
			0xb5, 0x00, 0x40, 0x75, 0x00, 0x01,
		];
		let tag = server
			.local
			.packet
			.encrypt_in_place(1, &server_header, &mut server_payload)
			.unwrap();
		let (first, rest) = server_header.split_at_mut(1);
		let rest_len = rest.len();
		server
			.local
			.header
			.encrypt_in_place(
				&server_payload[2..18],
				&mut first[0],
				&mut rest[rest_len - 2..],
			)
			.unwrap();
		let mut server_packet = server_header.to_vec();
		server_packet.extend(server_payload);
		server_packet.extend(tag.as_ref());
		let expected_server_packet = [
			0xdc, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
			0xb5, 0x00, 0x40, 0x75, 0xd9, 0x2f, 0xaa, 0xf1, 0x6f, 0x05, 0xd8, 0xa4, 0x39, 0x8c,
			0x47, 0x08, 0x96, 0x98, 0xba, 0xee, 0xa2, 0x6b, 0x91, 0xeb, 0x76, 0x1d, 0x9b, 0x89,
			0x23, 0x7b, 0xbf, 0x87, 0x26, 0x30, 0x17, 0x91, 0x53, 0x58, 0x23, 0x00, 0x35, 0xf7,
			0xfd, 0x39, 0x45, 0xd8, 0x89, 0x65, 0xcf, 0x17, 0xf9, 0xaf, 0x6e, 0x16, 0x88, 0x6c,
			0x61, 0xbf, 0xc7, 0x03, 0x10, 0x6f, 0xba, 0xf3, 0xcb, 0x4c, 0xfa, 0x52, 0x38, 0x2d,
			0xd1, 0x6a, 0x39, 0x3e, 0x42, 0x75, 0x75, 0x07, 0x69, 0x80, 0x75, 0xb2, 0xc9, 0x84,
			0xc7, 0x07, 0xf0, 0xa0, 0x81, 0x2d, 0x8c, 0xd5, 0xa6, 0x88, 0x1e, 0xaf, 0x21, 0xce,
			0xda, 0x98, 0xf4, 0xbd, 0x23, 0xf6, 0xfe, 0x1a, 0x3e, 0x2c, 0x43, 0xed, 0xd9, 0xce,
			0x7c, 0xa8, 0x4b, 0xed, 0x85, 0x21, 0xe2, 0xe1, 0x40,
		];
		assert_eq!(server_packet[..], expected_server_packet[..]);
	}

	#[cfg(not(feature = "fips"))]
	#[test]
	fn test_short_packet_length() {
		use rustls::crypto::cipher::AeadKey;
		let sample = [
			0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a,
			0x5b, 0xfb,
		];

		let key: [u8; 32] = [
			0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc,
			0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b,
			0x0a, 0xb7, 0xa7, 0xa4,
		];

		let hpk = super::HeaderProtectionKey {
			algo: super::HeaderProtectionAlgorithm::ChaCha20,
			key: AeadKey::from(key),
		};

		let mask = hpk.mask(&sample).unwrap();
		assert_eq!(mask, [0xae, 0xfe, 0xfe, 0x7d, 0x03]);
	}
}
