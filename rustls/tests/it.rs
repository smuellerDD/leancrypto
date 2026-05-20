//! Integration tests
use crate::server::start_server;
use rstest::rstest;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{CipherSuite, SignatureScheme, SupportedCipherSuite};
use rustls_leancrypto::{custom_provider, default_provider};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::fs;
use std::process::Command;
use std::{thread, time};

use leancrypto_sys::lcr_x509::lcr_x509_key;
use leancrypto_sys::lcr_x509::lcr_x509_key_type;

pub mod server;

fn test_with_provider(
	provider: CryptoProvider,
	port: u16,
	root_ca_certs: Vec<CertificateDer<'static>>,
) -> CipherSuite {
	// Add default webpki roots to the root store
	let mut root_store = rustls::RootCertStore {
		roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
	};

	root_store.add_parsable_certificates(root_ca_certs);

	#[allow(unused_mut)]
	let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
		.with_safe_default_protocol_versions()
		.unwrap()
		.with_root_certificates(root_store)
		.with_no_client_auth();

	let server_name = "localhost".try_into().unwrap();

	let mut sock = TcpStream::connect(format!("localhost:{port}")).unwrap();

	let mut conn = rustls::ClientConnection::new(Arc::new(config),
						     server_name).unwrap();
	let mut tls = rustls::Stream::new(&mut conn, &mut sock);

	tls.write_all(
		concat!(
			"GET / HTTP/1.1\r\n",
			"Host: localhost\r\n",
			"Connection: close\r\n",
			"Accept-Encoding: identity\r\n",
			"\r\n"
		)
		.as_bytes(),
	)
	.unwrap();

	let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

	let mut exit_buffer: [u8; 1] = [0]; // Size 1 because "q" is a single byte command
	exit_buffer[0] = b'q'; // Assign the ASCII value of "q" to the buffer

	// Write the "q" command to the TLS connection stream
	tls.write_all(&exit_buffer).unwrap();
	ciphersuite.suite()
}

#[rstest]
#[case::tls13_aes_128_gcm_sha256_x25519(
	rustls_leancrypto::cipher_suite::TLS13_AES_128_GCM_SHA256,
	rustls_leancrypto::kx_group::X25519,
	server::Alg::ED25519,
	CipherSuite::TLS13_AES_128_GCM_SHA256
)]
#[case::tls13_aes_128_gcm_sha256_mlkem1024(
	rustls_leancrypto::cipher_suite::TLS13_AES_128_GCM_SHA256,
	rustls_leancrypto::kx_group::MLKEM1024,
	server::Alg::ED25519,
	CipherSuite::TLS13_AES_128_GCM_SHA256
)]
#[case::tls13_aes_128_gcm_sha256(
	rustls_leancrypto::cipher_suite::TLS13_AES_128_GCM_SHA256,
	rustls_leancrypto::kx_group::MLKEM768,
	server::Alg::ED25519,
	CipherSuite::TLS13_AES_128_GCM_SHA256
)]

#[case::tls13_aes_256_gcm_sha384_x25519_mlkem768(
	rustls_leancrypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
	rustls_leancrypto::kx_group::X25519,
//	server::Alg::ML_DSA_87,
	server::Alg::ED25519,
	CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[case::tls13_aes_256_gcm_sha384_mlkem1024(
	rustls_leancrypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
	rustls_leancrypto::kx_group::MLKEM1024,
//	server::Alg::ML_DSA_87,
	server::Alg::ED25519,
	CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[case::tls13_aes_256_gcm_sha384_mlkem768(
	rustls_leancrypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
	rustls_leancrypto::kx_group::MLKEM768,
//	server::Alg::ML_DSA_87,
	server::Alg::ED25519,
	CipherSuite::TLS13_AES_256_GCM_SHA384
)]

#[case::tls13_chacha20_poly1305_sha256_x25519(
	rustls_leancrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
	rustls_leancrypto::kx_group::X25519,
	server::Alg::ED25519,
	CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
)]
#[case::tls13_chacha20_poly1305_sha256_mlkem1024(
	rustls_leancrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
	rustls_leancrypto::kx_group::MLKEM1024,
	server::Alg::ED25519,
	CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
)]
#[case::tls13_chacha20_poly1305_sha256_mlkem768(
	rustls_leancrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
	rustls_leancrypto::kx_group::MLKEM768,
	server::Alg::ED25519,
	CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
)]

fn test_client_and_server(
	#[case] suite: SupportedCipherSuite,
	#[case] group: &'static dyn SupportedKxGroup,
	#[case] alg: server::Alg,
	#[case] expected: CipherSuite,
) {
	// Run against a server using our default provider
	let (port, certificate) = start_server(alg, None);
	let provider = custom_provider(vec![suite], vec![group]);
	let actual_suite = test_with_provider(provider, port, vec![certificate]);
	assert_eq!(actual_suite, expected);
}

#[test]
fn test_classical_completion() {
	// Run against a server that only supports the classical component
	let provider = custom_provider(
		rustls_leancrypto::ALL_CIPHER_SUITES.to_vec(),
		vec![rustls_leancrypto::kx_group::X25519],
	);

	let (port, certificate) = start_server(server::Alg::ED25519, Some(provider));
	let provider = custom_provider(
		vec![rustls_leancrypto::cipher_suite::TLS13_AES_256_GCM_SHA384],
		// specifying both, with the hybrid first, causes rustls to reuse the classical component from the hybrid
		vec![
			rustls_leancrypto::kx_group::X25519MLKEM768,
			rustls_leancrypto::kx_group::X25519,
		],
	);
	let actual_suite = test_with_provider(provider, port, vec![certificate]);
	assert_eq!(actual_suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
}

/*
 * Test with life connection where a server is listening defined by the
 * following script: <leancrypto_source_root>/asn1/tests/testcerts
 */
#[rstest]
#[case::tls13_aes_256_gcm_sha384(
	rustls_leancrypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
	rustls_leancrypto::kx_group::X25519,
	CipherSuite::TLS13_AES_256_GCM_SHA384,
	"9999"
)]
#[case::tls13_aes_128_gcm_sha256(
	rustls_leancrypto::cipher_suite::TLS13_AES_128_GCM_SHA256,
	rustls_leancrypto::kx_group::MLKEM1024,
	CipherSuite::TLS13_AES_128_GCM_SHA256,
	"9998"
)]
#[case::tls13_chacha20_poly1305_sha256(
	rustls_leancrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
	rustls_leancrypto::kx_group::MLKEM768,
	CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
	"9997"
)]
fn test_to_internet(
	#[case] suite: SupportedCipherSuite,
	#[case] group: &'static dyn SupportedKxGroup,
	#[case] expected: CipherSuite,
	#[case] port: &str
) {
	let cipher_suites = vec![suite];
	let kx_group = vec![group];

	Command::new("../asn1/tests/testcerts/lc_openssl_server.sh")
		.arg(port)
		.arg("../asn1/tests/testcerts/")
		.spawn()
		.expect("sh command failed to start");
	let ten_millis = time::Duration::from_millis(500);
	thread::sleep(ten_millis);

	// Add certificate chain
	let mut root_store = rustls::RootCertStore::empty();
	let ca = fs::read("../asn1/tests/testcerts/ed448_cacert.der")
		.expect("Cannot read file");
	let _ = root_store.add(CertificateDer::from(ca))
		.map_err(|e| format!("Adding error {}", e));
	let int1 = fs::read("../asn1/tests/testcerts/ed448_int1.der")
		.expect("Cannot read file");
	let _ = root_store.add(CertificateDer::from(int1))
		.map_err(|e| format!("Adding error {}", e));
	let int2 = fs::read("../asn1/tests/testcerts/ed25519_int2.der")
		.expect("Cannot read file");
	let _ = root_store.add(CertificateDer::from(int2))
		.map_err(|e| format!("Adding error {}", e));

	#[allow(unused_mut)]
	let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(custom_provider(
		cipher_suites,
		kx_group,
	)))
		.with_safe_default_protocol_versions()
		.unwrap()
		.with_root_certificates(root_store)
		.with_no_client_auth();

	let server_name = "localhost".try_into().unwrap();
	let mut server_sock_name = String::new();
	server_sock_name.push_str("localhost:");
	server_sock_name.push_str(port);
	let mut sock = TcpStream::connect(server_sock_name).unwrap();

	let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
	let mut tls = rustls::Stream::new(&mut conn, &mut sock);

	tls.write_all(
		concat!(
			"GET /index.html HTTP/1.1\r\n",
			"Host: index.crates.io\r\n",
			"Connection: close\r\n",
			"Accept-Encoding: identity\r\n",
			"\r\n"
		)
		.as_bytes(),
	)
	.unwrap();

	let mut buf = Vec::new();
	tls.read_to_end(&mut buf).unwrap();
	println!("{}", String::from_utf8_lossy(&buf));
	assert!(String::from_utf8_lossy(&buf).contains("s_server"));

	let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

	let mut exit_buffer: [u8; 1] = [0]; // Size 1 because "Q" is a single byte command
	exit_buffer[0] = b'Q'; // Assign the ASCII value of "Q" to the buffer

	// Write the "Q" command to the TLS connection stream
	tls.write_all(&exit_buffer).unwrap();
	assert_eq!(ciphersuite.suite(), expected);
}

/// Test that the default provider returns the highest priority cipher suite
#[test]
fn test_default_client() {
	let (port, certificate) = start_server(server::Alg::ED25519, None);
	let actual_suite = test_with_provider(default_provider(), port,
					      vec![certificate]);
	assert_eq!(actual_suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
}

#[test]
fn test_ed25119_sign_and_verify() {
	let ours = rustls_leancrypto::default_provider();
	let theirs = rustls::crypto::aws_lc_rs::default_provider();
	let scheme = SignatureScheme::ED25519;

	let mut key = lcr_x509_key::new();
	let result = key.enable();
	assert_eq!(result, Ok(()));
	let result = key.key_pair_generation(lcr_x509_key_type::lcr_ed25519);
	assert_eq!(result, Ok(()));
	let der_key_result = key.pkcs8_encode();

	let der_key = match der_key_result {
		Ok(der_blob) => der_blob,
		Err(error) => panic!("Problem generating PKCS8 blob: {error:?}"),
	};

	let rustls_private_key = PrivateKeyDer::try_from(der_key.clone()).unwrap();
	let cert_der_result = key.get_pk();
	let pub_key = match cert_der_result {
		Ok(der_blob) => der_blob,
		Err(error) => panic!("Problem generating PKCS8 blob: {error:?}"),
	};

	eprintln!("verifying using theirs");
	sign_and_verify(
		&ours,
		&theirs,
		scheme,
		rustls_private_key.clone_key(),
		&pub_key,
	);
	eprintln!("verifying using ours");
	sign_and_verify(
		&theirs,
		&ours,
		scheme,
		rustls_private_key.clone_key(),
		&pub_key,
	);
}

fn sign_and_verify(
	signing_provider: &rustls::crypto::CryptoProvider,
	verifying_provider: &rustls::crypto::CryptoProvider,
	scheme: SignatureScheme,
	rustls_private_key: PrivateKeyDer<'static>,
	pub_key: &[u8],
) {
	let data = b"hello, world!";

	// sign
	let signing_key = signing_provider
		.key_provider
		.load_private_key(rustls_private_key)
		.unwrap();
	let signer = signing_key
		.choose_scheme(&[scheme])
		.expect("signing provider supports this scheme");
	let signature = signer.sign(data).unwrap();

	// verify
	let algs = verifying_provider
		.signature_verification_algorithms
		.mapping
		.iter()
		.find(|(k, _v)| *k == scheme)
		.map(|(_k, v)| *v)
		.expect("verifying provider supports this scheme");
	assert!(!algs.is_empty());
	assert!(algs.iter()
		.any(|alg| {
			alg.verify_signature(pub_key, data, &signature).is_ok()
		})
	);
}

// #[cfg(feature = "fips")]
// #[test]
// fn provider_is_fips() {
//     rustls_leancrypto::fips::enable();
//     let provider = rustls_leancrypto::default_provider();
//     assert!(provider.fips());
//}
