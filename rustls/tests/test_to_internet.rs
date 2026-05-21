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

use rstest::rstest;
use rustls::crypto::SupportedKxGroup;
use rustls::pki_types::CertificateDer;
use rustls::{CipherSuite, SupportedCipherSuite};
use rustls_leancrypto::custom_provider;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::process::Command;
use std::{thread, time};
use std::fs;

pub mod server;

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
#[case::tls13_chacha20_poly1305_sha256_mlkem768(
	rustls_leancrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
	rustls_leancrypto::kx_group::MLKEM768,
	CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
	"9997"
)]
#[case::tls13_chacha20_poly1305_sha256_x25519mlkem768(
	rustls_leancrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
	rustls_leancrypto::kx_group::X25519MLKEM768,
	CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
	"9996"
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
