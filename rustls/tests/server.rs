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
 * Util for creating test servers, adapted from
 * https://github.com/rustls/rustls/blob/20de56876d8bc45224c351339337c61126c1c954/provider-example/examples/server.rs
 */
use std::io::Write;
use std::sync::Arc;

use rcgen::SignatureAlgorithm;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::Acceptor;

/// Algorithm to use for the server keypair.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Alg {
	ED25519,
	//ML_DSA_87,
}

/// Start a server that uses [rustls_leancrypto::default_provider] on a random port,
/// generating a certificate for `localhost` with the specified algorithm.
///
/// The server will handle a single connection.
///
/// Returns the port the server is listening on and the CA certificate used to sign the server certificate.
pub fn start_server(
	alg: Alg,
	provider: Option<CryptoProvider>
) -> (u16, CertificateDer<'static>) {

	let pki = TestPki::for_algorithm(alg);
	let ca_cert_der = pki.ca_cert_der.clone();
	let server_config =
		pki.with_provider(provider.unwrap_or(rustls_leancrypto::default_provider()));

	let listener = std::net::TcpListener::bind("[::]:0").unwrap();
	let port = listener.local_addr().unwrap().port();
	std::thread::spawn(move || {
		let mut stream = listener.incoming().next().unwrap().unwrap();
		let mut acceptor = Acceptor::default();

		loop {
			acceptor.read_tls(&mut stream).unwrap();
			if let Some(accepted) = acceptor.accept().unwrap() {
				let mut conn =
					accepted
					.into_connection(server_config.clone())
					.unwrap();
				let msg = concat!(
					"HTTP/1.1 200 OK\r\n",
					"Connection: Closed\r\n",
					"Content-Type: text/html\r\n",
					"\r\n",
					"<h1>Hello World!</h1>\r\n"
					)
					.as_bytes();

				conn.writer().write_all(msg).unwrap();
				conn.write_tls(&mut stream).unwrap();
				conn.complete_io(&mut stream).unwrap();

				conn.send_close_notify();
				conn.write_tls(&mut stream).unwrap();
				conn.complete_io(&mut stream).unwrap();
			}
		}
	});
	(port, ca_cert_der)
}

struct TestPki {
	ca_cert_der: CertificateDer<'static>,
	server_cert_der: CertificateDer<'static>,
	server_key_der: PrivateKeyDer<'static>,
}

impl Alg {
	fn to_rcgen_algorithm(self) -> &'static SignatureAlgorithm {
		match self {
			#[cfg(feature="nonpqc")]
			Alg::ED25519 => &rcgen::PKCS_ED25519,
			//Alg::ML_DSA_87 => &rcgen::PKCS_ML_DSA_87,
		}
	}
}

impl TestPki {
	fn for_algorithm(alg: Alg) -> Self {
		let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
		ca_params
			.distinguished_name
			.push(rcgen::DnType::OrganizationName, "rustls-leancrypto tests");
		ca_params
			.distinguished_name
			.push(rcgen::DnType::CommonName, "Example CA");
		ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
		ca_params.key_usages = vec![
			rcgen::KeyUsagePurpose::KeyCertSign,
			rcgen::KeyUsagePurpose::DigitalSignature,
		];

		let ca_key = generate_for(alg);

		let ca_cert = ca_params.self_signed(&ca_key).unwrap();

		// Create a server end entity cert issued by the CA.
		let mut server_ee_params =
			rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
		server_ee_params.is_ca = rcgen::IsCa::NoCa;
		server_ee_params.extended_key_usages =
			vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
		let server_key = generate_for(alg);
		let server_cert = server_ee_params
			.signed_by(&server_key, &ca_cert, &ca_key)
			.unwrap();

		Self {
			ca_cert_der: ca_cert.into(),
			server_cert_der: server_cert.into(),
			server_key_der: PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
		}
	}

	fn with_provider(self, provider: CryptoProvider) -> Arc<ServerConfig> {
		let mut server_config = ServerConfig::builder_with_provider(provider.into())
			.with_safe_default_protocol_versions()
			.unwrap()
			.with_no_client_auth()
			.with_single_cert(vec![self.server_cert_der], self.server_key_der)
			.unwrap();

		server_config.key_log = Arc::new(rustls::KeyLogFile::new());

		Arc::new(server_config)
	}
}

fn generate_for(alg: Alg) -> rcgen::KeyPair {
	rcgen::KeyPair::generate_for(alg.to_rcgen_algorithm()).unwrap()
}
