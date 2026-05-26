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

//! Integration tests
use crate::server::start_server;
use rstest::rstest;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{CipherSuite, SignatureScheme, SupportedCipherSuite};
use rustls_leancrypto::{custom_provider, default_provider};
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

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
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

    let server_name = "localhost".try_into().unwrap();

    let mut sock = TcpStream::connect(format!("localhost:{port}")).unwrap();

    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
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
#[cfg(all(not(feature = "fips"), feature = "nonpqc"))]
#[case::tls13_aes_128_gcm_sha256_x25519(
    rustls_leancrypto::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls_leancrypto::kx_group::X25519,
    server::Alg::ED25519,
    CipherSuite::TLS13_AES_128_GCM_SHA256
)]
#[cfg(feature = "nonpqc")]
#[case::tls13_aes_128_gcm_sha256_mlkem1024(
    rustls_leancrypto::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls_leancrypto::kx_group::MLKEM1024,
    server::Alg::ED25519,
    CipherSuite::TLS13_AES_128_GCM_SHA256
)]
#[cfg(feature = "nonpqc")]
#[case::tls13_aes_128_gcm_sha256(
    rustls_leancrypto::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls_leancrypto::kx_group::MLKEM768,
    server::Alg::ED25519,
    CipherSuite::TLS13_AES_128_GCM_SHA256
)]
#[cfg(all(not(feature = "fips"), feature = "nonpqc"))]
#[case::tls13_aes_256_gcm_sha384_x25519_mlkem768(
	rustls_leancrypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
	rustls_leancrypto::kx_group::X25519,
//	server::Alg::ML_DSA_87,
	server::Alg::ED25519,
	CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[cfg(feature = "nonpqc")]
#[case::tls13_aes_256_gcm_sha384_mlkem1024(
	rustls_leancrypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
	rustls_leancrypto::kx_group::MLKEM1024,
//	server::Alg::ML_DSA_87,
	server::Alg::ED25519,
	CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[cfg(feature = "nonpqc")]
#[case::tls13_aes_256_gcm_sha384_mlkem768(
	rustls_leancrypto::cipher_suite::TLS13_AES_256_GCM_SHA384,
	rustls_leancrypto::kx_group::MLKEM768,
//	server::Alg::ML_DSA_87,
	server::Alg::ED25519,
	CipherSuite::TLS13_AES_256_GCM_SHA384
)]
#[cfg(all(not(feature = "fips"), feature = "nonpqc"))]
#[case::tls13_chacha20_poly1305_sha256_x25519(
    rustls_leancrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    rustls_leancrypto::kx_group::X25519,
    server::Alg::ED25519,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
)]
#[cfg(feature = "nonpqc")]
#[case::tls13_chacha20_poly1305_sha256_mlkem1024(
    rustls_leancrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    rustls_leancrypto::kx_group::MLKEM1024,
    server::Alg::ED25519,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
)]
#[cfg(feature = "nonpqc")]
#[case::tls13_chacha20_poly1305_sha256_mlkem768(
    rustls_leancrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    rustls_leancrypto::kx_group::MLKEM768,
    server::Alg::ED25519,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
)]
#[cfg(feature = "nonpqc")]
#[case::tls13_chacha20_poly1305_sha256_x25519mlkem768(
    rustls_leancrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    rustls_leancrypto::kx_group::X25519MLKEM768,
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
#[cfg(all(not(feature = "fips"), feature = "nonpqc"))]
fn test_classical_completion() {
    // Run against a server that only supports the classical component
    let provider = custom_provider(
        rustls_leancrypto::ALL_CIPHER_SUITES.to_vec(),
        vec![rustls_leancrypto::kx_group::X25519],
    );

    let (port, certificate) =
        start_server(server::Alg::ED25519, Some(provider));
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

/// Test that the default provider returns the highest priority cipher suite
#[test]
#[cfg(feature = "nonpqc")]
fn test_default_client() {
    let (port, certificate) = start_server(server::Alg::ED25519, None);
    let actual_suite =
        test_with_provider(default_provider(), port, vec![certificate]);
    assert_eq!(actual_suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
}

#[test]
#[cfg(feature = "nonpqc")]
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
    assert!(algs.iter().any(|alg| {
        alg.verify_signature(pub_key, data, &signature).is_ok()
    }));
}

// #[cfg(feature = "fips")]
// #[test]
// fn provider_is_fips() {
//     rustls_leancrypto::fips::enable();
//     let provider = rustls_leancrypto::default_provider();
//     assert!(provider.fips());
//}
