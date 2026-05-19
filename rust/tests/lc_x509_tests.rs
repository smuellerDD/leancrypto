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

use leancrypto_sys::lcr_x509::lcr_x509_key;
use leancrypto_sys::lcr_x509::lcr_x509_key_type;

fn pkcs8_key_pair_one(key_type: lcr_x509_key_type) {
	/* Generate PKCS8 blob */
	let mut key = lcr_x509_key::new();
	let result = key.enable();
	assert_eq!(result, Ok(()));
	let result = key.key_pair_generation(key_type);
	assert_eq!(result, Ok(()));
	let der_key_result = key.pkcs8_generation();

	let der_key = match der_key_result {
		Ok(der_blob) => der_blob,
		Err(error) => panic!("Problem generating PKCS8 blob: {error:?}"),
	};

	println!("PKCS8 blob len {}", der_key.len());

	/* Import PKCS8 blob into new PKCS8 component */
	let mut pkcs8_2 = lcr_x509_key::new();
	let result = pkcs8_2.pkcs8_sk_load(der_key);
	assert_eq!(result, Ok(()));
}

#[test]
fn pkcs8_key_pair_ed25519() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_ed25519);
}

#[test]
fn pkcs8_key_pair_ed448() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_ed448);
}

#[test]
fn pkcs8_key_pair_mldsa44() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_dilithium_44);
}

#[test]
fn pkcs8_key_pair_mldsa65() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_dilithium_65);
}

#[test]
fn pkcs8_key_pair_mldsa87() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_dilithium_87);
}

#[test]
fn pkcs8_key_pair_mldsa87_ed448() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_dilithium_87_ed448);
}

#[test]
fn pkcs8_key_pair_mldsa65_ed25519() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_dilithium_65_ed25519);
}

#[test]
fn pkcs8_key_pair_mldsa44_ed25519() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_dilithium_44_ed25519);
}

#[test]
fn pkcs8_key_pair_sphincs_shake_256s() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_sphincs_shake_256s);
}

#[test]
fn pkcs8_key_pair_sphincs_shake_256f() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_sphincs_shake_256f);
}

#[test]
fn pkcs8_key_pair_sphincs_shake_192s() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_sphincs_shake_192s);
}

#[test]
fn pkcs8_key_pair_sphincs_shake_192f() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_sphincs_shake_192f);
}

#[test]
fn pkcs8_key_pair_sphincs_shake_128s() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_sphincs_shake_128s);
}

#[test]
fn pkcs8_key_pair_sphincs_shake_128f() {
	pkcs8_key_pair_one(lcr_x509_key_type::lcr_sphincs_shake_128f);
}

fn x509_cert_one(key_type: lcr_x509_key_type) {
	let mut key = lcr_x509_key::new();
	let result = key.key_pair_generation(key_type);
	assert_eq!(result, Ok(()));
	let result = key.enable();
	assert_eq!(result, Ok(()));

	/*
	 * Set the different properties of the certifificate
	 */
	let result = key.cert_set_keyusage("digitalSignature");
	assert_eq!(result, Ok(()));
	let result = key.cert_set_keyusage("keyCertSign");
	assert_eq!(result, Ok(()));
	let result = key.cert_set_keyusage("critical");
	assert_eq!(result, Ok(()));
	let result = key.cert_set_ca_pathlen(9);
	assert_eq!(result, Ok(()));
	let result = key.cert_set_valid_from(1729527728);
	assert_eq!(result, Ok(()));
	let result = key.cert_set_valid_to(2044210606);
	assert_eq!(result, Ok(()));
	let result = key.cert_set_subject_cn("leancrypto test CA");
	assert_eq!(result, Ok(()));
	let result = key.cert_set_subject_ou("leancrypto test OU");
	assert_eq!(result, Ok(()));
	let result = key.cert_set_subject_o("leancrypto");
	assert_eq!(result, Ok(()));
	let result = key.cert_set_subject_st("Saxony");
	assert_eq!(result, Ok(()));
	let result = key.cert_set_subject_c("DE");
	assert_eq!(result, Ok(()));
	let result = key.cert_set_ca();
	assert_eq!(result, Ok(()));
	let result = key.cert_check_issuer_ca();
	assert_eq!(result, Ok(()));

	let cert_der_result = key.certificate_generation();

	let cert_der = match cert_der_result {
		Ok(der_blob) => der_blob,
		Err(error) => panic!("Problem generating PKCS8 blob: {error:?}"),
	};

	println!("X.509 certificate blob len {}", cert_der.len());

	/* Import DER blob into new X.509 component */
	let mut key2 = lcr_x509_key::new();
	let result = key2.cert_load(cert_der);
	assert_eq!(result, Ok(()));
}

#[test]
fn x509_key_pair_ed25519() {
	x509_cert_one(lcr_x509_key_type::lcr_ed25519);
}

#[test]
fn x509_key_pair_ed448() {
	x509_cert_one(lcr_x509_key_type::lcr_ed448);
}

#[test]
fn x509_key_pair_mldsa44() {
	x509_cert_one(lcr_x509_key_type::lcr_dilithium_44);
}

#[test]
fn x509_key_pair_mldsa65() {
	x509_cert_one(lcr_x509_key_type::lcr_dilithium_65);
}

#[test]
fn x509_key_pair_mldsa87() {
	x509_cert_one(lcr_x509_key_type::lcr_dilithium_87);
}

#[test]
fn x509_key_pair_mldsa87_ed448() {
	x509_cert_one(lcr_x509_key_type::lcr_dilithium_87_ed448);
}

#[test]
fn x509_key_pair_mldsa65_ed25519() {
	x509_cert_one(lcr_x509_key_type::lcr_dilithium_65_ed25519);
}

#[test]
fn x509_key_pair_mldsa44_ed25519() {
	x509_cert_one(lcr_x509_key_type::lcr_dilithium_44_ed25519);
}

#[test]
fn x509_key_pair_sphincs_shake_256s() {
	x509_cert_one(lcr_x509_key_type::lcr_sphincs_shake_256s);
}

#[test]
fn x509_key_pair_sphincs_shake_256f() {
	x509_cert_one(lcr_x509_key_type::lcr_sphincs_shake_256f);
}

#[test]
fn x509_key_pair_sphincs_shake_192s() {
	x509_cert_one(lcr_x509_key_type::lcr_sphincs_shake_192s);
}

#[test]
fn x509_key_pair_sphincs_shake_192f() {
	x509_cert_one(lcr_x509_key_type::lcr_sphincs_shake_192f);
}

#[test]
fn x509_key_pair_sphincs_shake_128s() {
	x509_cert_one(lcr_x509_key_type::lcr_sphincs_shake_128s);
}

#[test]
fn x509_key_pair_sphincs_shake_128f() {
	x509_cert_one(lcr_x509_key_type::lcr_sphincs_shake_128f);
}
