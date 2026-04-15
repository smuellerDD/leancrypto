/*
 * Copyright (C) 2025 - 2026, Stephan Mueller <smueller@chronox.de>
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

use leancrypto_sys::lcr_hkdf::lcr_hkdf;
use leancrypto_sys::lcr_hash::lcr_hash_type;

#[test]
fn lc_rust_hkdf_tester() {
	/* RFC 5869 vector */
	let ikm: [u8; 22] = [0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			    0x0b, 0x0b, 0x0b, 0x0b];
	let salt: [u8; 13] = [0x00, 0x01, 0x02, 0x03, 0x04,
			      0x05, 0x06, 0x07, 0x08, 0x09,
			      0x0a, 0x0b, 0x0c];
	let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
			      0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
	let exp: [u8; 42] = [
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90,
		0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d,
		0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d,
		0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
		0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
	];
	let mut hkdf = lcr_hkdf::new(lcr_hash_type::lcr_sha2_256);

	let result = hkdf.extract(&ikm, &salt);
	assert_eq!(result, Ok(()));

	let mut act = vec![0u8; exp.len()];
	let result = hkdf.expand(&info, &mut act);
	assert_eq!(result, Ok(()));

	assert_eq!(act, &exp[..]);
}
