/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

use leancrypto::lcr_sphincs::lcr_sphincs;
use leancrypto::lcr_sphincs::lcr_sphincs_type;

#[test]
fn lc_rust_sphincs_shake_128f() {
	let msg: [u8; 33] = [
		0xD8, 0x1C, 0x4D, 0x8D, 0x73, 0x4F, 0xCB, 0xFB,
		0xEA, 0xDE, 0x3D, 0x3F, 0x8A, 0x03, 0x9F, 0xAA,
		0x2A, 0x2C, 0x99, 0x57, 0xE8, 0x35, 0xAD, 0x55,
		0xB2, 0x2E, 0x75, 0xBF, 0x57, 0xBB, 0x55, 0x6A,
		0xC8
	];
	let mut sphincs = lcr_sphincs::new();

	let result = sphincs.keypair(lcr_sphincs_type::lcr_sphincs_shake_128f);
	assert_eq!(result, Ok(()));

	let result = sphincs.sign_deterministic(&msg);
	assert_eq!(result, Ok(()));

	let result = sphincs.verify(&msg);
	assert_eq!(result, Ok(()));

	//TODO make this work
	// let pk = sphincs.pk_as_slice();
	// let sk = sphincs.sk_as_slice();
 //
	// let mut sphincs2 = lcr_sphincs::new();
	// let result = sphincs2.sk_load(&sk);
	// assert_eq!(result, Ok(()));
	// assert_eq!(sphincs2.sk_as_slice(), &sk[..]);
 //
	// let result = sphincs2.pk_load(&pk);
	// assert_eq!(result, Ok(()));
	// assert_eq!(sphincs2.pk_as_slice(), &pk[..]);
 //
	// let result = sphincs2.sign_deterministic(&msg);
	// assert_eq!(result, Ok(()));
	// assert_eq!(sphincs.sig_as_slice(), sphincs2.sig_as_slice());
 //
	// let result = sphincs2.verify(&msg);
	// assert_eq!(result, Ok(()));
}
