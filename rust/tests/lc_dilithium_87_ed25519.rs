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

use leancrypto::lcr_dilithium_ed25519::lcr_dilithium_ed25519;
use leancrypto::lcr_dilithium_ed25519::lcr_dilithium_ed25519_type;

#[test]
fn lc_rust_dilithium_87_ed25519() {
	let msg: [u8; 3] = [
		0x00, 0x01, 0x02
	];
	let mut dilithium_ed25519 = lcr_dilithium_ed25519::new();

	let result = dilithium_ed25519.keypair(lcr_dilithium_ed25519_type::lcr_dilithium_87);
	assert_eq!(result, Ok(()));

	let result = dilithium_ed25519.sign_deterministic(&msg);
	assert_eq!(result, Ok(()));

	let result = dilithium_ed25519.verify(&msg);
	assert_eq!(result, Ok(()));

	// let pk = dilithium_ed25519.pk_as_slice().to_vec();
	// let sk = dilithium_ed25519.sk_as_slice().to_vec();
 //
	// let mut dilithium_ed255192 = lcr_dilithium_ed25519::new();
	// let result = dilithium_ed255192.sk_load(&sk);
	// assert_eq!(result, Ok(()));
	// assert_eq!(dilithium_ed25519.sk_as_slice(), dilithium_ed255192.sk_as_slice());
 //
	// let result = dilithium_ed255192.pk_load(&pk);
	// assert_eq!(result, Ok(()));
	// assert_eq!(dilithium_ed25519.pk_as_slice(), dilithium_ed255192.pk_as_slice());
 //
	// let result = dilithium_ed255192.sign_deterministic(&msg);
	// assert_eq!(result, Ok(()));
	// assert_eq!(dilithium_ed25519.sig_as_slice(), dilithium_ed255192.sig_as_slice());
	// //println!("sig {:x?}",  dilithium_ed255192.sig_as_slice().to_vec().chunks(10).next());
 //
	// let result = dilithium_ed255192.verify(&msg);
	// assert_eq!(result, Ok(()));
}
