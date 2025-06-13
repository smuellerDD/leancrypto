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

use leancrypto_sys::lcr_dilithium_ed448::lcr_dilithium_ed448;
use leancrypto_sys::lcr_dilithium_ed448::lcr_dilithium_ed448_type;

#[test]
fn lc_rust_dilithium_87_ed448() {
	let msg: [u8; 3] = [
		0x00, 0x01, 0x02
	];
	let mut dilithium_ed448 = lcr_dilithium_ed448::new();

	let result = dilithium_ed448.keypair(lcr_dilithium_ed448_type::lcr_dilithium_87);
	assert_eq!(result, Ok(()));

	let result = dilithium_ed448.sign_deterministic(&msg);
	assert_eq!(result, Ok(()));

	let result = dilithium_ed448.verify(&msg);
	assert_eq!(result, Ok(()));

	// Get both PKs
	let (dilithium_pk_slice, ed448_pk_slice, result) =
		dilithium_ed448.pk();
	assert_eq!(result, Ok(()));
	let dilithium_pk = dilithium_pk_slice.to_vec();
	let ed448_pk = ed448_pk_slice.to_vec();

	// Get both SKs
	let (dilithium_sk_slice, ed448_sk_slice, result) =
		dilithium_ed448.sk();
	assert_eq!(result, Ok(()));
	let dilithium_sk = dilithium_sk_slice.to_vec();
	let ed448_sk = ed448_sk_slice.to_vec();

	let mut dilithium_ed4482 = lcr_dilithium_ed448::new();

	let result = dilithium_ed4482.sk_load(&dilithium_sk, &ed448_sk);
	assert_eq!(result, Ok(()));
	// Check Dilithium SK
	assert_eq!(dilithium_ed448.sk().0,
		   dilithium_ed4482.sk().0);
	// Check ED448 SK
	assert_eq!(dilithium_ed448.sk().1,
		   dilithium_ed4482.sk().1);

	let result = dilithium_ed4482.pk_load(&dilithium_pk, &ed448_pk);
	assert_eq!(result, Ok(()));
	// Check Dilithium SK
	assert_eq!(dilithium_ed448.pk().0,
		   dilithium_ed4482.pk().0);
	// Check ED448 SK
	assert_eq!(dilithium_ed448.pk().1,
		   dilithium_ed4482.pk().1);

	let result = dilithium_ed4482.sign_deterministic(&msg);
	assert_eq!(result, Ok(()));
	// Check Dilithium Sig
	assert_eq!(dilithium_ed448.sig().0,
		   dilithium_ed4482.sig().0);
	// Check ED448 Sig
	assert_eq!(dilithium_ed448.sig().1,
		   dilithium_ed4482.sig().1);
	//println!("sig {:x?}",  dilithium_ed4482.sig().to_vec().chunks(10).next());

	let result = dilithium_ed4482.verify(&msg);
	assert_eq!(result, Ok(()));
}
