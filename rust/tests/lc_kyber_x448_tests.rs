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

use leancrypto_sys::lcr_kyber_x448::lcr_kyber_x448;
use leancrypto_sys::lcr_kyber_x448::lcr_kyber_x448_type;

fn lc_rust_kyber_x448_one(kyber_x448_type: lcr_kyber_x448_type) {
	let mut kyber_x448 = lcr_kyber_x448::new();
	let mut ss1: [u8; 32] = [0u8; 32];
	let mut ss2: [u8; 32] = [0u8; 32];

	let result = kyber_x448.keypair(kyber_x448_type);
	assert_eq!(result, Ok(()));

	let result = kyber_x448.encapsulate(&mut ss1);
	assert_eq!(result, Ok(()));

	let (ct_kyber_slice, ct_x448_slice, result) = kyber_x448.ct();
	assert_eq!(result, Ok(()));
	let ct_kyber = ct_kyber_slice.to_vec();
	let ct_x448 = ct_x448_slice.to_vec();
	let (sk_kyber_slice, sk_x448_slice, result) = kyber_x448.sk();
	assert_eq!(result, Ok(()));
	let sk_kyber = sk_kyber_slice.to_vec();
	let sk_x448 = sk_x448_slice.to_vec();

	let mut kyber_x4482 = lcr_kyber_x448::new();
	let result = kyber_x4482.sk_load(&sk_kyber, &sk_x448);
	assert_eq!(result, Ok(()));
	assert_eq!(kyber_x448.sk().0, kyber_x4482.sk().0);
	assert_eq!(kyber_x448.sk().1, kyber_x4482.sk().1);

	let result = kyber_x4482.ct_load(&ct_kyber, &ct_x448);
	assert_eq!(result, Ok(()));
	assert_eq!(kyber_x448.ct().0, kyber_x4482.ct().0);
	assert_eq!(kyber_x448.ct().1, kyber_x4482.ct().1);

	let result = kyber_x4482.decapsulate(&mut ss2);
	assert_eq!(result, Ok(()));
	assert_eq!(ss1, ss2);
	//println!("ct {:x?}",  kyber_x4482.ct().to_vec().chunks(10).next());
}

#[test]
fn lc_rust_kyber_x448_512() {
	lc_rust_kyber_x448_one(lcr_kyber_x448_type::lcr_kyber_512);
}

#[test]
fn lc_rust_kyber_x448_768() {
	lc_rust_kyber_x448_one(lcr_kyber_x448_type::lcr_kyber_768);
}

#[test]
fn lc_rust_kyber_x448_1024() {
	lc_rust_kyber_x448_one(lcr_kyber_x448_type::lcr_kyber_1024);
}
