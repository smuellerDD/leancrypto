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

use leancrypto_sys::lcr_kyber::lcr_kyber;
use leancrypto_sys::lcr_kyber::lcr_kyber_type;

fn lc_rust_kyber_one(kyber_type: lcr_kyber_type) {
	let mut kyber = lcr_kyber::new();

	let result = kyber.keypair(kyber_type);
	assert_eq!(result, Ok(()));

	let result = kyber.encapsulate();
	assert_eq!(result, Ok(()));

	let (ct_slice, result) = kyber.ct();
	assert_eq!(result, Ok(()));
	let ct = ct_slice.to_vec();
	let (sk_slice, result) = kyber.sk();
	assert_eq!(result, Ok(()));
	let sk = sk_slice.to_vec();

	let mut kyber2 = lcr_kyber::new();
	let result = kyber2.sk_load(&sk);
	assert_eq!(result, Ok(()));
	assert_eq!(kyber.sk().0, kyber2.sk().0);

	let result = kyber2.ct_load(&ct);
	assert_eq!(result, Ok(()));
	assert_eq!(kyber.ct().0, kyber2.ct().0);

	let result = kyber2.decapsulate();
	assert_eq!(result, Ok(()));
	assert_eq!(kyber.ss().0, kyber2.ss().0);
	//println!("ct {:x?}",  kyber2.ct().to_vec().chunks(10).next());
}

#[test]
fn lc_rust_kyber_512() {
	lc_rust_kyber_one(lcr_kyber_type::lcr_kyber_512);
}

#[test]
fn lc_rust_kyber_768() {
	lc_rust_kyber_one(lcr_kyber_type::lcr_kyber_768);
}

#[test]
fn lc_rust_kyber_1024() {
	lc_rust_kyber_one(lcr_kyber_type::lcr_kyber_1024);
}
