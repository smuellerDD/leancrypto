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

use leancrypto_sys::lcr_hqc::lcr_hqc;
use leancrypto_sys::lcr_hqc::lcr_hqc_type;

fn lc_rust_hqc_one(hqc_type: lcr_hqc_type) {
	let mut hqc = lcr_hqc::new();

	let result = hqc.keypair(hqc_type);
	assert_eq!(result, Ok(()));

	let result = hqc.encapsulate();
	assert_eq!(result, Ok(()));

	let ct_slice = hqc.get_ct().expect("get_ct");
	let ct = ct_slice.to_vec();
	let sk_slice = hqc.get_sk().expect("get_sk");
	let sk = sk_slice.to_vec();

	let mut hqc2 = lcr_hqc::new();
	let result = hqc2.sk_load(&sk);
	assert_eq!(result, Ok(()));
	assert_eq!(hqc.get_sk().expect("get_sk"),
		   hqc2.get_sk().expect("get_ct"));

	let result = hqc2.ct_load(&ct);
	assert_eq!(result, Ok(()));
	assert_eq!(hqc.get_ct().expect("get_ct"),
		   hqc2.get_ct().expect("get_ct"));

	let result = hqc2.decapsulate();
	assert_eq!(result, Ok(()));
	assert_eq!(hqc.get_ss().expect("get_ss"),
		   hqc2.get_ss().expect("get_ss"));
	//println!("ct {:x?}",  hqc2.ct().to_vec().chunks(10).next());
}

#[test]
fn lc_rust_hqc_128() {
	lc_rust_hqc_one(lcr_hqc_type::lcr_hqc_128);
}

#[test]
fn lc_rust_hqc_192() {
	lc_rust_hqc_one(lcr_hqc_type::lcr_hqc_192);
}

#[test]
fn lc_rust_hqc_256() {
	lc_rust_hqc_one(lcr_hqc_type::lcr_hqc_256);
}
