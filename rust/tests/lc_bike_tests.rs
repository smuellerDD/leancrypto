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

use leancrypto_sys::lcr_bike::lcr_bike;
use leancrypto_sys::lcr_bike::lcr_bike_type;

fn lc_rust_bike_one(bike_type: lcr_bike_type) {
	let mut bike = lcr_bike::new();

	let result = bike.keypair(bike_type);
	assert_eq!(result, Ok(()));

	let result = bike.encapsulate();
	assert_eq!(result, Ok(()));

	let (ct_slice, result) = bike.ct_as_slice();
	assert_eq!(result, Ok(()));
	let ct = ct_slice.to_vec();
	let (sk_slice, result) = bike.sk_as_slice();
	assert_eq!(result, Ok(()));
	let sk = sk_slice.to_vec();

	let mut bike2 = lcr_bike::new();
	let result = bike2.sk_load(&sk);
	assert_eq!(result, Ok(()));
	assert_eq!(bike.sk_as_slice().0, bike2.sk_as_slice().0);

	let result = bike2.ct_load(&ct);
	assert_eq!(result, Ok(()));
	assert_eq!(bike.ct_as_slice().0, bike2.ct_as_slice().0);

	let result = bike2.decapsulate();
	assert_eq!(result, Ok(()));
	assert_eq!(bike.ss_as_slice().0, bike2.ss_as_slice().0);
	//println!("ct {:x?}",  bike2.ct_as_slice().to_vec().chunks(10).next());
}

#[test]
fn lc_rust_bike_1() {
	lc_rust_bike_one(lcr_bike_type::lcr_bike_1);
}

#[test]
fn lc_rust_bike_3() {
	lc_rust_bike_one(lcr_bike_type::lcr_bike_3);
}

#[test]
fn lc_rust_bike_5() {
	lc_rust_bike_one(lcr_bike_type::lcr_bike_5);
}
