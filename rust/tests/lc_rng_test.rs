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

use leancrypto::lcr_rng::lcr_rng;
use leancrypto::lcr_rng::lcr_rng_type;
use leancrypto::error::RngError;

#[test]
fn lc_rust_rng_seeded() {
	let mut rng = lcr_rng::new();

	let not_exp: [u8; 15] = [0; 15];

	let (rngdata, result) = rng.generate(&[], not_exp.len());
	assert_eq!(result, Ok(()));
	assert_eq!(rngdata.len(), not_exp.len());
	assert_ne!(rngdata, not_exp);
}

fn lc_rust_rng_stack_one(rng_type: lcr_rng_type) {
	let mut rng = lcr_rng::new();

	let not_exp: [u8; 15] = [0; 15];

	let result = rng.set_type(rng_type);
	assert_eq!(result, Ok(()));

	// This should fail as we are not seeded
	let (_rngdata, result) = rng.generate(&[], not_exp.len());
	assert_eq!(result, Err(RngError::NotSeeded));

	let seed: [u8; 3] = [0x01, 0x02, 0x03];
	let result = rng.seed(&seed, &[]);
	assert_eq!(result, Ok(()));

	let (rngdata, result) = rng.generate(&[], not_exp.len());
	assert_eq!(result, Ok(()));
	assert_eq!(rngdata.len(), not_exp.len());
	assert_ne!(rngdata, not_exp);
}

#[test]
fn lc_rust_rng_xdrbg256() {
	lc_rust_rng_stack_one(lcr_rng_type::lcr_xdrbg256)
}

#[test]
fn lc_rust_rng_xdrbg128() {
	lc_rust_rng_stack_one(lcr_rng_type::lcr_xdrbg128)
}

#[test]
fn lc_rust_rng_hmac_drbg() {
	lc_rust_rng_stack_one(lcr_rng_type::lcr_hmac_drbg)
}

#[test]
fn lc_rust_rng_hash_drbg() {
	lc_rust_rng_stack_one(lcr_rng_type::lcr_hash_drbg)
}
