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

use leancrypto_sys::lcr_x25519::lcr_x25519;

fn lc_rust_x25519_one() {
	let mut x25519_local = lcr_x25519::new();
	let mut x25519_remote = lcr_x25519::new();

	/* Generate local key pair */
	let result = x25519_local.keypair();
	assert_eq!(result, Ok(()));

	/* Export local public key */
	let (pk_local_slice, result) = x25519_local.pk();
	assert_eq!(result, Ok(()));
	let pk_local = pk_local_slice.to_vec();

	/* Generate remote key pair */
	let result = x25519_remote.keypair();
	assert_eq!(result, Ok(()));

	/* Export remote public key */
	let (pk_remote_slice, result) = x25519_remote.pk();
	assert_eq!(result, Ok(()));
	let pk_remote = pk_remote_slice.to_vec();

	/* Load remote PK into local context */
	let result = x25519_local.pk_remote_load(&pk_remote);
	assert_eq!(result, Ok(()));

	/* Load local PK into remote context */
	let result = x25519_remote.pk_remote_load(&pk_local);
	assert_eq!(result, Ok(()));

	/* Generate local shared secret */
	let result = x25519_local.shared_secret();
	assert_eq!(result, Ok(()));

	/* Export local shared secret */
	let (ss_local_slice, result) = x25519_local.ss();
	assert_eq!(result, Ok(()));
	let ss_local = ss_local_slice.to_vec();

	/* Generate remote shared secret */
	let result = x25519_remote.shared_secret();
	assert_eq!(result, Ok(()));

	/* Export remote shared secret */
	let (ss_remote_slice, result) = x25519_remote.ss();
	assert_eq!(result, Ok(()));
	let ss_remote = ss_remote_slice.to_vec();

	/* Check that local and remote shared secrets match */
	assert_eq!(ss_local, ss_remote);
	//println!("ss local {:x?}",  ss_local);
	//println!("ss remote {:x?}",  ss_remote);
}

#[test]
fn lc_rust_x25519() {
	lc_rust_x25519_one();
}
