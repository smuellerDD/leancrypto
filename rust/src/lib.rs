/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub fn lcr_sha3_512(msg: &[u8]) -> [u8; 64]
{
	let mut digest: [u8; 64] = [0; 64];

	unsafe {
		lc_hash(lc_sha3_512, msg.as_ptr(), msg.len(),
			digest.as_mut_ptr());
	}

	return digest;
}

pub fn lcr_sha3_384(msg: &[u8]) -> [u8; 48]
{
	let mut digest: [u8; 48] = [0; 48];

	unsafe {
		lc_hash(lc_sha3_384, msg.as_ptr(), msg.len(),
			digest.as_mut_ptr());
	}

	return digest;
}

pub fn lcr_sha3_256(msg: &[u8]) -> [u8; 32]
{
	let mut digest: [u8; 32] = [0; 32];

	unsafe {
		lc_hash(lc_sha3_256, msg.as_ptr(), msg.len(),
			digest.as_mut_ptr());
	}

	return digest;
}

pub fn lcr_sha3_224(msg: &[u8]) -> [u8; 28]
{
	let mut digest: [u8; 28] = [0; 28];

	unsafe {
		lc_hash(lc_sha3_224, msg.as_ptr(), msg.len(),
			digest.as_mut_ptr());
	}

	return digest;
}

pub fn lcr_sha256(msg: &[u8]) -> [u8; 32]
{
	let mut digest: [u8; 32] = [0; 32];

	unsafe {
		lc_hash(lc_sha256, msg.as_ptr(), msg.len(),
			digest.as_mut_ptr());
	}

	return digest;
}

pub fn lcr_sha512(msg: &[u8]) -> [u8; 64]
{
	let mut digest: [u8; 64] = [0; 64];

	unsafe {
		lc_hash(lc_sha512, msg.as_ptr(), msg.len(),
			digest.as_mut_ptr());
	}

	return digest;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn leancrypto_lc_hash_sha3_512_lib() {
		unsafe {
			let msg_512: [u8; 3] = [0x82, 0xD9, 0x19];
			let exp_512: [u8; 64] =
				[0x76, 0x75, 0x52, 0x82, 0xA9, 0xC5, 0x0A, 0x67,
				 0xFE, 0x69, 0xBD, 0x3F, 0xCE, 0xFE, 0x12, 0xE7,
				 0x1D, 0xE0, 0x4F, 0xA2, 0x51, 0xC6, 0x7E, 0x9C,
				 0xC8, 0x5C, 0x7F, 0xAB, 0xC6, 0xCC, 0x89, 0xCA,
				 0x9B, 0x28, 0x88, 0x3B, 0x2A, 0xDB, 0x22, 0x84,
				 0x69, 0x5D, 0xD0, 0x43, 0x77, 0x55, 0x32, 0x19,
				 0xC8, 0xFD, 0x07, 0xA9, 0x4C, 0x29, 0xD7, 0x46,
				 0xCC, 0xEF, 0xB1, 0x09, 0x6E, 0xDE, 0x42, 0x91];
			let mut act: [u8; 64] = [0; 64];

			let msg_512_ptr = &msg_512 as *const _;

			lc_hash(lc_sha3_512, msg_512_ptr, msg_512.len(),
                                act.as_mut_ptr());

			assert_eq!(&act[..], &exp_512[..]);
		}
	}
}
