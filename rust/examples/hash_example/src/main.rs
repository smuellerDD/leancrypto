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

fn main()
{
	// SHA3-512
	let msg_512: [u8; 3] = [0x82, 0xD9, 0x19];
	let exp_512: [u8; 64] = [
		0x76, 0x75, 0x52, 0x82, 0xA9, 0xC5, 0x0A, 0x67,
		0xFE, 0x69, 0xBD, 0x3F, 0xCE, 0xFE, 0x12, 0xE7,
		0x1D, 0xE0, 0x4F, 0xA2, 0x51, 0xC6, 0x7E, 0x9C,
		0xC8, 0x5C, 0x7F, 0xAB, 0xC6, 0xCC, 0x89, 0xCA,
		0x9B, 0x28, 0x88, 0x3B, 0x2A, 0xDB, 0x22, 0x84,
		0x69, 0x5D, 0xD0, 0x43, 0x77, 0x55, 0x32, 0x19,
		0xC8, 0xFD, 0x07, 0xA9, 0x4C, 0x29, 0xD7, 0x46,
		0xCC, 0xEF, 0xB1, 0x09, 0x6E, 0xDE, 0x42, 0x91
	];
	let act_512 = leancrypto::lcr_sha3_512(&msg_512);
	assert_eq!(&act_512[..], &exp_512[..]);

	// SHA3-224
	let msg_384: [u8; 3] = [ 0xE7, 0x3B, 0xAD ];
	let exp_384: [u8; 48] = [
		0xc4, 0x02, 0xc8, 0x29, 0x90, 0x68, 0xaa, 0x30, 0x28, 0xa9,
		0xa4, 0x1c, 0xff, 0x9a, 0x0b, 0x74, 0x27, 0x31, 0x92, 0x70,
		0xf2, 0x42, 0x18, 0xda, 0xe8, 0x68, 0x1a, 0x89, 0x01, 0x51,
		0x0c, 0x47, 0x5a, 0x5f, 0xb9, 0x6b, 0x5c, 0xbc, 0x32, 0xdc,
		0xa1, 0x5f, 0x28, 0x53, 0xa0, 0xce, 0x55, 0xf6
	];
	let act_384 = leancrypto::lcr_sha3_384(&msg_384);
	assert_eq!(&act_384[..], &exp_384[..]);

	// SHA3-256
	let msg_256: [u8; 3] = [ 0x5E, 0x5E, 0xD6 ];
	let exp_256: [u8; 32] = [
		0xF1, 0x6E, 0x66, 0xC0, 0x43, 0x72,
		0xB4, 0xA3, 0xE1, 0xE3, 0x2E, 0x07,
		0xC4, 0x1C, 0x03, 0x40, 0x8A, 0xD5,
		0x43, 0x86, 0x8C, 0xC4, 0x0E, 0xC5,
		0x5E, 0x00, 0xBB, 0xBB, 0xBD, 0xF5,
		0x91, 0x1E
	];
	let act_256 = leancrypto::lcr_sha3_256(&msg_256);
	assert_eq!(&act_256[..], &exp_256[..]);

	// SHA3-224
	let msg_224: [u8; 3] = [0x50, 0xEF, 0x73];
	let exp_224: [u8; 28] = [
		0x42, 0xF9, 0xE4, 0xEA, 0xE8, 0x55,
		0x49, 0x61, 0xD1, 0xD2, 0x7D, 0x47,
		0xD9, 0xAF, 0x08, 0xAF, 0x98, 0x8F,
		0x18, 0x9F, 0x53, 0x42, 0x2A, 0x07,
		0xD8, 0x7C, 0x68, 0xC1
	];
	let act_224 = leancrypto::lcr_sha3_224(&msg_224);
	assert_eq!(&act_224[..], &exp_224[..]);

	// SHA2-512
	let msg_2512: [u8; 3] = [0x7F, 0xAD, 0x12];
	let exp_2512: [u8; 64] = [
		0x53, 0x35, 0x98, 0xe5, 0x29, 0x49, 0x18, 0xa0, 0xaf, 0x4b,
		0x3a, 0x62, 0x31, 0xcb, 0xd7, 0x19, 0x21, 0xdb, 0x80, 0xe1,
		0x00, 0xa0, 0x74, 0x95, 0xb4, 0x44, 0xc4, 0x7a, 0xdb, 0xbc,
		0x9a, 0x64, 0x76, 0xbb, 0xc8, 0xdb, 0x8e, 0xe3, 0x0c, 0x87,
		0x2f, 0x11, 0x35, 0xf1, 0x64, 0x65, 0x9c, 0x52, 0xce, 0xc7,
		0x7c, 0xcf, 0xb8, 0xc7, 0xd8, 0x57, 0x63, 0xda, 0xee, 0x07,
		0x9f, 0x60, 0x0c, 0x79
	];
	let act_2512 = leancrypto::lcr_sha512(&msg_2512);
	assert_eq!(&act_2512[..], &exp_2512[..]);

	// SHA2-256
	let msg_2256: [u8; 3] = [ 0x06, 0x3A, 0x53 ];
	let exp_2256: [u8; 32] = [
		0x8b, 0x05, 0x65, 0x59, 0x60, 0x71,
		0xc7, 0x6e, 0x35, 0xe1, 0xea, 0x54,
		0x48, 0x39, 0xe6, 0x47, 0x27, 0xdf,
		0x89, 0xb4, 0xde, 0x27, 0x74, 0x44,
		0xa7, 0x7f, 0x77, 0xcb, 0x97, 0x89,
		0x6f, 0xf4
	];
	let act_2256 = leancrypto::lcr_sha256(&msg_2256);
	assert_eq!(&act_2256[..], &exp_2256[..]);
}