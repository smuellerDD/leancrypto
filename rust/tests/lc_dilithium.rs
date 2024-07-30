#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ptr;
use leancrypto;
use std::mem::MaybeUninit;

#[test]
fn lc_rust_dilithium_ed25519() {
	unsafe {
		let mut sk: MaybeUninit<lc_dilithium_87_ed25519_sk> =
			MaybeUninit::uninit();
		let mut pk: MaybeUninit<lc_dilithium_87_ed25519_pk> =
			MaybeUninit::uninit();
		let mut sig: MaybeUninit<lc_dilithium_87_ed25519_sig> =
			MaybeUninit::uninit();

		let msg: [u8; 3] = [0x00, 0x01, 0x02];
		let msg2: [u8; 3] = [0x00, 0x01, 0x02];

		if lc_dilithium_87_ed25519_keypair(pk.as_mut_ptr(),
						   sk.as_mut_ptr(),
						   lc_seeded_rng) != 0 {
			println!("Keypair generation failed");
		}
		pk.assume_init();
		sk.assume_init();

		if lc_dilithium_87_ed25519_sign(sig.as_mut_ptr(), msg.as_ptr(),
						msg.len(), sk.as_ptr(),
						lc_seeded_rng) != 0 {
			println!("Signature generation failed");
		}
		sig.assume_init();

		if lc_dilithium_87_ed25519_verify(sig.as_ptr(), msg.as_ptr(),
						  msg.len(), pk.as_ptr()) != 0 {
			println!("Signature verification failed");
		}

		/* modify msg */
		let ret = lc_dilithium_87_ed25519_verify(sig.as_ptr(),
							 msg2.as_ptr(),
							 msg2.len(),
							 pk.as_ptr());
		assert_ne!(-i32::from(EBADMSG as i16), ret);
	}
}
