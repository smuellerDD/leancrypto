#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ptr;
use leancrypto;
use std::mem::MaybeUninit;

#[test]
fn lc_rust_kyber_x25519_kex() {
	unsafe {
		let mut pk_r: MaybeUninit<lc_kyber_1024_x25519_pk> =
			MaybeUninit::uninit();
		let mut sk_r: MaybeUninit<lc_kyber_1024_x25519_sk> =
			MaybeUninit::uninit();

		let mut pk_i: MaybeUninit<lc_kyber_1024_x25519_pk> =
			MaybeUninit::uninit();
		let mut sk_i: MaybeUninit<lc_kyber_1024_x25519_sk> =
			MaybeUninit::uninit();

		let mut pk_e_i: MaybeUninit<lc_kyber_1024_x25519_pk> =
			MaybeUninit::uninit();
		let mut ct_e_r: MaybeUninit<lc_kyber_1024_x25519_ct> =
			MaybeUninit::uninit();
		let mut ct_e_i: MaybeUninit<lc_kyber_1024_x25519_ct> =
			MaybeUninit::uninit();
		let mut ct_e_r_1: MaybeUninit<lc_kyber_1024_x25519_ct> =
			MaybeUninit::uninit();
		let mut ct_e_r_2: MaybeUninit<lc_kyber_1024_x25519_ct> =
			MaybeUninit::uninit();
		let mut sk_e: MaybeUninit<lc_kyber_1024_x25519_sk> =
			MaybeUninit::uninit();

		let mut tk: MaybeUninit<lc_kyber_1024_x25519_ss> =
			MaybeUninit::uninit();

		let mut ss_r: [u8; LC_KYBER_SSBYTES as usize] =
			[0; LC_KYBER_SSBYTES as usize];
		let mut ss_i: [u8; LC_KYBER_SSBYTES as usize] =
			[0; LC_KYBER_SSBYTES as usize];
		let zero: [u8; LC_KYBER_SSBYTES as usize] =
			[0; LC_KYBER_SSBYTES as usize];

		// Generate static key for Bob
		if lc_kyber_1024_x25519_keypair(pk_r.as_mut_ptr(),
						sk_r.as_mut_ptr(),
						lc_seeded_rng) != 0 {
			println!("Keypair generation failed");
		}
		pk_r.assume_init();
		sk_r.assume_init();

		// Generate static key for Alice
		if lc_kyber_1024_x25519_keypair(pk_i.as_mut_ptr(),
						sk_i.as_mut_ptr(),
						lc_seeded_rng) != 0 {
			println!("Keypair generation failed");
		}
		pk_i.assume_init();
		sk_i.assume_init();

		// Perform unilaterally authenticated key exchange

		// Run by Bob
		if lc_kex_1024_x25519_uake_initiator_init(pk_e_i.as_mut_ptr(),
							  ct_e_i.as_mut_ptr(),
							  tk.as_mut_ptr(),
							  sk_e.as_mut_ptr(),
							  pk_r.as_ptr()) != 0 {
			println!("Bob UAKE init");
		}
		pk_e_i.assume_init();
		ct_e_i.assume_init();
		tk.assume_init();
		sk_e.assume_init();

		// Run by Alice
		if lc_kex_1024_x25519_uake_responder_ss(
			ct_e_r.as_mut_ptr(), ss_r.as_mut_ptr(),
			LC_KYBER_SSBYTES as usize, ptr::null(), 0,
			pk_e_i.as_ptr(), ct_e_i.as_ptr(), sk_r.as_ptr()) != 0 {
			println!("Alice UAKE SS");
		}
		ct_e_r.assume_init();
		sk_r.assume_init();

		// Run by Bob
		if lc_kex_1024_x25519_uake_initiator_ss(
			ss_i.as_mut_ptr(), LC_KYBER_SSBYTES as usize,
			ptr::null(), 0, ct_e_r.as_ptr(), tk.as_ptr(),
			sk_e.as_ptr()) != 0 {
			println!("Bob UAKE SS");
		}

		assert_eq!(&ss_i[..], &ss_r[..]);
		assert_ne!(&ss_i[..], &zero[..]);

		// Perform mutually authenticated key exchange

		// Run by Bob
		if lc_kex_1024_x25519_ake_initiator_init(
			pk_e_i.as_mut_ptr(), ct_e_i.as_mut_ptr(),
			tk.as_mut_ptr(), sk_e.as_mut_ptr(),
			pk_r.as_ptr()) != 0 {
			println!("Bob AKE init");
		}

		// Run by Alice
		if lc_kex_1024_x25519_ake_responder_ss(
			ct_e_r_1.as_mut_ptr(), ct_e_r_2.as_mut_ptr(),
			ss_r.as_mut_ptr(), LC_KYBER_SSBYTES as usize,
			ptr::null(), 0, pk_e_i.as_ptr(), ct_e_i.as_ptr(),
			sk_r.as_ptr(), pk_i.as_ptr()) != 0 {
			println!("Alice AKE SS");
		}
		ct_e_r_1.assume_init();
		ct_e_r_2.assume_init();

		// Run by Bob
		if lc_kex_1024_x25519_ake_initiator_ss(
			ss_i.as_mut_ptr(), LC_KYBER_SSBYTES as usize,
			ptr::null(), 0, ct_e_r_1.as_ptr(), ct_e_r_2.as_ptr(),
			tk.as_ptr(), sk_e.as_ptr(), sk_i.as_ptr()) != 0 {
			println!("Bob AKE SS");
		}

		assert_eq!(&ss_i[..], &ss_r[..]);
		assert_ne!(&ss_i[..], &zero[..]);
	}
}
