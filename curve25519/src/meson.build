if get_option('kyber_x25519').enabled() or get_option('dilithium_ed25519').enabled()
	src += files([
		'ed25519.c',
		'ed25519_ref10.c',
		'x25519.c',
		'x25519_scalarmult.c',
	])
endif
