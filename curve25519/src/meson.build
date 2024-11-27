if get_option('kyber_x25519').enabled() or get_option('dilithium_ed25519').enabled()
	src_fips += files([
		'ed25519.c',
		'ed25519_ref10.c',
		'x25519.c',
		'x25519_scalarmult_c.c',
	])

	include_files += files([
		'../api/lc_ed25519.h',
		'../api/lc_x25519.h',
	])

	if (x86_64_asm)
		subdir('avx')
	elif (arm64_asm)
		subdir('armv8')
	elif (arm32_neon_asm)
		subdir('armv7')
	else
		src_fips += files([
			'x25519_scalarmult.c',
		])
	endif

endif
