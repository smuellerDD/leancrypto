curve25519_base = 0

if get_option('kyber_x25519').enabled()
	src += files([
		'x25519.c',
		'x25519_scalarmult_c.c',
	])

	include_files += files([
		'../api/lc_x25519.h',
	])

	if (x86_64_asm)
		subdir('avx')
		src += files([
			'avx/curve25519_avx.c',
		])
	elif (arm64_asm)
		subdir('armv8')
		src += files([
			'armv8/curve25519_armv8.c',
		])
	elif (arm32_neon_asm)
		subdir('armv7')
		src += files([
			'armv7/curve25519_armv7.c',
		])
	else
		src += files([
			'x25519_scalarmult.c',
		])
	endif

	curve25519_base = 1
endif

if get_option('dilithium_ed25519').enabled()
	src += files([
		'ed25519.c',
	])

	include_files += files([
		'../api/lc_ed25519.h',
	])

	curve25519_base = 1
endif

if (curve25519_base == 1)
	src += files([
		'ed25519_ref10.c'
	])
endif
