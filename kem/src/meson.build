# for i in $(ls *.c | sort); do echo "'$i',"; done

if get_option('kyber').enabled()
	src += files([
		'kyber_cbd.c',
		'kyber_ies.c',
		'kyber_kem.c',
		'kyber_kem_c.c',
		'kyber_kex.c',
		'kyber_indcpa.c',
		'kyber_poly.c',
		'kyber_polyvec.c',
		'kyber_selftest.c',
		'kyber_selftest_kdf.c',
		'kyber_verify.c',
		'kyber_zetas.c'
	])
	if get_option('kyber_debug').enabled()
		src += files ([ 'kyber_debug.c', ])
	endif

	if (x86_64_asm and get_option('kyber_strength') == '4')
		src += files([ 'kyber_ntt.c' ])
		subdir('avx2')
	elif (arm64_asm and get_option('kyber_strength') == '4')
		src += files([ 'kyber_ntt.c' ])
		subdir('armv8')
	else
		src += files([ 'kyber_kem_api_c.c' ])

		if (arm32_neon_gcc_asm)
			subdir('armv7')
		else
			src += files([ 'kyber_ntt.c' ])
		endif
	endif

	if get_option('kyber_x25519').enabled()
		src += files ([
			'kyber_x25519_ies.c',
			'kyber_x25519_kem.c',
			'kyber_x25519_kex.c',
		])
	endif
endif

