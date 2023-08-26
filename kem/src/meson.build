# for i in $(ls *.c | sort); do echo "'$i',"; done

if get_option('kyber').enabled()
	src += files([
		'kyber_cbd.c',
		'kyber_ies.c',
		'kyber_kem.c',
		'kyber_kem_c.c',
		'kyber_kex.c',
		'kyber_indcpa.c',
		'kyber_ntt.c',
		'kyber_poly.c',
		'kyber_polyvec.c',
		'kyber_selftest.c',
		'kyber_selftest_kdf.c',
		'kyber_selftest_rnd.c',
		'kyber_verify.c',
	])

	if (x86_64_asm and get_option('kyber_strength') == '4')
		subdir('avx2')
	elif (arm64_asm and get_option('kyber_strength') == '4')
		subdir('armv8')
	else
		src += files([ 'kyber_kem_api_c.c' ])
	endif
endif

