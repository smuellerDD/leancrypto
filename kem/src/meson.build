# for i in $(ls *.c | sort); do echo "'$i',"; done

if get_option('kyber').enabled()
	src += files([
		'kyber_cbd.c',
		'kyber_ies.c',
		'kyber_kem_c.c',
		'kyber_kex.c',
		'kyber_indcpa.c',
		'kyber_ntt.c',
		'kyber_poly.c',
		'kyber_polyvec.c',
		'kyber_verify.c',
	])

	if (x86_64_asm)
		subdir('avx2')
	else
		src += files([ 'kyber_kem_api_c.c' ])
	endif

	include_files += files([
		'../api/lc_kyber.h'
	])
endif

