# for i in $(ls *.c | sort); do echo "'$i',"; done

if get_option('dilithium').enabled()
	src += files([
		'dilithium_debug.c',
		'dilithium_signature_c.c',
		'dilithium_ntt.c',
		'dilithium_pack.c',
		'dilithium_poly.c',
		'dilithium_rounding.c',
		'dilithium_selftest.c'
	])

	if (x86_64_asm and get_option('dilithium_strength') == '5')
		subdir('avx2')
	else
		src += files([ 'dilithium_signature_api_c.c' ])
	endif
endif
