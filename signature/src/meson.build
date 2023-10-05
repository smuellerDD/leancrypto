# for i in $(ls *.c | sort); do echo "'$i',"; done

if get_option('dilithium').enabled()
	src += files([
		'dilithium_signature_c.c',
		'dilithium_ntt.c',
		'dilithium_poly.c',
		'dilithium_rounding.c',
		'dilithium_selftest.c'
	])

	if get_option('dilithium_debug').enabled()
		src += files ([ 'dilithium_debug.c', ])
	endif

	if (x86_64_asm and get_option('dilithium_strength') == '5')
		subdir('avx2')
	elif (arm64_asm and get_option('dilithium_strength') == '5')
		subdir('armv8')
	# 32 bit ARM processor and GCC
	elif (arm32_neon_gcc_asm and get_option('dilithium_strength') == '5')
		subdir('armv7')
	else
		src += files([ 'dilithium_signature_api_c.c' ])
	endif
endif
