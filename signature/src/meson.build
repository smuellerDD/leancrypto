# for i in $(ls *.c | sort); do echo "'$i',"; done

if get_option('dilithium').enabled()
	src += files([
		'dilithium_signature.c',
		'dilithium_ntt.c',
		'dilithium_pack.c',
		'dilithium_poly.c',
		'dilithium_rounding.c'
	])
endif
