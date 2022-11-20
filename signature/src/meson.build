# for i in $(ls *.c | sort); do echo "'$i',"; done

if get_option('dilithium').enabled()
	src += files([
		'dilithium_signature_c.c',
		'dilithium_ntt.c',
		'dilithium_pack.c',
		'dilithium_poly.c',
		'dilithium_rounding.c'
	])

	if (build_machine.cpu_family() == 'x86_64')
		subdir('avx2')
	else
		src += files([ 'dilithium_signature_api_c.c' ])
	endif

	include_files += files([
		'../api/lc_dilithium.h'
	])
endif
