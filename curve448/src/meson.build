curve448_base = 0
if get_option('dilithium_ed448').enabled()
	src += files([
		'ed448.c',
	])

	include_files += files([
		'../api/lc_ed448.h',
	])

	curve448_base = 1
endif
if get_option('kyber_x448').enabled()
	src += files([
		'x448_scalarmult_c.c',
		'x448.c'
	])

	include_files += files([
		'../api/lc_x448.h',
	])

	if (x86_64_asm)
		subdir('avx2')
		src += files([
			'avx2/curve448_scalarmult_avx2.c',
		])
	else
		src += files([
			'x448_scalarmult.c',
		])
	endif

	curve448_base = 1
endif

if curve448_base == 1
	src += files([
		'curve448.c',
		'curve448_tables.c',
		'f_generic.c',
		'f_impl.c',
		'scalar.c',
	])
endif
