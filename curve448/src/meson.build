curve25519_base = 0
if get_option('dilithium_ed448').enabled()
	src_fips += files([
		'ed448.c',
	])

	curve25519_base = 1
endif
if get_option('kyber_x448').enabled()
	src_fips += files([
		'x448.c'
	])

	curve25519_base = 1
endif

if curve25519_base == 1
	src_fips += files([
		'curve448.c',
		'curve448_tables.c',
		'f_generic.c',
		'f_impl.c',
		'scalar.c',
	])

	include_files += files([
		'../api/lc_ed448.h',
	])
endif
