# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
if (get_option('kyber_1024').enabled() or get_option('kyber_768').enabled() or get_option('kyber_512').enabled())
	src += files([
		'kyber_api.c',
		'kyber_cbd.c',
		'kyber_pct.c',
		'kyber_zetas.c',
	])

	if (not arm32_neon_asm)
		src += files([ 'kyber_ntt.c' ])
	endif
endif

# Files which are compiled for each Kyber implementation separately
kyber_c = files([
	'kyber_ies.c',
	'kyber_kem.c',
	'kyber_kem_c.c',
	'kyber_kex.c',
	'kyber_indcpa.c',
	'kyber_poly.c',
	'kyber_polyvec.c',
	'kyber_selftest.c',
	'kyber_selftest_kdf.c',
])
if get_option('kyber_debug').enabled()
	kyber_c += files ([ 'kyber_debug.c', ])
endif

if get_option('kyber_x25519').enabled()
	kyber_c += files ([
		'kyber_x25519_ies.c',
		'kyber_x25519_kem.c',
		'kyber_x25519_kex.c',
	])
endif

if (x86_64_asm)
	subdir('avx2')
elif (arm64_asm)
	subdir('armv8')
elif (arm32_neon_asm)
	subdir('armv7')
endif

if get_option('kyber_1024').enabled()
	kyber_1024_files = kyber_c

	if (not x86_64_asm and not arm64_asm)
		kyber_1024_files += files([ 'kyber_kem_api_c.c' ])
	endif
	leancrypto_kyber_1024_c_lib = static_library(
		'leancrypto_kyber_1024_c_lib',
		[ kyber_1024_files ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
	)
	leancrypto_support_libs += leancrypto_kyber_1024_c_lib
endif

if get_option('kyber_768').enabled()
	kyber_768_files = kyber_c

	if (not x86_64_asm and not arm64_asm)
		kyber_768_files += files([ 'kyber_kem_api_c.c' ])
	endif

	leancrypto_kyber_768_c_lib = static_library(
		'leancrypto_kyber_768_c_lib',
		[ kyber_768_files ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : '-DLC_KYBER_TYPE_768'
	)
	leancrypto_support_libs += leancrypto_kyber_768_c_lib
endif

if get_option('kyber_512').enabled()
	kyber_512_files = kyber_c

	kyber_512_files += files([ 'kyber_kem_api_c.c' ])

	leancrypto_kyber_512_c_lib = static_library(
		'leancrypto_kyber_512_c_lib',
		[ kyber_512_files ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : '-DLC_KYBER_TYPE_512'
	)
	leancrypto_support_libs += leancrypto_kyber_512_c_lib
endif

