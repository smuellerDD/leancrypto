# for i in $(ls *.c | sort); do echo "'$i',"; done

curve25519_avx = files([
	'curve25519_avx.c',
	'curve25519_avx_asm.S',
	'fe51_invert.c',
	'fe_frombytes_avx.c',
])

leancrypto_curve25519_avx_lib = static_library(
		'leancrypto_curve25519_avx_lib',
		[ curve25519_avx ],
		include_directories: [
			'../',
			include_internal_dirs
		],
		c_args: cc_avx2_args
	)

leancrypto_support_libs_fips += leancrypto_curve25519_avx_lib
