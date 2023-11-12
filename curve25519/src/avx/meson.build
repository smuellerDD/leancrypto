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
		c_args: [
			'-mavx2',
			'-mpopcnt',
			'-Wno-unused-command-line-argument'
		]
	)

leancrypto_support_libs += leancrypto_curve25519_avx_lib
