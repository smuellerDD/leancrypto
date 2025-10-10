# for i in $(ls *.c | sort); do echo "'$i',"; done

curve25519_armv7 = files([
	'curve25519_armv7.c',
	'x25519-cortex-m4-gcc.S',
])

leancrypto_curve25519_armv7_lib = static_library(
		'leancrypto_curve25519_armv7_lib',
		[ curve25519_armv7 ],
		include_directories: [
			'../',
			include_internal_dirs
		],
		c_args: cc_armv7_neon_simd_args
	)

leancrypto_support_libs += leancrypto_curve25519_armv7_lib
