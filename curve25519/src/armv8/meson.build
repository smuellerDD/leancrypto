# for i in $(ls *.c | sort); do echo "'$i',"; done

curve25519_armv8 = files([
	'curve25519_armv8.c',
	'X25519-AArch64.S',
])

leancrypto_curve25519_armv8_lib = static_library(
		'leancrypto_curve25519_armv8_lib',
		[ curve25519_armv8 ],
		include_directories: [
			'../',
			include_internal_dirs
		],
		c_args: cc_armv8_neon_simd_args
	)

leancrypto_support_libs_fips += leancrypto_curve25519_armv8_lib
