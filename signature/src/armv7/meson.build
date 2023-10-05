# for i in $(ls *.c | sort); do echo "'$i',"; done

dilithium_armv7 = files([
	'dilithium_ntt_armv7.S',
	'dilithium_pointwise_smull_armv7.S',
	'dilithium_poly.c',
	'dilithium_poly_armv7.S',
	'dilithium_signature_api_armv7.c',
	'dilithium_signature_armv7.c'
])

leancrypto_dilithium_armv7_lib = static_library(
		'leancrypto_dilithium_armv7_lib',
		[ dilithium_armv7 ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
# 		c_args: [
# 			'-mfpu=neon-vfpv4',
# 			'-mthumb',
# 			'-march=armv7-a+vfpv4',
# 			'-funsafe-math-optimizations'
# 		],
	)

leancrypto_support_libs += leancrypto_dilithium_armv7_lib
