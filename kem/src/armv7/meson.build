# for i in $(ls *.c | sort); do echo "'$i',"; done

kyber_armv7 = files([
	'kyber_fastinvntt_armv7.S',
	'kyber_fastntt_armv7.S',
	'kyber_ntt_armv7.c',
	'kyber_poly_armv7.S',
])

leancrypto_kyber_armv7_lib = static_library(
		'leancrypto_kyber_armv7_lib',
		[ kyber_armv7 ],
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

leancrypto_support_libs += leancrypto_kyber_armv7_lib
