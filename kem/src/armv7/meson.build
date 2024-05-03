# for i in $(ls *.c | sort); do echo "'$i',"; done

kyber_armv7 = files([
	'kyber_fastinvntt_armv7.S',
	'kyber_fastntt_armv7.S',
	'kyber_ntt_armv7.c',
	'kyber_poly_armv7.S',
])

leancrypto_kyber_1024_armv7_lib = static_library(
		'leancrypto_kyber_1024_armv7_lib',
		[ kyber_armv7 ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
# 		c_args: cc_armv7_neon_simd_args,
	)

leancrypto_support_libs += leancrypto_kyber_1024_armv7_lib

if get_option('kyber_768').enabled()
	leancrypto_kyber_768_armv7_lib = static_library(
			'leancrypto_kyber_768_armv7_lib',
			[ kyber_armv7 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
#	 		c_args: cc_armv7_neon_simd_args,
			c_args: [ '-DLC_KYBER_TYPE_768' ]
		)

	leancrypto_support_libs += leancrypto_kyber_768_armv7_lib
endif

if get_option('kyber_512').enabled()
	leancrypto_kyber_512_armv7_lib = static_library(
			'leancrypto_kyber_512_armv7_lib',
			[ kyber_armv7 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
#	 		c_args: cc_armv7_neon_simd_args,
			c_args: [ '-DLC_KYBER_TYPE_512' ]
		)

	leancrypto_support_libs += leancrypto_kyber_512_armv7_lib
endif
