# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
if (get_option('kyber_1024').enabled() or get_option('kyber_768').enabled() or get_option('kyber_512').enabled())
	kyber_armv7_common = files([
		'kyber_consts_armv7.c',
		'kyber_fastinvntt_armv7.S',
		'kyber_fastntt_armv7.S',
		'kyber_ntt_armv7.c',
	])

	leancrypto_kyber_common_armv7_lib = static_library(
			'leancrypto_kyber_common_armv7_lib',
			[ kyber_armv7_common ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
		)
	leancrypto_support_libs += leancrypto_kyber_common_armv7_lib
endif

# Files which are compiled for each Kyber implementation separately

kyber_armv7 = files([
	'kyber_poly_armv7.S',
])

if get_option('kyber_1024').enabled()
	leancrypto_kyber_1024_armv7_lib = static_library(
			'leancrypto_kyber_1024_armv7_lib',
			[ kyber_armv7 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
		)
	leancrypto_support_libs += leancrypto_kyber_1024_armv7_lib
endif

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
