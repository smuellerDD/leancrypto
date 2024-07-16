# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
if (get_option('kyber_1024').enabled() or get_option('kyber_768').enabled())
	src += files([
		'kyber_ntt_armv8.c',
	])
endif

# Files which are compiled for each Kyber implementation separately
kyber_armv8 = files([
	'kyber_add_armv8.S',
	'kyber_basemul_armv8.S',
	'kyber_cbd_armv8.S',
	'kyber_indcpa_armv8.c',
	'kyber_inv_ntt_armv8.S',
	'kyber_kem_api_armv8.c',
	'kyber_kem_armv8.c',
	'kyber_ntt_armv8_asm.S',
	'kyber_poly_armv8.c',
	'kyber_poly_armv8_asm.S',
	'kyber_reduce_armv8.S'
])

if get_option('kyber_1024').enabled()
	leancrypto_kyber_1024_armv8_lib = static_library(
			'leancrypto_kyber_1024_armv8_lib',
			[ kyber_armv8 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args: [
				'-Wno-unused-result',
			]
		)
	leancrypto_support_libs += leancrypto_kyber_1024_armv8_lib
endif

if get_option('kyber_768').enabled()
	leancrypto_kyber_768_armv8_lib = static_library(
			'leancrypto_kyber_768_armv8_lib',
			[ kyber_armv8 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args: [
				'-Wno-unused-result', '-DLC_KYBER_TYPE_768'
			]
		)
	leancrypto_support_libs += leancrypto_kyber_768_armv8_lib
endif

# Support for Kyber-512 is not implemented
