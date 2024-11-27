# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
if (get_option('dilithium_87').enabled() or get_option('dilithium_65').enabled())
	src_fips += files([
		'dilithium_consts_avx2.c',
	])
endif

# Files which are compiled for each Dilithium implementation separately
dilithium_avx2 = files([
	'dilithium_invntt_avx2.S',
	'dilithium_ntt_avx2.S',
	'dilithium_pointwise_avx2.S',
	'dilithium_poly_avx2.c',
	'dilithium_polyvec_avx2.c',
	'dilithium_rejsample_avx2.c',
	'dilithium_rounding_avx2.c',
	'dilithium_signature_api_avx2.c',
	'dilithium_signature_avx2.c',
	'dilithium_shuffle_avx2.S',
])

if get_option('dilithium_87').enabled()
	leancrypto_dilithium_87_avx2_lib = static_library(
			'leancrypto_dilithium_87_avx2_lib',
			[ dilithium_avx2 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args: cc_avx2_args
		)
	leancrypto_support_libs_fips += leancrypto_dilithium_87_avx2_lib
endif

if get_option('dilithium_65').enabled()
	leancrypto_dilithium_65_avx2_lib = static_library(
			'leancrypto_dilithium_65_avx2_lib',
			[ dilithium_avx2 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs,
			],
			c_args: [ cc_avx2_args, '-DLC_DILITHIUM_TYPE_65' ]
		)
	leancrypto_support_libs_fips += leancrypto_dilithium_65_avx2_lib
endif
