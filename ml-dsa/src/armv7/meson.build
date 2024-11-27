# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
if (get_option('dilithium_87').enabled() or get_option('dilithium_65').enabled())
	src_fips += files([
		'dilithium_ntt_consts.c'
	])
endif

# Files which are compiled for each Dilithium implementation separately
dilithium_armv7 = files([
	'dilithium_ntt_armv7.S',
	'dilithium_pointwise_smull_armv7.S',
	'dilithium_poly.c',
	'dilithium_poly_armv7.S',
	'dilithium_signature_api_armv7.c',
	'dilithium_signature_armv7.c'
])

if get_option('dilithium_87').enabled()
	leancrypto_dilithium_87_armv7_lib = static_library(
			'leancrypto_dilithium_87_armv7_lib',
			[ dilithium_armv7 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
	# 		c_args: cc_armv7_neon_simd_args,
		)

	leancrypto_support_libs_fips += leancrypto_dilithium_87_armv7_lib
endif

if get_option('dilithium_65').enabled()
	leancrypto_dilithium_65_armv7_lib = static_library(
			'leancrypto_dilithium_65_armv7_lib',
			[ dilithium_armv7 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
	# 		c_args: cc_armv7_neon_simd_args,
			c_args: [ '-DLC_DILITHIUM_TYPE_65' ]
		)

	leancrypto_support_libs_fips += leancrypto_dilithium_65_armv7_lib
endif
