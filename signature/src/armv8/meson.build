# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
if (get_option('dilithium_87').enabled() or get_option('dilithium_65').enabled())
	src += files([
		'NTT_params.c'
	])
endif

# Files which are compiled for each Dilithium implementation separately

dilithium_armv8 = files([
	'dilithium_intt_armv8.S',
	'dilithium_ntt_armv8.S',
	'dilithium_poly.c',
	'dilithium_poly_armv8.S',
	'dilithium_signature_api_armv8.c',
	'dilithium_signature_armv8.c'
])

if get_option('dilithium_87').enabled()
	leancrypto_dilithium_87_armv8_lib = static_library(
			'leancrypto_dilithium_87_armv8_lib',
			[ dilithium_armv8 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args: [
				'-Wno-unused-result',
			]
		)

	leancrypto_support_libs += leancrypto_dilithium_87_armv8_lib
endif

if get_option('dilithium_65').enabled()
	leancrypto_dilithium_65_armv8_lib = static_library(
			'leancrypto_dilithium_65_armv8_lib',
			[ dilithium_armv8 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args: [
				'-Wno-unused-result', '-DLC_DILITHIUM_TYPE_65'
			]
		)

	leancrypto_support_libs += leancrypto_dilithium_65_armv8_lib
endif
