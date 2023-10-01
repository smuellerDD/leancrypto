# for i in $(ls *.c | sort); do echo "'$i',"; done

dilithium_armv8 = files([
	'dilithium_intt_armv8.S',
	'dilithium_ntt_armv8.S',
	'dilithium_poly.c',
	'dilithium_poly_armv8.S',
	'dilithium_signature_api_armv8.c',
	'dilithium_signature_armv8.c'
])

leancrypto_dilithium_armv8_lib = static_library(
		'leancrypto_dilithium_armv8_lib',
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

leancrypto_support_libs += leancrypto_dilithium_armv8_lib
