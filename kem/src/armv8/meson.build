# for i in $(ls *.c | sort); do echo "'$i',"; done

kyber_armv8 = files([
	'kyber_add_armv8.S',
	'kyber_basemul_armv8.S',
	'kyber_cbd_armv8.S',
	'kyber_indcpa_armv8.c',
	'kyber_inv_ntt_armv8.S',
	'kyber_kem_api_armv8.c',
	'kyber_kem_armv8.c',
	'kyber_ntt_armv8.c',
	'kyber_ntt_armv8.S',
	'kyber_poly_armv8.c',
	'kyber_poly_armv8.S',
	'kyber_reduce_armv8.S'
])

leancrypto_kyber_armv8_lib = static_library(
		'leancrypto_kyber_armv8_lib',
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
leancrypto_support_libs += leancrypto_kyber_armv8_lib
