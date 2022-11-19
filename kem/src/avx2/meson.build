# for i in $(ls *.c | sort); do echo "'$i',"; done

kyber_avx2 = files([
	'kyber_basemul_avx2.S',
	'kyber_cbd_avx2.c',
	'kyber_consts_avx2.c',
	'kyber_fq_avx2.S',
	'kyber_indcpa_avx2.c',
	'kyber_invntt_avx2.S',
	'kyber_kem_api_avx2.c',
	'kyber_kem_avx2.c',
	'kyber_ntt_avx2.S',
	'kyber_poly_avx2.c',
	'kyber_rejsample_avx2.c',
	'kyber_shuffle_avx2.S',
])

leancrypto_kyber_avx2_lib = static_library(
		'leancrypto_kyber_avx2_lib',
		[ kyber_avx2 ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
		c_args: [
			'-mavx2',
			'-mbmi2',
			'-mpopcnt',
			'-Wno-unused-command-line-argument'
		]
	)
leancrypto_support_libs += leancrypto_kyber_avx2_lib
