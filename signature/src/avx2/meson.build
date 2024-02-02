# for i in $(ls *.c | sort); do echo "'$i',"; done

dilithium_avx2 = files([
	'dilithium_consts_avx2.c',
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

leancrypto_dilithium_avx2_lib = static_library(
		'leancrypto_dilithium_avx2_lib',
		[ dilithium_avx2 ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
		c_args: cc_avx2_args
	)

#-Wl,--whole-archive kem/src/avx2/libleancrypto_kyber_avx2_lib.a -Wl,--no-whole-archive

leancrypto_support_libs += leancrypto_dilithium_avx2_lib
