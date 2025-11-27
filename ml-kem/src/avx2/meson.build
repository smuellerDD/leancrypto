# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
kyber_avx2_common = files([
	'kyber_consts_avx2.c',
	'kyber_cbd_avx2.c',
])

# Files which are compiled for each Kyber implementation separately
kyber_avx2 = files([
	'kyber_basemul_avx2.S',
	'kyber_fq_avx2.S',
	'kyber_indcpa_avx2.c',
	'kyber_invntt_avx2.S',
	'kyber_kem_avx2.c',
	'kyber_ntt_avx2.S',
	'kyber_poly_avx2.c',
	'kyber_rejsample_avx2.c',
	'kyber_shuffle_avx2.S',
])

if (get_option('kyber_1024').enabled() or get_option('kyber_768').enabled())
	leancrypto_kyber_common_avx2_lib = static_library(
			'leancrypto_kyber_common_avx2_lib',
			[ kyber_avx2_common ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args: cc_avx2_args
		)
	leancrypto_support_libs += leancrypto_kyber_common_avx2_lib
endif

if get_option('kyber_1024').enabled()
	leancrypto_kyber_1024_avx2_lib = static_library(
			'leancrypto_kyber_1024_avx2_lib',
			[ kyber_avx2 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args: cc_avx2_args
		)
	leancrypto_support_libs += leancrypto_kyber_1024_avx2_lib
endif

if get_option('kyber_768').enabled()
	leancrypto_kyber_768_avx2_lib = static_library(
			'leancrypto_kyber_768_avx2_lib',
			[ kyber_avx2 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args: [ cc_avx2_args, '-DLC_KYBER_TYPE_768' ]
		)
	leancrypto_support_libs += leancrypto_kyber_768_avx2_lib
endif

# Support for Kyber-512 is not implemented
