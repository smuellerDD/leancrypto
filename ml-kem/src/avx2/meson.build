# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
kyber_avx2_common = files([
	'kyber_consts_avx2.c',
	'kyber_cbd_avx2.c',
])

# Files which are compiled for each Kyber implementation separately
kyber_avx2 = files([
	'kyber_indcpa_avx2.c',
	'kyber_kem_avx2.c',
	'kyber_poly_avx2.c',
	'kyber_rejsample_avx2.c',
])

# Assembler files which are compiled for each Kyber implementation separately -
# see asm_unique_copy why they need a per-implementation name
kyber_avx2_asm = [
	'kyber_basemul_avx2.S',
	'kyber_fq_avx2.S',
	'kyber_invntt_avx2.S',
	'kyber_ntt_avx2.S',
	'kyber_shuffle_avx2.S',
]

kyber_1024_avx2 = kyber_avx2
kyber_768_avx2 = kyber_avx2
foreach f : kyber_avx2_asm
	if asm_unique_copy
		kyber_1024_avx2 += configure_file(input: f,
						  output: 'kyber_1024_' + f,
						  copy: true)
		kyber_768_avx2 += configure_file(input: f,
						 output: 'kyber_768_' + f,
						 copy: true)
	else
		kyber_1024_avx2 += files(f)
		kyber_768_avx2 += files(f)
	endif
endforeach

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
			[ kyber_1024_avx2 ],
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
			[ kyber_768_avx2 ],
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
