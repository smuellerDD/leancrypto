# for i in $(ls *.c | sort); do echo "'$i',"; done

hqc_src_avx2 = files([
	'code_avx2.c',
	'fft_avx2.c',
	'gf_avx2.c',
	'gf2x_avx2.c',
	'hqc_avx2.c',
	'hqc_kem_api_avx2.c',
	'hqc_kem_avx2.c',
	'parsing_avx2.c',
	'reed_muller_avx2.c',
	'reed_solomon_avx2.c',
        'vector_avx2.c'
])

hqc_avx2_args = [ cc_avx2_args, '-mbmi', '-mpclmul' ]
if get_option('hqc_256').enabled()
	leancrypto_hqc_256_avx2_lib = static_library(
		'leancrypto_hqc_256_avx2_lib',
		[ hqc_src_avx2 ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args: hqc_avx2_args
	)
	leancrypto_support_libs += leancrypto_hqc_256_avx2_lib
endif

if get_option('hqc_192').enabled()
	leancrypto_hqc_192_avx2_lib = static_library(
		'leancrypto_hqc_192_avx2_lib',
		[ hqc_src_avx2 ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : [ hqc_avx2_args, '-DLC_HQC_TYPE_192' ]
	)
	leancrypto_support_libs += leancrypto_hqc_192_avx2_lib
endif

if get_option('hqc_128').enabled()
	leancrypto_hqc_128_avx2_lib = static_library(
		'leancrypto_hqc_128_avx2_lib',
		[ hqc_src_avx2 ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : [ hqc_avx2_args, '-DLC_HQC_TYPE_128' ]
	)
	leancrypto_support_libs += leancrypto_hqc_128_avx2_lib
endif
