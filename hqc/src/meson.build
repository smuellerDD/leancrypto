# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
if (get_option('hqc_256').enabled() or
    get_option('hqc_192').enabled() or
    get_option('hqc_128').enabled())
	src += files([
		'hqc_api.c',
		'shake_prng.c',
	])
endif

hqc_src = files([
	'code.c',
	'fft.c',
	'gf.c',
	'gf2x.c',
	'hqc.c',
	'hqc_kem.c',
	'parsing.c',
	'reed_muller.c',
	'reed_solomon.c',
	'vector.c'
])

if get_option('hqc_256').enabled()
	leancrypto_hqc_256_c_lib = static_library(
		'leancrypto_hqc_256_c_lib',
		[ hqc_src ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
	)
	leancrypto_support_libs += leancrypto_hqc_256_c_lib
endif

if get_option('hqc_192').enabled()
	leancrypto_hqc_192_c_lib = static_library(
		'leancrypto_hqc_192_c_lib',
		[ hqc_src ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : [ '-DLC_HQC_TYPE_192' ]
	)
	leancrypto_support_libs += leancrypto_hqc_192_c_lib
endif

if get_option('hqc_128').enabled()
	leancrypto_hqc_128_c_lib = static_library(
		'leancrypto_hqc_128_c_lib',
		[ hqc_src ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : [ '-DLC_HQC_TYPE_128' ]
	)
	leancrypto_support_libs += leancrypto_hqc_128_c_lib
endif
