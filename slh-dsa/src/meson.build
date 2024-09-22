# for i in $(ls *.c | sort); do echo "'$i',"; done

sphincs_src = files([
	'sphincs_address.c',
	#'sphincs_fors.c',
	'sphincs_hash_shake.c',
	#'sphincs_merkle.c',
	'sphincs_sign.c',
	'sphincs_thash_shake_robust.c',
	'sphincs_utils.c',
	'sphincs_utilsx1.c',
	#'sphincs_wots.c',
	'sphincs_wotsx1.c',


	'avx2/sphincs_fors_avx2.c',
	'avx2/sphincs_hash_shakex4_avx2.c',
	'avx2/sphincs_merkle_avx2.c',
	'avx2/sphincs_thash_shake_robustx4_avx2.c',
	'avx2/sphincs_utilsx4_avx2.c',
	'avx2/sphincs_wots_avx2.c',
])

sphincs_src_avx2 = files([
	'avx2/sphincs_fors_avx2.c',
])

spincs_args = []

sphincs_include_dirs = '../'

spincs_args += cc_avx2_args

if get_option('sphincs_shake_256s').enabled()
	leancrypto_sphincs_shake_256s_c_lib = static_library(
		'leancrypto_sphincs_shake_256s_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
		c_args : [ spincs_args ]
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_256s_c_lib
endif

if get_option('sphincs_shake_256f').enabled()
	leancrypto_sphincs_shake_256f_c_lib = static_library(
		'leancrypto_sphincs_shake_256f_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
		c_args : [ spincs_args, '-DLC_SPHINCS_TYPE_256F' ]
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_256f_c_lib
endif

if get_option('sphincs_shake_192s').enabled()
	leancrypto_sphincs_shake_192s_c_lib = static_library(
		'leancrypto_sphincs_shake_192s_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
		c_args : [ spincs_args, '-DLC_SPHINCS_TYPE_192S' ]
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_192s_c_lib
endif

if get_option('sphincs_shake_192f').enabled()
	leancrypto_sphincs_shake_192f_c_lib = static_library(
		'leancrypto_sphincs_shake_192f_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
		c_args : [ spincs_args, '-DLC_SPHINCS_TYPE_192F' ]
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_192f_c_lib
endif

if get_option('sphincs_shake_128s').enabled()
	leancrypto_sphincs_shake_128s_c_lib = static_library(
		'leancrypto_sphincs_shake_128s_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
		c_args : [ spincs_args, '-DLC_SPHINCS_TYPE_128S' ]
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_128s_c_lib
endif

if get_option('sphincs_shake_128f').enabled()
	leancrypto_sphincs_shake_128f_c_lib = static_library(
		'leancrypto_sphincs_shake_128f_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
		c_args : [ spincs_args, '-DLC_SPHINCS_TYPE_128F' ]
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_128f_c_lib
endif
