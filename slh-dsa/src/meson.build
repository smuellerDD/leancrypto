# for i in $(ls *.c | sort); do echo "'$i',"; done

sphincs_src = files([
	'sphincs_address.c',
	'sphincs_fors.c',
	'sphincs_hash_shake.c',
	'sphincs_merkle.c',
	'sphincs_sign.c',
	'sphincs_thash_shake_robust.c',
	'sphincs_utils.c',
	'sphincs_utilsx1.c',
	'sphincs_wots.c',
	'sphincs_wotsx1.c'
])

if get_option('sphincs_shake_256s').enabled()
	leancrypto_sphincs_shake_256s_c_lib = static_library(
		'leancrypto_sphincs_shake_256s_c_lib',
		[ sphincs_src ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_256s_c_lib
endif

if get_option('sphincs_shake_256f').enabled()
	leancrypto_sphincs_shake_256f_c_lib = static_library(
		'leancrypto_sphincs_shake_256f_c_lib',
		[ sphincs_src ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : '-DLC_SPHINCS_TYPE_256F'
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_256f_c_lib
endif

if get_option('sphincs_shake_192s').enabled()
	leancrypto_sphincs_shake_192s_c_lib = static_library(
		'leancrypto_sphincs_shake_192s_c_lib',
		[ sphincs_src ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : '-DLC_SPHINCS_TYPE_192S'
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_192s_c_lib
endif

if get_option('sphincs_shake_192f').enabled()
	leancrypto_sphincs_shake_192f_c_lib = static_library(
		'leancrypto_sphincs_shake_192f_c_lib',
		[ sphincs_src ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : '-DLC_SPHINCS_TYPE_192F'
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_192f_c_lib
endif
