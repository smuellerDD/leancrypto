# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
if (get_option('sphincs_shake_256s').enabled() or
    get_option('sphincs_shake_256f').enabled() or
    get_option('sphincs_shake_192s').enabled() or
    get_option('sphincs_shake_192f').enabled() or
    get_option('sphincs_shake_128s').enabled() or
    get_option('sphincs_shake_128f').enabled())
	src += files([
		'sphincs_pct.c',
	])
endif

sphincs_src = files([
	'sphincs_address.c',
	'sphincs_fors.c',
	'sphincs_hash_shake.c',
	'sphincs_merkle.c',
	'sphincs_sign.c',
	'sphincs_signature_helper.c',
	'sphincs_thash_shake_robust.c',
	'sphincs_utils.c',
	'sphincs_utilsx1.c',
	'sphincs_wots.c',
	'sphincs_wotsx1.c',
])

sphincs_src_avx2 = files([
	'avx2/sphincs_fors_avx2.c',
	'avx2/sphincs_hash_shakex4_avx2.c',
	'avx2/sphincs_merkle_avx2.c',
	'avx2/sphincs_thash_shake_robustx4_avx2.c',
	'avx2/sphincs_utilsx4_avx2.c',
	'avx2/sphincs_wots_avx2.c',
])

sphincs_src_armv8 = files([
	'armv8/sphincs_fors_armv8.c',
	'armv8/sphincs_hash_shakex2_armv8.c',
	'armv8/sphincs_merkle_armv8.c',
	'armv8/sphincs_thash_shake_robustx2_armv8.c',
	'armv8/sphincs_utilsx2_armv8.c',
	'armv8/sphincs_wots_armv8.c',
])

sphincs_include_dirs = '../'

if get_option('sphincs_shake_256s').enabled()
	if x86_64_asm
		leancrypto_sphincs_shake_256s_avx2_lib = static_library(
			'leancrypto_sphincs_shake_256s_avx2_lib',
			[ sphincs_src_avx2 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_avx2_args ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_256s_avx2_lib
	endif

	if arm64_asm
		leancrypto_sphincs_shake_256s_armv8_lib = static_library(
			'leancrypto_sphincs_shake_256s_armv8_lib',
			[ sphincs_src_armv8 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_armv8_neon_simd_args ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_256s_armv8_lib
	endif

	leancrypto_sphincs_shake_256s_c_lib = static_library(
		'leancrypto_sphincs_shake_256s_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_256s_c_lib
endif

if get_option('sphincs_shake_256f').enabled()
	if x86_64_asm
		leancrypto_sphincs_shake_256f_avx2_lib = static_library(
			'leancrypto_sphincs_shake_256f_avx2_lib',
			[ sphincs_src_avx2 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_avx2_args, '-DLC_SPHINCS_TYPE_256F' ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_256f_avx2_lib
	endif

	if arm64_asm
		leancrypto_sphincs_shake_256f_armv8_lib = static_library(
			'leancrypto_sphincs_shake_256f_armv8_lib',
			[ sphincs_src_armv8 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_armv8_neon_simd_args,
				   '-DLC_SPHINCS_TYPE_256F' ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_256f_armv8_lib
	endif

	leancrypto_sphincs_shake_256f_c_lib = static_library(
		'leancrypto_sphincs_shake_256f_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
		c_args : [ '-DLC_SPHINCS_TYPE_256F' ]
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_256f_c_lib
endif

if get_option('sphincs_shake_192s').enabled()
	if x86_64_asm
		leancrypto_sphincs_shake_192s_avx2_lib = static_library(
			'leancrypto_sphincs_shake_192s_avx2_lib',
			[ sphincs_src_avx2 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_avx2_args, '-DLC_SPHINCS_TYPE_192S' ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_192s_avx2_lib
	endif

	if arm64_asm
		leancrypto_sphincs_shake_192s_armv8_lib = static_library(
			'leancrypto_sphincs_shake_192s_armv8_lib',
			[ sphincs_src_armv8 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_armv8_neon_simd_args,
				   '-DLC_SPHINCS_TYPE_192S' ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_192s_armv8_lib
	endif

	leancrypto_sphincs_shake_192s_c_lib = static_library(
		'leancrypto_sphincs_shake_192s_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
		c_args : [ '-DLC_SPHINCS_TYPE_192S' ]
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_192s_c_lib
endif

if get_option('sphincs_shake_192f').enabled()
	if x86_64_asm
		leancrypto_sphincs_shake_192f_avx2_lib = static_library(
			'leancrypto_sphincs_shake_192f_avx2_lib',
			[ sphincs_src_avx2 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_avx2_args, '-DLC_SPHINCS_TYPE_192F' ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_192f_avx2_lib
	endif

	if arm64_asm
		leancrypto_sphincs_shake_192f_armv8_lib = static_library(
			'leancrypto_sphincs_shake_192f_armv8_lib',
			[ sphincs_src_armv8 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_armv8_neon_simd_args,
				   '-DLC_SPHINCS_TYPE_192F' ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_192f_armv8_lib
	endif

	leancrypto_sphincs_shake_192f_c_lib = static_library(
		'leancrypto_sphincs_shake_192f_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
		c_args : [ '-DLC_SPHINCS_TYPE_192F' ]
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_192f_c_lib
endif

if get_option('sphincs_shake_128s').enabled()
	if x86_64_asm
		leancrypto_sphincs_shake_128s_avx2_lib = static_library(
			'leancrypto_sphincs_shake_128s_avx2_lib',
			[ sphincs_src_avx2 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_avx2_args, '-DLC_SPHINCS_TYPE_128S' ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_128s_avx2_lib
	endif

	if arm64_asm
		leancrypto_sphincs_shake_128s_armv8_lib = static_library(
			'leancrypto_sphincs_shake_128s_armv8_lib',
			[ sphincs_src_armv8 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_armv8_neon_simd_args,
				   '-DLC_SPHINCS_TYPE_128S' ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_128s_armv8_lib
	endif

	leancrypto_sphincs_shake_128s_c_lib = static_library(
		'leancrypto_sphincs_shake_128s_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
		c_args : [ '-DLC_SPHINCS_TYPE_128S' ]
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_128s_c_lib
endif

if get_option('sphincs_shake_128f').enabled()
	if x86_64_asm
		leancrypto_sphincs_shake_128f_avx2_lib = static_library(
			'leancrypto_sphincs_shake_128f_avx2_lib',
			[ sphincs_src_avx2 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_avx2_args, '-DLC_SPHINCS_TYPE_128F' ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_128f_avx2_lib
	endif

	if arm64_asm
		leancrypto_sphincs_shake_128f_armv8_lib = static_library(
			'leancrypto_sphincs_shake_128f_armv8_lib',
			[ sphincs_src_armv8 ],
			include_directories: [
				sphincs_include_dirs,
				include_dirs,
				include_internal_dirs
			],
			c_args : [ cc_armv8_neon_simd_args,
				   '-DLC_SPHINCS_TYPE_128F' ]
		)
		leancrypto_support_libs += leancrypto_sphincs_shake_128f_armv8_lib
	endif

	leancrypto_sphincs_shake_128f_c_lib = static_library(
		'leancrypto_sphincs_shake_128f_c_lib',
		[ sphincs_src ],
		include_directories: [
			sphincs_include_dirs,
			include_dirs,
			include_internal_dirs
		],
		c_args : [ '-DLC_SPHINCS_TYPE_128F' ]
	)
	leancrypto_support_libs += leancrypto_sphincs_shake_128f_c_lib
endif
