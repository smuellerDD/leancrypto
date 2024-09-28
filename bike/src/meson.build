# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
if (get_option('bike_5').enabled() or
    get_option('bike_3').enabled() or
    get_option('bike_1').enabled())
	src += files([
		'bike_api.c',
	])
endif


bike_src = files([
	'bike_decode.c',
	'bike_decode_portable.c',
	'bike_gf2x_inv.c',
	'bike_gf2x_ksqr_portable.c',
	'bike_gf2x_mul.c',
	'bike_gf2x_mul_base_portable.c',
	'bike_gf2x_mul_portable.c',
	'bike_sampling.c',
	'bike_sampling_portable.c'
])

bike_src_xor = files([
	'bike_kem.c',
])

bike_avx2_src = [
		'bike_decode_avx2.c',
		'bike_gf2x_mul_avx2.c',
		'bike_gf2x_ksqr_avx2.c',
		'bike_sampling_avx2.c',
	]
bike_avx512_src = [
		'bike_decode_avx512.c',
		'bike_gf2x_mul_avx512.c',
		'bike_gf2x_ksqr_avx512.c',
		'bike_sampling_avx512.c',
	]
bike_pclmul_src = [
		'bike_gf2x_mul_base_pclmul.c',
	]
bike_vpclmul_src = [
		'bike_gf2x_mul_base_vpclmul.c',
	]


bike_args = [ '-funroll-loops' ]

if (host_machine.cpu_family() == 'x86_64')
	bike_args += [ '-mno-red-zone', '-DX86_64' ]
endif

#bike_args += [ '-DUNIFORM_SAMPLING=1' ]
#bike_args += [ '-DBIND_PK_AND_M=1' ]

if get_option('bike_5').enabled()
	if x86_64_asm
		bike_avx2_src += bike_src_xor

		leancrypto_bike_5_avx2_lib = static_library(
			'leancrypto_bike_5_avx2_lib',
			[ bike_avx2_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_avx2_args ]
		)
		leancrypto_support_libs += leancrypto_bike_5_avx2_lib

		leancrypto_bike_5_avx512_lib = static_library(
			'leancrypto_bike_5_avx512_lib',
			[ bike_avx512_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_avx512_args,
				   '-mavx512bw', '-mavx512dq' ]
		)
		leancrypto_support_libs += leancrypto_bike_5_avx512_lib

		leancrypto_bike_5_pclmul_lib = static_library(
			'leancrypto_bike_5_pclmul_lib',
			[ bike_pclmul_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, '-mpclmul' ]
		)
		leancrypto_support_libs += leancrypto_bike_5_pclmul_lib

		leancrypto_bike_5_vpclmul_lib = static_library(
			'leancrypto_bike_5_vpclmul_lib',
			[ bike_vpclmul_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_avx512_args,
				   '-mvpclmulqdq' ]
		)
		leancrypto_support_libs += leancrypto_bike_5_vpclmul_lib
	elif arm64_asm
		leancrypto_bike_5_armv8_lib = static_library(
			'leancrypto_bike_5_armv8_lib',
			[ bike_src_xor ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_armv8_neon_simd_args ]
		)
		leancrypto_support_libs += leancrypto_bike_5_armv8_lib
	elif arm32_neon_asm
		leancrypto_bike_5_armv7_lib = static_library(
			'leancrypto_bike_5_armv7_lib',
			[ bike_src_xor ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_armv7_neon_simd_args ]
		)
		leancrypto_support_libs += leancrypto_bike_5_armv7_lib
	else
		bike_src += bike_src_xor
	endif

	leancrypto_bike_5_c_lib = static_library(
		'leancrypto_bike_5_c_lib',
		[ bike_src ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : bike_args
	)
	leancrypto_support_libs += leancrypto_bike_5_c_lib
endif

if get_option('bike_3').enabled()
	if x86_64_asm
		leancrypto_bike_3_avx2_lib = static_library(
			'leancrypto_bike_3_avx2_lib',
			[ bike_avx2_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_avx2_args, '-DLC_BIKE_TYPE_3' ]
		)
		leancrypto_support_libs += leancrypto_bike_3_avx2_lib

		leancrypto_bike_3_avx512_lib = static_library(
			'leancrypto_bike_3_avx512_lib',
			[ bike_avx512_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_avx512_args,
				   '-DLC_BIKE_TYPE_3',
				   '-mavx512bw', '-mavx512dq' ]
		)
		leancrypto_support_libs += leancrypto_bike_3_avx512_lib

		leancrypto_bike_3_pclmul_lib = static_library(
			'leancrypto_bike_3_pclmul_lib',
			[ bike_pclmul_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, '-DLC_BIKE_TYPE_3', '-mpclmul' ]
		)
		leancrypto_support_libs += leancrypto_bike_3_pclmul_lib

		leancrypto_bike_3_vpclmul_lib = static_library(
			'leancrypto_bike_3_vpclmul_lib',
			[ bike_vpclmul_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_avx512_args,
				   '-DLC_BIKE_TYPE_3', '-mvpclmulqdq' ]
		)
		leancrypto_support_libs += leancrypto_bike_3_vpclmul_lib
	elif arm64_asm
		leancrypto_bike_3_armv8_lib = static_library(
			'leancrypto_bike_3_armv8_lib',
			[ bike_src_xor ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_armv8_neon_simd_args,
				   '-DLC_BIKE_TYPE_3' ]
		)
		leancrypto_support_libs += leancrypto_bike_3_armv8_lib
	elif arm32_neon_asm
		leancrypto_bike_3_armv7_lib = static_library(
			'leancrypto_bike_3_armv7_lib',
			[ bike_src_xor ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_armv7_neon_simd_args,
				   '-DLC_BIKE_TYPE_3' ]
		)
		leancrypto_support_libs += leancrypto_bike_3_armv7_lib
	else
		bike_src += bike_src_xor
	endif

	leancrypto_bike_3_c_lib = static_library(
		'leancrypto_bike_3_c_lib',
		[ bike_src ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : [ bike_args, '-DLC_BIKE_TYPE_3' ]
	)
	leancrypto_support_libs += leancrypto_bike_3_c_lib
endif

if get_option('bike_1').enabled()
	if x86_64_asm
		leancrypto_bike_1_avx2_lib = static_library(
			'leancrypto_bike_1_avx2_lib',
			[ bike_avx2_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_avx2_args, '-DLC_BIKE_TYPE_1' ]
		)
		leancrypto_support_libs += leancrypto_bike_1_avx2_lib

		leancrypto_bike_1_avx512_lib = static_library(
			'leancrypto_bike_1_avx512_lib',
			[ bike_avx512_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_avx512_args,
				   '-DLC_BIKE_TYPE_1',
				   '-mavx512bw', '-mavx512dq' ]
		)
		leancrypto_support_libs += leancrypto_bike_1_avx512_lib

		leancrypto_bike_1_pclmul_lib = static_library(
			'leancrypto_bike_1_pclmul_lib',
			[ bike_pclmul_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, '-DLC_BIKE_TYPE_1', '-mpclmul' ]
		)
		leancrypto_support_libs += leancrypto_bike_1_pclmul_lib

		leancrypto_bike_1_vpclmul_lib = static_library(
			'leancrypto_bike_1_vpclmul_lib',
			[ bike_vpclmul_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_avx512_args,
				   '-DLC_BIKE_TYPE_1', '-mvpclmulqdq' ]
		)
		leancrypto_support_libs += leancrypto_bike_1_vpclmul_lib
	elif arm64_asm
		leancrypto_bike_1_armv8_lib = static_library(
			'leancrypto_bike_1_armv8_lib',
			[ bike_src_xor ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_armv8_neon_simd_args,
				   '-DLC_BIKE_TYPE_1']
		)
		leancrypto_support_libs += leancrypto_bike_1_armv8_lib
	elif arm32_neon_asm
		leancrypto_bike_1_armv7_lib = static_library(
			'leancrypto_bike_1_armv7_lib',
			[ bike_src_xor ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			c_args : [ bike_args, cc_armv7_neon_simd_args,
				   '-DLC_BIKE_TYPE_1' ]
		)
		leancrypto_support_libs += leancrypto_bike_1_armv7_lib
	else
		bike_src += bike_src_xor
	endif

	leancrypto_bike_1_c_lib = static_library(
		'leancrypto_bike_1_c_lib',
		[ bike_src ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : [ bike_args, '-DLC_BIKE_TYPE_1' ]
	)
	leancrypto_support_libs += leancrypto_bike_1_c_lib
endif
