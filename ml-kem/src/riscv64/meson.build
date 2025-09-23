kyber_riscv_rvv_c_args = []

kyber_riscv_rvv_common = files([
	'kyber_rvv_vlen_selector.c',
	'ntt_rvv_vlen128.S',
	'ntt_rvv_vlen256.S',
	'riscv_rvv_selector_test.S'
])

kyber_riscv_riscv_api = files([
	'kyber_kem_api_riscv.c',
])

kyber_riscv_rvv_vlen128 = files([
	'kyber_indcpa_rvv_vlen128.c',
	'kyber_kem_rvv_vlen128.c',
])

kyber_riscv_rvv_vlen256 = files([
	'kyber_indcpa_rvv_vlen256.c',
	'kyber_kem_rvv_vlen256.c',
])

if get_option('riscv_rvv_vlen128').enabled()
	kyber_riscv_rvv_c_args += [ '-DLC_KYBER_RISCV_RVV_VLEN128' ]
	kyber_riscv_rvv_common += files([
		'kyber_consts_rvv_vlen128.c',
	])
endif

if get_option('riscv_rvv_vlen256').enabled()
	kyber_riscv_rvv_c_args += [ '-DLC_KYBER_RISCV_RVV_VLEN256' ]
	kyber_riscv_rvv_common += files([
		'kyber_consts_rvv_vlen256.c',
	])
endif

# Files compiled only once
if (get_option('kyber_1024').enabled() or
    get_option('kyber_768').enabled() or
    get_option('kyber_512').enabled())
	kyber_riscv_common = files([
		'kyber_zetas_riscv.c',
		'ntt_dualissue_plant_rv64im.S'
	])

	leancrypto_kyber_common_riscv_lib = static_library(
			'leancrypto_kyber_common_riscv_lib',
			[ kyber_riscv_common ],
			c_args: cc_riscv64_asm_args,
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
		)
	leancrypto_support_libs += leancrypto_kyber_common_riscv_lib

	leancrypto_kyber_riscv_rvv_lib = static_library(
			'leancrypto_kyber_riscv_rvv_lib',
			[ kyber_riscv_rvv_common ],
			c_args: [ cc_riscv64_asm_rvv_args,
				  kyber_riscv_rvv_c_args ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
		)
	leancrypto_support_libs += leancrypto_kyber_riscv_rvv_lib
endif

# Kyber RISCV API
if get_option('kyber_1024').enabled()
	kyber_1024_files = kyber_riscv_riscv_api

	leancrypto_kyber_1024_riscv_lib = static_library(
		'leancrypto_kyber_1024_riscv_lib',
		[ kyber_1024_files ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
	)
	leancrypto_support_libs += leancrypto_kyber_1024_riscv_lib
endif

if get_option('kyber_768').enabled()
	kyber_768_files = kyber_riscv_riscv_api

	leancrypto_kyber_768_riscv_lib = static_library(
		'leancrypto_kyber_768_riscv_lib',
		[ kyber_768_files ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
		c_args : [ '-DLC_KYBER_TYPE_768']
	)
	leancrypto_support_libs += leancrypto_kyber_768_riscv_lib
endif

if get_option('kyber_512').enabled()
	kyber_512_files = kyber_riscv_riscv_api

	leancrypto_kyber_512_riscv_lib = static_library(
		'leancrypto_kyber_512_riscv_lib',
		[ kyber_512_files ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
		c_args : [ '-DLC_KYBER_TYPE_512' ]
	)
	leancrypto_support_libs += leancrypto_kyber_512_riscv_lib
endif

# Kyber RVV vector length 128
if get_option('riscv_rvv_vlen128').enabled()
	if get_option('kyber_1024').enabled()
		kyber_1024_files = kyber_riscv_rvv_vlen128

		leancrypto_kyber_1024_riscv_rvv_vlen128_lib = static_library(
			'leancrypto_kyber_1024_riscv_rvv_vlen128_lib',
			[ kyber_1024_files ],
			c_args: [ kyber_riscv_rvv_c_args ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
		)
		leancrypto_support_libs += leancrypto_kyber_1024_riscv_rvv_vlen128_lib
	endif

	if get_option('kyber_768').enabled()
		kyber_768_files = kyber_riscv_rvv_vlen128

		leancrypto_kyber_768_riscv_rvv_vlen128_lib = static_library(
			'leancrypto_kyber_768_riscv_rvv_vlen128_lib',
			[ kyber_768_files ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args : [ kyber_riscv_rvv_c_args, '-DLC_KYBER_TYPE_768']
		)
		leancrypto_support_libs += leancrypto_kyber_768_riscv_rvv_vlen128_lib
	endif

	if get_option('kyber_512').enabled()
		kyber_512_files = kyber_riscv_rvv_vlen128

		leancrypto_kyber_512_riscv_rvv_vlen128_lib = static_library(
			'leancrypto_kyber_512_riscv_rvv_vlen128_lib',
			[ kyber_512_files ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args : [kyber_riscv_rvv_c_args, '-DLC_KYBER_TYPE_512' ]
		)
		leancrypto_support_libs += leancrypto_kyber_512_riscv_rvv_vlen128_lib
	endif
endif

# Kyber RVV vector length 256
if get_option('riscv_rvv_vlen256').enabled()
	if get_option('kyber_1024').enabled()
		kyber_1024_files = kyber_riscv_rvv_vlen256

		leancrypto_kyber_1024_riscv_rvv_vlen256_lib = static_library(
			'leancrypto_kyber_1024_riscv_rvv_vlen256_lib',
			[ kyber_1024_files ],
			c_args: [ kyber_riscv_rvv_c_args ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
		)
		leancrypto_support_libs += leancrypto_kyber_1024_riscv_rvv_vlen256_lib
	endif

	if get_option('kyber_768').enabled()
		kyber_768_files = kyber_riscv_rvv_vlen256

		leancrypto_kyber_768_riscv_rvv_vlen256_lib = static_library(
			'leancrypto_kyber_768_riscv_rvv_vlen256_lib',
			[ kyber_768_files ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args : [ kyber_riscv_rvv_c_args, '-DLC_KYBER_TYPE_768']
		)
		leancrypto_support_libs += leancrypto_kyber_768_riscv_rvv_vlen256_lib
	endif

	if get_option('kyber_512').enabled()
		kyber_512_files = kyber_riscv_rvv_vlen256

		leancrypto_kyber_512_riscv_rvv_vlen256_lib = static_library(
			'leancrypto_kyber_512_riscv_rvv_vlen256_lib',
			[ kyber_512_files ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args : [kyber_riscv_rvv_c_args, '-DLC_KYBER_TYPE_512' ]
		)
		leancrypto_support_libs += leancrypto_kyber_512_riscv_rvv_vlen256_lib
	endif
endif
