# Files which are compiled once
src += files([
	'dilithium_consts_rvv.c',
	'dilithium_zetas_riscv64.c'
	])

# Files which are compiled for each Dilithium implementation separately
dilithium_riscv64_asm = files([
	'dilithium_signature_api_riscv64.c',
	'dilithium_signature_riscv64.c',
	'ntt_8l_dualissue_plant_rv64im.S'
])

dilithium_riscv64_rvv_asm = files([
	'dilithium_signature_riscv64_rvv.c',
	'ntt_rvv.S'
])

if get_option('dilithium_87').enabled()
	leancrypto_dilithium_87_riscv64_lib = static_library(
		'leancrypto_dilithium_87_riscv64_lib',
		[ dilithium_riscv64_asm ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
		c_args: cc_riscv64_asm_args,
	)

	leancrypto_support_libs += leancrypto_dilithium_87_riscv64_lib

	leancrypto_dilithium_87_riscv64_rvv_lib = static_library(
		'leancrypto_dilithium_87_riscv64_rvv_lib',
		[ dilithium_riscv64_rvv_asm ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
		c_args: [ cc_riscv64_asm_rvv_args, '-DLC_DILITHIUM_RISCV64_RVV' ]
	)

	leancrypto_support_libs += leancrypto_dilithium_87_riscv64_rvv_lib
endif

if get_option('dilithium_65').enabled()
	leancrypto_dilithium_65_riscv64_lib = static_library(
		'leancrypto_dilithium_65_riscv64_lib',
		[ dilithium_riscv64_asm ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
		c_args: [ cc_riscv64_asm_args, '-DLC_DILITHIUM_TYPE_65' ]
	)

	leancrypto_support_libs += leancrypto_dilithium_65_riscv64_lib

	leancrypto_dilithium_65_riscv64_rvv_lib = static_library(
		'leancrypto_dilithium_65_riscv64_rvv_lib',
		[ dilithium_riscv64_rvv_asm ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
		c_args: [ cc_riscv64_asm_rvv_args, '-DLC_DILITHIUM_RISCV64_RVV',
			  '-DLC_DILITHIUM_TYPE_65' ]
	)

	leancrypto_support_libs += leancrypto_dilithium_65_riscv64_rvv_lib
endif

if get_option('dilithium_44').enabled()
	leancrypto_dilithium_44_riscv64_lib = static_library(
		'leancrypto_dilithium_44_riscv64_lib',
		[ dilithium_riscv64_asm ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
		c_args: [ cc_riscv64_asm_args, '-DLC_DILITHIUM_TYPE_44' ]
	)

	leancrypto_support_libs += leancrypto_dilithium_44_riscv64_lib

	leancrypto_dilithium_44_riscv64_rvv_lib = static_library(
		'leancrypto_dilithium_44_riscv64_rvv_lib',
		[ dilithium_riscv64_rvv_asm ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
		c_args: [ cc_riscv64_asm_rvv_args, '-DLC_DILITHIUM_RISCV64_RVV',
			  '-DLC_DILITHIUM_TYPE_44' ]
	)

	leancrypto_support_libs += leancrypto_dilithium_44_riscv64_rvv_lib
endif
