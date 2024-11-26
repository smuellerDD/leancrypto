# for i in $(ls *.c | sort); do echo "'$i',"; done
src += files([
	'dilithium_zetas_riscv64.c'
	])

# Files which are compiled for each Dilithium implementation separately
dilithium_riscv64 = files([
	'dilithium_signature_api_riscv64.c',
	'dilithium_signature_riscv64.c',
	'ntt_8l_dualissue_plant_rv64im.S'
])

if get_option('dilithium_87').enabled()
	leancrypto_dilithium_87_riscv64_lib = static_library(
			'leancrypto_dilithium_87_riscv64_lib',
			[ dilithium_riscv64 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
	 		c_args: cc_riscv64_asm_args,
		)

	leancrypto_support_libs += leancrypto_dilithium_87_riscv64_lib
endif

if get_option('dilithium_65').enabled()
	leancrypto_dilithium_65_riscv64_lib = static_library(
			'leancrypto_dilithium_65_riscv64_lib',
			[ dilithium_riscv64 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args: [ cc_riscv64_asm_args, '-DLC_DILITHIUM_TYPE_65' ]
		)

	leancrypto_support_libs += leancrypto_dilithium_65_riscv64_lib
endif

if get_option('dilithium_44').enabled()
	leancrypto_dilithium_44_riscv64_lib = static_library(
			'leancrypto_dilithium_44_riscv64_lib',
			[ dilithium_riscv64 ],
			include_directories: [
				'../',
				include_dirs,
				include_internal_dirs
			],
			c_args: [ cc_riscv64_asm_args, '-DLC_DILITHIUM_TYPE_44' ]
		)

	leancrypto_support_libs += leancrypto_dilithium_44_riscv64_lib
endif
