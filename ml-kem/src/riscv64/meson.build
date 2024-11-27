# for i in $(ls *.c | sort); do echo "'$i',"; done

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
	leancrypto_support_libs_fips += leancrypto_kyber_common_riscv_lib
endif
