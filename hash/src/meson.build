lc_hash = 0

if get_option('sha2-256').enabled()
	src += files([ 'sha256.c', 'sha256_selector.c' ])
	include_files += files([ '../api/lc_sha256.h' ])
	lc_hash = 1

	# SHA2-256: Intel AVX2 implementation
	if (x86_64_asm)
		src += files([ 'sha256_avx2.c', 'sha256_shani.c' ])
		if (host_machine.system() == 'windows')
			src += files([ 'asm/AVX2/sha2-256-AVX2_windows.S' ])
		else
			src += files([ 'asm/AVX2/sha2-256-AVX2.S' ])
		endif
	else
		src += files([ 'sha256_avx2_null.c',
				    'sha256_shani_null.c' ])
	endif

	# 64 bit ARM processor and GCC
	if (arm64_asm)
		leancrypto_arm8a_neon_sha256_lib = static_library(
			'leancrypto_arm8a_neon_sha256_lib',
			[ 'sha256_arm_neon.c',
			  'sha256_arm_ce.c',
			  'asm/ARMv8A/sha2-256-ARMv8.S' ],
			c_args: cc_armv8_neon_simd_args,
			include_directories: [
				include_dirs,
				include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_arm8a_neon_sha256_lib
	else
		src += files([ 'sha256_arm_neon_null.c',
				    'sha256_arm_ce_null.c' ])
	endif

	# 64 bit RISCV straight assembler
	if (riscv64_asm)
		leancrypto_riscv_sha256_lib = static_library(
			'leancrypto_riscv_sha256_lib',
			[ 'sha256_riscv.c',
			  'asm/riscv64/sha2-256-riscv.S' ],
			c_args: cc_riscv64_asm_args,
			include_directories: [
				include_dirs,
				include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_riscv_sha256_lib
	else
		src += files([ 'sha256_riscv_null.c' ])
	endif

	# 64 bit RISCV ZBB assembler
	if (riscv64_asm)
		leancrypto_riscv_zbb_sha256_lib = static_library(
			'leancrypto_riscv_zbb_sha256_lib',
			[ 'sha256_riscv_zbb.c',
			  'asm/riscv64/sha2-256-riscv.S' ],
			c_args: cc_riscv64_asm_zbb_args,
			include_directories: [
				include_dirs,
				include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_riscv_zbb_sha256_lib
	else
		src += files([ 'sha256_riscv_zbb_null.c' ])
	endif
endif

if get_option('sha2-512').enabled()
	src += files([ 'sha512.c', 'sha512_selector.c' ])
	include_files += files([ '../api/lc_sha512.h' ])
	lc_hash = 1

	# SHA2-512: Intel AVX2 implementation
	if (x86_64_asm)
		src += files([ 'sha512_avx2.c', 'sha512_shani.c' ])
		if (host_machine.system() == 'windows')
			src += files([ 'asm/AVX2/sha2-512-AVX2_windows.S' ])
		else
			src += files([ 'asm/AVX2/sha2-512-AVX2.S' ])
		endif
	else
		src += files([ 'sha512_avx2_null.c',
				    'sha512_shani_null.c' ])
	endif

	# 64 bit ARM processor and GCC
	if (arm64_asm)
		leancrypto_arm_neon_sha512_lib = static_library(
			'leancrypto_arm_neon_sha512_lib',
			[ 'sha512_arm_neon.c',
			  'sha512_arm_ce.c',
			  'asm/ARMv8A/sha2-512-ARMv8.S' ],
			c_args: cc_armv8_neon_simd_args,
			include_directories: [
				include_dirs,
				include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_arm_neon_sha512_lib
	else
		src += files([ 'sha512_arm_neon_null.c',
				    'sha512_arm_ce_null.c' ])
	endif

	# 64 bit RISCV straight assembler
	if (riscv64_asm)
		leancrypto_riscv_sha512_lib = static_library(
			'leancrypto_riscv_sha512_lib',
			[ 'sha512_riscv.c',
			  'asm/riscv64/sha2-512-riscv.S' ],
			c_args: cc_riscv64_asm_args,
			include_directories: [
				include_dirs,
				include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_riscv_sha512_lib
	else
		src += files([ 'sha512_riscv_null.c' ])
	endif

	# 64 bit RISCV ZBB assembler
	if (riscv64_asm)
		leancrypto_riscv_zbb_sha512_lib = static_library(
			'leancrypto_riscv_zbb_sha512_lib',
			[ 'sha512_riscv_zbb.c',
			  'asm/riscv64/sha2-512-riscv.S' ],
			c_args: cc_riscv64_asm_zbb_args,
			include_directories: [
				include_dirs,
				include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_riscv_zbb_sha512_lib
	else
		src += files([ 'sha512_riscv_zbb_null.c' ])
	endif
endif

if get_option('sha3').enabled()

	# Non-optimized C implementatinos
	src += files([ 'cshake.c', 'sha3_selector.c', 'sha3_c.c',
			    'sha3_selftest.c' ])
	include_files += files([ '../api/lc_cshake.h', '../api/lc_sha3.h' ])
	lc_hash = 1

	# Keccak: Intel AVX2, AVX512 and 4-way SIMD implementation
	if (x86_64_asm)
		src += files([ 'sha3_avx2.c',
				    'asm/AVX2/KeccakP-1600-AVX2.S' ])
		src += files([ 'sha3_avx512.c',
				    'asm/AVX512/KeccakP-1600-AVX512.S' ])

		leancrypto_keccak_avx2_4x_lib = static_library(
			'leancrypto_keccak_avx2_4x_lib',
			[ 'shake_4x_avx2.c',
			  'asm/AVX2_4x/KeccakP-1600-times4-SIMD256.c' ],
			c_args: cc_avx2_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_keccak_avx2_4x_lib

	else
		src += files([ 'sha3_avx2_null.c' ])
		src += files([ 'sha3_avx512_null.c' ])
	endif

	# 32 bit ARM processor and GCC
	if (arm32_neon_asm)
		leancrypto_keccak_arm7a_neon_lib = static_library(
			'leancrypto_keccak_arm7a_neon_lib',
			[ 'sha3_arm_neon.c',
			  'asm/ARMv7A-NEON/KeccakP-1600-armv7a-le-neon-gcc.S' ],
			c_args: cc_armv7_neon_simd_args,
			include_directories: [
				include_directories(['asm/ARMv7A-NEON/']),
				include_dirs,
				include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_keccak_arm7a_neon_lib

	# 64 bit ARM processor and GCC
	elif (arm64_neon_gcc_asm)
		leancrypto_keccak_arm8a_neon_lib = static_library(
			'leancrypto_keccak_arm8a_neon_lib',
			[ 'sha3_arm_neon.c',
			  'asm/ARMv8A/KeccakP-1600-armv8a-neon.S' ],
			c_args: cc_armv8_neon_simd_args,
			include_directories: [
				include_directories(['asm/ARMv8A/']),
				include_dirs,
				include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_keccak_arm8a_neon_lib
	else
		src += files([ 'sha3_arm_neon_null.c' ])
	endif

	if (arm64_asm)
		src += files([ 'sha3_arm_asm.c',
				    'sha3_arm_ce.c',
				    'asm/ARMv8A/KeccakP-1600-armv8a-ce.S' ])

		# Enable once Dilithium ARMv8 support is enabled
		leancrypto_keccak_armv8_2x_ce_lib = static_library(
			'leancrypto_keccak_armv8_2x_ce_lib',
			[ 'asm/ARMv8_2x/keccakx2_armce.S' ],
			c_args: cc_armv8_neon_sha3_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_keccak_armv8_2x_ce_lib

		# Enable once Dilithium ARMv8 support is enabled
		leancrypto_keccak_armv8_2x_c_lib = static_library(
			'leancrypto_keccak_armv8_2x_c_lib',
			[ 'shake_2x_armv8.c' ],
			c_args: cc_armv8_neon_simd_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_keccak_armv8_2x_c_lib
	else
		src += files([ 'sha3_arm_asm_null.c', 'sha3_arm_ce_null.c' ])
	endif

# 	if (riscv32_gcc_asm)
# 		leancrypto_keccak_riscv_asm_lib = static_library(
# 			'leancrypto_keccak_riscv_asm_lib',
# 			[ 'sha3_riscv_asm.c', 'asm/riscv32/keccakf1600_asm.S' ],
# 			c_args: [
# 				'-march=rv32im',
# 				'-mabi=ilp32'
# 			],
# 			include_directories: [
# 				include_dirs,
# 				include_internal_dirs ],
# 		)
# 		leancrypto_support_libs += leancrypto_keccak_riscv_asm_lib
	if (riscv64_asm)
		leancrypto_keccak_riscv_asm_lib = static_library(
			'leancrypto_keccak_riscv_asm_lib',
			[ 'asm/riscv64/fips202_rv64im.S', 'sha3_riscv_asm.c' ],
			c_args: cc_riscv64_asm_args,
			include_directories: [
				include_dirs,
				include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_keccak_riscv_asm_lib

		leancrypto_keccak_riscv_zbb_lib = static_library(
			'leancrypto_keccak_riscv_zbb_lib',
			[ 'asm/riscv64/fips202_rv64imb.S', 'sha3_riscv_asm_zbb.c' ],
			c_args: cc_riscv64_asm_zbb_args,
			include_directories: [
				include_dirs,
				include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_keccak_riscv_zbb_lib
 	else
		src += files([ 'sha3_riscv_asm_null.c',
				    'sha3_riscv_asm_zbb_null.c' ])
	endif
endif

if get_option('ascon').enabled()
	src += files([
		'ascon_c.c',
		'ascon_hash_common.c',
		'ascon_selector.c',
		'ascon_selftest.c'
		])
	lc_hash = 1

	# Ascon: Intel AVX2 implementation
	if (x86_64_asm)
		leancrypto_ascon_avx512_lib = static_library(
			'leancrypto_ascon_avx512_lib',
			[ 'ascon_avx512.c' ],
			c_args: cc_avx512_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_ascon_avx512_lib

	else
		src += files([ 'ascon_avx512_null.c' ])
	endif

	# 32 bit ARM processor and GCC
	if (arm32_neon_asm)
		leancrypto_asm_arm7a_neon_lib = static_library(
			'leancrypto_asm_arm7a_neon_lib',
			[ 'ascon_arm_neon.c' ],
			c_args: cc_armv7_neon_simd_args,
			include_directories: [
				include_dirs,
				include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_asm_arm7a_neon_lib
	else
		src += files([ 'ascon_arm_neon_null.c' ])
	endif

endif

if get_option('chacha20poly1305').enabled()
	include_files += files([
		'../api/lc_poly1305.h',
	])
	src += files([
		'poly1305.c'
		])
endif

if (lc_hash == 1)
	src += files([ 'hash.c' ])
endif
