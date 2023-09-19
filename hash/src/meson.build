# for i in $(ls *.c | sort); do echo "'$i',"; done

lc_hash = 0

if get_option('sha2-256').enabled()
	src += files([ 'sha256.c' ])
	include_files += files([ '../api/lc_sha256.h' ])
	lc_hash = 1
endif

if get_option('sha2-512').enabled()
	src += files([ 'sha512.c' ])
	include_files += files([ '../api/lc_sha512.h' ])
	lc_hash = 1
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
			c_args: [
				'-mavx2',
				'-mbmi2',
				'-mpopcnt',
			],
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_keccak_avx2_4x_lib

	else
		src += files([ 'sha3_avx2_null.c' ])
		src += files([ 'sha3_avx512_null.c' ])
	endif

	# 32 bit ARM processor and GCC
	if (arm32_neon_gcc_asm)
		leancrypto_keccak_arm7a_neon_lib = static_library(
			'leancrypto_keccak_arm7a_neon_lib',
			[ 'sha3_arm_neon.c',
			  'asm/ARMv7A-NEON/KeccakP-1600-armv7a-le-neon-gcc.S' ],
			c_args: [
				'-mfpu=neon-vfpv4',
				'-mthumb',
				'-march=armv7-a+vfpv4',
				'-funsafe-math-optimizations'
			],
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
			c_args: [
				'-march=armv8-a+simd',
				'-funsafe-math-optimizations'
			],
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
		#leancrypto_keccak_armv8_2x_lib = static_library(
		#	'leancrypto_keccak_armv8_2x_lib',
		#	[ 'shake_2x_armv8.c',
		#	  'asm/ARMv8_2x/keccakx2_armce.S' ],
		#	c_args: [
		#		'-Wno-unused-result',
		#	],
		#	include_directories: [ include_dirs,
		#			       include_internal_dirs ],
		#)
		#leancrypto_support_libs += leancrypto_keccak_armv8_2x_lib
	else
		src += files([ 'sha3_arm_asm_null.c', 'sha3_arm_ce_null.c' ])
	endif

# 	if (riscv)
# 		src += files([ 'sha3_riscv_asm.c',
# 			       'asm/riscv32/keccakf1600.c' ])
# 	elif (riscv32_gcc_asm)
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
# 	elif (riscv64_gcc_asm)
# 		leancrypto_keccak_riscv_asm_lib = static_library(
# 			'leancrypto_keccak_riscv_asm_lib',
# 			[ 'sha3_riscv_asm.c', 'asm/riscv32/keccakf1600_asm.S' ],
# 			c_args: [
# 				'-march=rv64gc',
# 				'-mabi=lp64d',
# 				'-mcmodel=medany'
# 			],
# 			include_directories: [
# 				include_dirs,
# 				include_internal_dirs ],
# 		)
# 		leancrypto_support_libs += leancrypto_keccak_riscv_asm_lib
# 	else
		src += files([ 'sha3_riscv_asm_null.c' ])
#	endif
endif

if (lc_hash == 1)
	src += files([ 'hash.c' ])
	include_files += files([ '../api/lc_hash.h' ])
endif
