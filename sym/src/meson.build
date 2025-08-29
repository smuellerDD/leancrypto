# for i in $(ls *.c | sort); do echo "'$i',"; done

lc_sym = 0
lc_aes = 0
lc_aesni_asm = 0
lc_armce_v8_asm = 0
lc_riscv64_asm = 0
lc_block = 0

if get_option('chacha20').enabled()
	# Compiling Chacha20 in FIPS library is appropriate as the init function
	# disables ChaCha20 in FIPS mode
	src_fips += files([
		'chacha20.c',
		'chacha20_selector.c'
	])

	if (x86_64_asm)
		src_fips += files([
			'chacha20_avx2.c',
			'chacha20_avx512.c'
		])

		leancrypto_chacha20_avx2_lib = static_library(
			'leancrypto_chacha20_avx2_lib',
			[ 'asm/AVX2/chacha20_impl_avx2.c' ],
			c_args: cc_avx2_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs_fips += leancrypto_chacha20_avx2_lib

		leancrypto_chacha20_avx512_lib = static_library(
			'leancrypto_chacha20_avx512_lib',
			[ 'asm/AVX512/chacha20_impl_avx512.c' ],
			c_args: cc_avx512_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs_fips += leancrypto_chacha20_avx512_lib
	else
		src_fips += files([
			'chacha20_avx2_null.c',
			'chacha20_avx512_null.c'
		])
	endif

	if (arm64_asm)
		src_fips += files([ 'chacha20_neon.c' ])

		leancrypto_chacha20_neon_armv8_lib = static_library(
			'leancrypto_chacha20_neon_armv8_lib',
			[ 'asm/ARMv8/chacha20_neon.S' ],
			c_args: cc_armv8_neon_simd_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs_fips += leancrypto_chacha20_neon_armv8_lib
	elif (arm32_neon_asm)
		src_fips += files([ 'chacha20_neon.c' ])

		leancrypto_chacha20_neon_armv7_lib = static_library(
			'leancrypto_chacha20_neon_armv7_lib',
			[ 'asm/ARMv7/chacha20_neon_armv7.S' ],
			c_args: cc_armv7_neon_simd_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs_fips += leancrypto_chacha20_neon_armv7_lib
	else
		src_fips += files([ 'chacha20_neon_null.c' ])
	endif

	if (riscv64_asm)
		src_fips += files([ 'chacha20_riscv64_v_zbb.c' ])

		leancrypto_chacha20_riscv64_v_zbb_armv8_lib = static_library(
			'leancrypto_chacha20_riscv64_v_zbb_armv8_lib',
			[ 'asm/riscv64/chacha20_riscv64_v_zbb.S' ],
			c_args: cc_riscv64_asm_rvv_zbb_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs_fips += leancrypto_chacha20_riscv64_v_zbb_armv8_lib
	else
		src_fips += files([ 'chacha20_riscv64_v_zbb_null.c' ])
	endif

	include_files += files([ '../api/lc_chacha20.h' ])
	lc_sym = 1
endif

if get_option('aes_ecb').enabled()
	src_fips += files([ 'aes_ecb.c' ])
	lc_aes = 1
endif

if get_option('aes_cbc').enabled()
	src_fips += files([ 'aes_cbc.c', 'mode_cbc.c' ])
	lc_aes = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src_fips += files([ 'aes_cbc_aesni.c', ])
	else
		src_fips += files([ 'aes_cbc_aesni_null.c' ])
	endif

	if (arm64_asm)
		lc_armce_v8_asm = 1
		src_fips += files([ 'aes_cbc_armce_v8.c' ])
	else
		src_fips += files([ 'aes_cbc_armce_v8_null.c' ])
	endif

	if (riscv64_asm)
		lc_riscv64_asm = 1
		src_fips += files([ 'aes_cbc_riscv64.c' ])
	else
		src_fips += files([ 'aes_cbc_riscv64_null.c' ])
	endif
endif

if get_option('aes_ctr').enabled()
	src_fips += files([ 'aes_ctr.c', 'mode_ctr.c' ])
	lc_aes = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src_fips += files([ 'aes_ctr_aesni.c' ])
	else
		src_fips += files([ 'aes_ctr_aesni_null.c' ])
	endif

	if (arm64_asm)
		lc_armce_v8_asm = 1
		src_fips += files([ 'aes_ctr_armce_v8.c' ])
	else
		src_fips += files([ 'aes_ctr_armce_v8_null.c' ])
	endif

	if (riscv64_asm)
		lc_riscv64_asm = 1
		src_fips += files([ 'aes_ctr_riscv64.c' ])
	else
		src_fips += files([ 'aes_ctr_riscv64_null.c' ])
	endif
endif

if get_option('aes_kw').enabled()
	src_fips += files([ 'aes_kw.c', 'mode_kw.c'])
	lc_aes = 1
	lc_block = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src_fips += files([ 'aes_kw_aesni.c' ])
	else
		src_fips += files([ 'aes_kw_aesni_null.c' ])
	endif

	if (arm64_asm)
		lc_armce_v8_asm = 1
		src_fips += files([ 'aes_kw_armce_v8.c' ])
	else
		src_fips += files([ 'aes_kw_armce_v8_null.c' ])
	endif

	if (riscv64_asm)
		lc_riscv64_asm = 1
		src_fips += files([ 'aes_kw_riscv64.c' ])
	else
		src_fips += files([ 'aes_kw_riscv64_null.c' ])
	endif
endif

if get_option('aes_gcm').enabled()
	lc_aes = 1
	lc_block = 1
endif

if get_option('aes_xts').enabled()
	src_fips += files([ 'aes_xts.c', 'mode_xts.c' ])
	lc_aes = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src_fips += files([ 'aes_xts_aesni.c' ])
	else
		src_fips += files([ 'aes_xts_aesni_null.c' ])
	endif

	if (arm64_asm)
		lc_armce_v8_asm = 1
		src_fips += files([ 'aes_xts_armce_v8.c' ])
	else
		src_fips += files([ 'aes_xts_armce_v8_null.c' ])
	endif

	if (riscv64_asm)
		lc_riscv64_asm = 1
		src_fips += files([ 'aes_xts_riscv64.c' ])
	else
		src_fips += files([ 'aes_xts_riscv64_null.c' ])
	endif
endif

if (lc_block == 1)
	src_fips += files([ 'aes_block.c' ])
	lc_aes = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src_fips += files([ 'aes_block_aesni.c' ])
	else
		src_fips += files([ 'aes_block_aesni_null.c' ])
	endif

	if (arm64_asm)
		lc_armce_v8_asm = 1
		src_fips += files([ 'aes_block_armce_v8.c' ])
	else
		src_fips += files([ 'aes_block_armce_v8_null.c' ])
	endif

	if (riscv64_asm)
		lc_riscv64_asm = 1
		src_fips += files([ 'aes_block_riscv64.c' ])
	else
		src_fips += files([ 'aes_block_riscv64_null.c' ])
	endif
endif

if (lc_aesni_asm == 1)
	src_fips += files([ 'asm/AESNI_x86_64/aes_aesni_x86_64.S' ])
endif

if (lc_armce_v8_asm == 1)
	#src += files([ 'asm/ARMv8/aes_armv8_ce.S' ])

	leancrypto_aes_arm8a_ce_lib = static_library(
		'leancrypto_aes_arm8a_ce_lib',
		[ 'asm/ARMv8/aes_armv8_ce.S' ],
		c_args: [
			'-march=armv8-a+crypto'
		],
		include_directories: [
			include_directories(['asm/ARMv8/']),
			include_dirs,
			include_internal_dirs ],
	)
	leancrypto_support_libs_fips += leancrypto_aes_arm8a_ce_lib
endif

if (lc_riscv64_asm == 1)
	leancrypto_aes_riscv64_asm_lib = static_library(
		'leancrypto_aes_riscv64_asm_lib',
		[ 'asm/riscv64/riscv64_aes_asm.S' ],
		c_args: [ cc_riscv64_asm_args ],
		include_directories: [
			include_directories(['asm/riscv64/']),
			include_dirs,
			include_internal_dirs ],
	)
	leancrypto_support_libs_fips += leancrypto_aes_riscv64_asm_lib
endif

if (lc_aes == 1)
	src_fips += files([
			'aes_sbox.c',
			'aes_selector.c'
		     ])
	include_files += files([ '../api/lc_aes.h' ])
	lc_sym = 1
endif

if (lc_sym == 1)
	src_fips += files([ 'sym.c' ])
	include_files += files([ '../api/lc_sym.h' ])
endif
