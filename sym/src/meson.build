# for i in $(ls *.c | sort); do echo "'$i',"; done

lc_sym = 0
lc_aes = 0
lc_aesni_asm = 0
lc_armce_v8_asm = 0
lc_riscv64_asm = 0
lc_block = 1

if get_option('chacha20').enabled()
	if (x86_64_asm)
		# This is required for the XOR 256 bit implementation
		leancrypto_chacha20_avx2_lib = static_library(
			'leancrypto_chacha20_avx2_lib',
			[ 'chacha20.c' ],
			c_args: [
				'-mavx2',
				'-mbmi2',
				'-mpopcnt',
			],
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_chacha20_avx2_lib

	elif (arm64_asm)
		# This is required for the XOR 128 bit NEON implementation
		leancrypto_chacha20_neon_armv8_lib = static_library(
			'leancrypto_chacha20_neon_armv8_lib',
			[ 'chacha20.c' ],
			c_args: [
				'-march=armv8-a+simd',
				'-Wno-unused-result',
			],
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_chacha20_neon_armv8_lib

	elif (arm32_neon_gcc_asm)
		# This is required for the XOR 128 bit NEON implementation
		leancrypto_chacha20_neon_armv7_lib = static_library(
			'leancrypto_chacha20_neon_armv7_lib',
			[ 'chacha20.c' ],
			c_args: [
				'-mfpu=neon-vfpv4',
				'-mthumb',
				'-march=armv7-a+vfpv4',
				'-funsafe-math-optimizations'
			],
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_chacha20_neon_armv7_lib

	else
		src += files([ 'chacha20.c' ])
	endif

	include_files += files([ '../api/lc_chacha20.h' ])
	lc_sym = 1
endif

if get_option('aes_ecb').enabled()
	src += files([ 'aes_ecb.c' ])
	lc_aes = 1
endif

if get_option('aes_cbc').enabled()
	src += files([ 'aes_cbc.c', 'mode_cbc.c' ])
	lc_aes = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src += files([ 'aes_cbc_aesni.c', ])
	else
		src += files([ 'aes_cbc_aesni_null.c' ])
	endif

	if (arm64_asm)
		lc_armce_v8_asm = 1
		src += files([ 'aes_cbc_armce_v8.c' ])
	else
		src += files([ 'aes_cbc_armce_v8_null.c' ])
	endif

	if (riscv64_asm)
		lc_riscv64_asm = 1
		src += files([ 'aes_cbc_riscv64.c' ])
	else
		src += files([ 'aes_cbc_riscv64_null.c' ])
	endif
endif

if get_option('aes_ctr').enabled()
	src += files([ 'aes_ctr.c', 'mode_ctr.c' ])
	lc_aes = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src += files([ 'aes_ctr_aesni.c' ])
	else
		src += files([ 'aes_ctr_aesni_null.c' ])
	endif

	if (arm64_asm)
		lc_armce_v8_asm = 1
		src += files([ 'aes_ctr_armce_v8.c' ])
	else
		src += files([ 'aes_ctr_armce_v8_null.c' ])
	endif

	if (riscv64_asm)
		lc_riscv64_asm = 1
		src += files([ 'aes_ctr_riscv64.c' ])
	else
		src += files([ 'aes_ctr_riscv64_null.c' ])
	endif
endif

if get_option('aes_kw').enabled()
	src += files([ 'aes_kw.c', 'mode_kw.c'])
	lc_aes = 1
	lc_block = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src += files([ 'aes_kw_aesni.c' ])
	else
		src += files([ 'aes_kw_aesni_null.c' ])
	endif

	if (arm64_asm)
		lc_armce_v8_asm = 1
		src += files([ 'aes_kw_armce_v8.c' ])
	else
		src += files([ 'aes_kw_armce_v8_null.c' ])
	endif

	if (riscv64_asm)
		lc_riscv64_asm = 1
		src += files([ 'aes_kw_riscv64.c' ])
	else
		src += files([ 'aes_kw_riscv64_null.c' ])
	endif
endif

if (lc_block == 1)
	src += files([ 'aes_block.c' ])
	lc_aes = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src += files([ 'aes_block_aesni.c' ])
	else
		src += files([ 'aes_block_aesni_null.c' ])
	endif

	if (arm64_asm)
		lc_armce_v8_asm = 1
		src += files([ 'aes_block_armce_v8.c' ])
	else
		src += files([ 'aes_block_armce_v8_null.c' ])
	endif

	if (riscv64_asm)
		lc_riscv64_asm = 1
		src += files([ 'aes_block_riscv64.c' ])
	else
		src += files([ 'aes_block_riscv64_null.c' ])
	endif
endif

if (lc_aesni_asm == 1)
	src += files([ 'asm/AESNI_x86_64/aes_aesni_x86_64.S' ])
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
	leancrypto_support_libs += leancrypto_aes_arm8a_ce_lib
endif

if (lc_riscv64_asm == 1)
	leancrypto_aes_riscv64_asm_lib = static_library(
		'leancrypto_aes_riscv64_asm_lib',
		[ 'asm/riscv64/riscv64_aes_asm.S' ],
		c_args: [
			'-march=rv64gc',
			'-mabi=lp64d',
		],
		include_directories: [
			include_directories(['asm/riscv64/']),
			include_dirs,
			include_internal_dirs ],
	)
	leancrypto_support_libs += leancrypto_aes_riscv64_asm_lib
endif

if (lc_aes == 1)
	src += files([ 'aes.c',
		       'aes_selector.c'
		     ])
	include_files += files([ '../api/lc_aes.h' ])
	lc_sym = 1
endif

if (lc_sym == 1)
	src += files([ 'sym.c' ])
	include_files += files([ '../api/lc_sym.h' ])
endif
