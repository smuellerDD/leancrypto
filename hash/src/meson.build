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
	src += files([ 'cshake.c', 'sha3_selector.c', 'sha3_c.c' ])
	include_files += files([ '../api/lc_cshake.h', '../api/lc_sha3.h' ])
	lc_hash = 1

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

	if (build_machine.cpu_family() == 'notcompiled_aarch64')
		src += files([ 'sha3_arm8_neon.c',
			       'asm/ARMv8A/KeccakP-1600-armv8a-neon.S' ])
	else
		src += files([ 'sha3_arm8_neon_null.c' ])
	endif
endif

if (lc_hash == 1)
	src += files([ 'hash.c' ])
	include_files += files([ '../api/lc_hash.h' ])
endif
