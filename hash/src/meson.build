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

	if (build_machine.cpu_family() == 'x86_64')
		src += files([ 'sha3_avx2.c',
			       'asm/AVX2/KeccakP-1600-AVX2.S' ])
		src += files([ 'sha3_avx512.c',
			       'asm/AVX512/KeccakP-1600-AVX512.S' ])
	else
		src += files([ 'sha3_avx2_null.c' ])
		src += files([ 'sha3_avx512_null.c' ])
	endif

	if (build_machine.cpu_family() == 'aarch64')
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
