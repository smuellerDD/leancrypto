# for i in $(ls *.c | sort); do echo "'$i',"; done
if get_option('hash_crypt').enabled()
	src += files([
		'hash_crypt.c',
	])

	include_files += files([
		'../api/lc_aead.h',
		'../api/lc_ascon_aead.h',
		'../api/lc_cshake_crypt.h',
		'../api/lc_hash_crypt.h',
		'../api/lc_kmac_crypt.h',
	])

	aead_src_files = files([
				'ascon.c',
				'ascon_lightweight.c',
				'cshake_crypt.c',
				'kmac_crypt.c'
			       ])
	if get_option('sha3').enabled()
		aead_src_files += files([ 'ascon_keccak.c' ])
		include_files += files([ '../api/lc_ascon_keccak.h' ])
		add_global_arguments([ '-DLC_ASCON_KECCAK' ], language: 'c')
	endif

	if (x86_64_asm)
		# This is required for the XOR 256 bit AVX2 implementation
		leancrypto_aead_avx2_lib = static_library(
			'leancrypto_aead_avx2_lib',
			aead_src_files,
			c_args: cc_avx2_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_aead_avx2_lib

	elif (arm64_asm)
		# This is required for the XOR 128 bit NEON implementation
		leancrypto_aead_neon_armv8_lib = static_library(
			'leancrypto_aead_neon_armv8_lib',
			aead_src_files,
			c_args: cc_armv8_neon_simd_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_aead_neon_armv8_lib

	elif (arm32_neon_gcc_asm)
		# This is required for the XOR 128 bit NEON implementation
		leancrypto_aead_neon_armv7_lib = static_library(
			'leancrypto_aead_neon_armv7_lib',
			aead_src_files,
			c_args: cc_armv7_neon_simd_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_aead_neon_armv7_lib

	else
		src += aead_src_files
	endif
endif

# We need HMAC and a symmetric algo
if (get_option('aes_cbc').enabled() or get_option('aes_ctr').enabled())
	if get_option('sha2-512').enabled()
		src += files([
			'symhmac.c'
		])

		include_files += files([
			'../api/lc_symhmac.h'
		])
	endif

	if get_option('kmac').enabled()
		src += files([
			'symkmac.c'
		])

		include_files += files([
			'../api/lc_symkmac.h'
		])
	endif
endif
