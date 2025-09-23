# for i in $(ls *.c | sort); do echo "'$i',"; done

compile_hash_crypt = 0
compile_aead = 0
aead_src_files = [ ]

if (aead_support_enabled)
	include_files += files([
		'../api/lc_aead.h',
	])
endif

if get_option('hash_crypt').enabled()
	src += files([
		'hash_crypt.c',
	])

	include_files += files([
		'../api/lc_cshake_crypt.h',
		'../api/lc_hash_crypt.h',
		'../api/lc_kmac_crypt.h',
	])

	aead_src_files += files([
				'cshake_crypt.c',
				'kmac_crypt.c'
			       ])

	compile_hash_crypt = 1
	compile_aead = 1
endif

if get_option('ascon').enabled() or get_option('ascon_keccak').enabled()
	src += files([ 'ascon.c', ])
	include_files += files([ '../api/lc_ascon_aead.h' ])
endif

if get_option('ascon').enabled()
	src += files([ 'ascon_lightweight.c', ])
	include_files += files([ '../api/lc_ascon_lightweight.h' ])
	add_global_arguments([ '-DLC_ASCON' ], language: 'c')

	compile_hash_crypt = 1
endif

if get_option('ascon_keccak').enabled()
	src += files([ 'ascon_keccak.c' ])
	include_files += files([ '../api/lc_ascon_keccak.h' ])
	add_global_arguments([ '-DLC_ASCON_KECCAK' ], language: 'c')

	compile_hash_crypt = 1
endif

if (compile_hash_crypt == 1)
	src += aead_src_files
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

		compile_aead = 1
	endif

	if get_option('kmac').enabled()
		src += files([
			'symkmac.c'
		])

		include_files += files([
			'../api/lc_symkmac.h'
		])

		compile_aead = 1
	endif
endif

if get_option('chacha20poly1305').enabled()
	include_files += files([
		'../api/lc_chacha20_poly1305.h',
	])

	src += files([
		'chacha20poly1305.c'
		])
	compile_aead = 1
endif

if get_option('aes_gcm').enabled()
	include_files += files([
		'../api/lc_aes_gcm.h',
	])

	src += files([
		'gcm.c'
		])
	compile_aead = 1

	if (arm64_asm)
		leancrypto_aes_gcm_neon_armv8_lib = static_library(
			'leancrypto_aes_gcm_neon_armv8_lib',
			[ 'asm/ARMv8/gfmul_neon.S',
			  'asm/ARMv8/gfmul_neon_if.c'
			],
			c_args: cc_armv8_neon_simd_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_aes_gcm_neon_armv8_lib
	endif

	if (x86_64_asm)
		leancrypto_aes_gcm_x86_64_lib = static_library(
			'leancrypto_aes_gcm_x86_64_lib',
			[ 'asm/X86_64/gfmul_x86_64.S',
			  'asm/X86_64/gfmul_x86_64_if.c' ],
			c_args: cc_avx2_args,
			include_directories: [ include_dirs,
					       include_internal_dirs ],
		)
		leancrypto_support_libs += leancrypto_aes_gcm_x86_64_lib
	endif
endif

if (compile_aead == 1)
	src += files([ 'aead_api.c' ])
endif
