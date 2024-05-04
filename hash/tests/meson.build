hasher = 1

if get_option('sha2-256').enabled()
	sha256_tester = executable('sha256_tester',
				   [ 'sha256_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('Hash SHA256', sha256_tester)
else
	hasher = 0
endif

if get_option('sha2-512').enabled()
	sha512_tester = executable('sha512_tester',
				   [ 'sha512_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('Hash SHA512', sha512_tester)
else
	hasher = 0
endif

if get_option('sha3').enabled()
	sha3_224_tester = executable('sha3_224_tester',
				     [ 'sha3-224_tester.c', internal_src ],
				     include_directories: [ include_internal_dirs ],
				     dependencies: leancrypto
				     )
	sha3_256_tester = executable('sha3_256_tester',
				     [ 'sha3-256_tester.c', internal_src ],
				     include_directories: [ include_internal_dirs ],
				     dependencies: leancrypto
				     )
	sha3_384_tester = executable('sha3_384_tester',
				     [ 'sha3-384_tester.c', internal_src ],
				     include_directories: [ include_internal_dirs ],
				     dependencies: leancrypto
				     )
	sha3_512_tester = executable('sha3_512_tester',
				     [ 'sha3-512_tester.c', internal_src ],
				     include_directories: [ include_internal_dirs ],
				     dependencies: leancrypto
				    )
	shake128_tester = executable('shake128_tester',
				  [ 'shake128_tester.c', internal_src ],
				  include_directories: [ include_internal_dirs ],
				  dependencies: leancrypto
				  )
	shake256_tester = executable('shake256_tester',
				  [ 'shake256_tester.c', internal_src ],
				  include_directories: [ include_internal_dirs ],
				  dependencies: leancrypto
				  )
	shake_squeeze_more_tester = executable('shake_squeeze_more_tester',
				  [ 'shake_squeeze_more_tester.c', internal_src ],
				  include_directories: [ include_internal_dirs ],
				  dependencies: leancrypto
				  )
	cshake_128_tester = executable('cshake_128_tester',
				   [ 'cshake_128_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	cshake_256_tester = executable('cshake_256_tester',
				   [ 'cshake_256_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	cshake_ctx_256_tester = executable('cshake_ctx_256_tester',
				   [ 'cshake_ctx_256_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	keccak_tester = executable('keccak_tester',
				   [ 'keccak_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('Hash SHA3-224', sha3_224_tester)
	test('Hash SHA3-256', sha3_256_tester)
	test('Hash SHA3-384', sha3_384_tester)
	test('Hash SHA3-512', sha3_512_tester)
	test('Hash SHAKE128', shake128_tester)
	test('Hash SHAKE256', shake256_tester)
	test('Hash SHAKE256 Squeeze More', shake_squeeze_more_tester)
	test('Hash cSHAKE128', cshake_128_tester)
	test('Hash cSHAKE256', cshake_256_tester)
	test('Hash cSHAKE256 Reinit', cshake_ctx_256_tester)
	test('Keccak Permutation', keccak_tester)

	if (x86_64_asm)
		shake128_4x_avx2_tester = executable('shake128_4x_avx2_tester',
					[ 'shake128_4x_avx2_tester.c', internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)
		shake256_4x_avx2_tester = executable('shake256_4x_avx2_tester',
					[ 'shake256_4x_avx2_tester.c', internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

		test('Hash SHAKE128 4x AVX2', shake128_4x_avx2_tester)
		test('Hash SHAKE256 4x AVX2', shake256_4x_avx2_tester)
	elif (arm64_asm)
		shake128_2x_armv8_tester = executable('shake128_2x_armv8_tester',
					[ 'shake128_2x_armv8_tester.c', internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)
		shake256_2x_armv8_tester = executable('shake256_2x_armv8_tester',
					[ 'shake256_2x_armv8_tester.c', internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

		test('Hash SHAKE128 2x ARMv8', shake128_2x_armv8_tester)
		test('Hash SHAKE256 2x ARMv8', shake256_2x_armv8_tester)
	endif
else
	hasher = 0
endif

if get_option('ascon').enabled()
	ascon_128_tester = executable('ascon_128_tester',
				   [ 'ascon_128_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	ascon_128a_tester = executable('ascon_128a_tester',
				   [ 'ascon_128a_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	ascon_xof_tester = executable('ascon_xof_tester',
				   [ 'ascon_xof_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	ascon_xofa_tester = executable('ascon_xofa_tester',
				   [ 'ascon_xofa_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	ascon_xof_squeeze_more_tester = executable('ascon_xof_squeeze_more_tester',
				   [ 'ascon_xof_squeeze_more_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('Hash Ascon 128', ascon_128_tester)
	test('Hash Ascon 128a', ascon_128a_tester)
	test('Hash Ascon XOF', ascon_xof_tester)
	test('Hash Ascon XOFa', ascon_xofa_tester)
	test('Hash Ascon XOF Squeeze More', ascon_xof_squeeze_more_tester)
endif

if (hasher == 1)
	hasher = executable('hasher',
				     [ 'hasher.c', internal_src ],
				     include_directories: [ include_internal_dirs ],
				     dependencies: leancrypto
				     )
endif
