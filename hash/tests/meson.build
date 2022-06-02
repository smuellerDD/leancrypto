if get_option('sha2-256').enabled()
	sha256_tester = executable('sha256_tester',
				   [ 'sha256_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('SHA256', sha256_tester)
endif

if get_option('sha2-512').enabled()
	sha512_tester = executable('sha512_tester',
				   [ 'sha512_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('SHA512', sha512_tester)
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
	shake_tester = executable('shake_tester',
				  [ 'shake_tester.c', internal_src ],
				  include_directories: [ include_internal_dirs ],
				  dependencies: leancrypto
				  )
	shake_squeeze_more_tester = executable('shake_squeeze_more_tester',
				  [ 'shake_squeeze_more_tester.c', internal_src ],
				  include_directories: [ include_internal_dirs ],
				  dependencies: leancrypto
				  )
	cshake_tester = executable('cshake_tester',
				   [ 'cshake_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('SHA3-224', sha3_224_tester)
	test('SHA3-256', sha3_256_tester)
	test('SHA3-384', sha3_384_tester)
	test('SHA3-512', sha3_512_tester)
	test('SHAKE256', shake_tester)
	test('SHAKE256 Squeeze More', shake_squeeze_more_tester)
	test('cSHAKE256', cshake_tester)
endif
