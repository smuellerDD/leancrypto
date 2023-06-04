if get_option('sha2-512').enabled() and get_option('drbg_hash').enabled()
	hash_crypt_tester = executable('hash_crypt_test',
				[ 'hash_crypt_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	hash_crypt_large_tester = executable('hash_crypt_large_test',
			       [ 'hash_crypt_large_test.c', internal_src ],
			       include_directories: [ include_internal_dirs ],
			       dependencies: leancrypto
			       )

	test('AEAD Hash Crypt', hash_crypt_tester)
	test('AEAD Hash Crypt 1GB', hash_crypt_large_tester,
	     timeout: 2500, is_parallel: false)
endif

if get_option('kmac_drng').enabled()
	kmac_crypt_tester = executable('kmac_crypt_test',
				[ 'kmac_crypt_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	kmac_crypt_large_tester = executable('kmac_crypt_large_test',
				[ 'kmac_crypt_large_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	kmac_crypt_large_tester_c = executable('kmac_crypt_large_test_c',
				[ 'kmac_crypt_large_test_c.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)

	test('AEAD KMAC Crypt', kmac_crypt_tester)
	test('AEAD KMAC Crypt Accel 1GB', kmac_crypt_large_tester,
	     timeout: 2500, is_parallel: false)
	test('AEAD KMAC Crypt C 1GB', kmac_crypt_large_tester_c, timeout: 2500,
	     is_parallel: false)
endif

if get_option('cshake_drng').enabled()
	cshake_crypt_tester = executable('cshake_crypt_test',
				[ 'cshake_crypt_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	cshake_crypt_large_tester = executable('cshake_crypt_large_test',
				[ 'cshake_crypt_large_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	cshake_crypt_large_tester_c = executable('cshake_crypt_large_test_c',
				[ 'cshake_crypt_large_test_c.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)

	test('AEAD cSHAKE Crypt', cshake_crypt_tester)
	test('AEAD cSHAKE Crypt Accel 1GB', cshake_crypt_large_tester,
	     timeout: 2500, is_parallel: false)
	test('AEAD cSHAKE Crypt C 1GB', cshake_crypt_large_tester_c,
	     timeout: 2500, is_parallel: false)
endif

if get_option('aes_cbc').enabled()
	symhmac_test = executable('symhmac_test',
				[ 'symhmac_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	symhmac_large_test = executable('symhmac_large_test',
				[ 'symhmac_large_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)

	test('AEAD Sym HMAC', symhmac_test)
	test('AEAD Sym HMAC 1GB', symhmac_large_test,
	     timeout: 2500, is_parallel: false)
endif
