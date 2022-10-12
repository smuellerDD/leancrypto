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

	test('Hash Crypt', hash_crypt_tester)
	test('Hash Crypt 1GB', hash_crypt_large_tester, timeout: 300)
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

	test('KMAC Crypt', kmac_crypt_tester)
	test('KMAC Crypt 1GB', kmac_crypt_large_tester, timeout: 300)
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

	test('cSHAKE Crypt', cshake_crypt_tester)
	test('cSHAKE Crypt 1GB', cshake_crypt_large_tester, timeout: 300)
endif

if get_option('aes_cbc').enabled()
	symhmac_test = executable('symhmac_test',
				[ 'symhmac_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)

	test('Sym HMAC AEAD', symhmac_test)
endif
