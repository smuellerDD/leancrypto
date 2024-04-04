# aes_gcm_openssl_large_tester = executable('aes_gcm_openssl_large_tester',
# 					[ 'aes_gcm_openssl_large_tester.c',
# 					internal_src ],
# 					include_directories: [ include_internal_dirs,
# 							  '../src' ],
# 					dependencies: [ leancrypto,
# 							dependency('openssl') ]
# 					)

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
	if get_option('sha2-512').enabled()
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

	if get_option('kmac').enabled()
		symkmac256_test = executable('symkmac256_test',
				[ 'symkmac256_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
		symkmac256_large_test = executable('symkmac256_large_test',
				[ 'symkmac256_large_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
		symkmac128_test = executable('symkmac128_test',
				[ 'symkmac128_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
		symkmac128_large_test = executable('symkmac128_large_test',
				[ 'symkmac128_large_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)

		test('AEAD Sym KMAC256', symkmac256_test)
		test('AEAD Sym KMAC256 1GB', symkmac256_large_test,
		     timeout: 2500, is_parallel: false)

		test('AEAD Sym KMAC128', symkmac128_test)
		test('AEAD Sym KMAC128 1GB', symkmac128_large_test,
		     timeout: 2500, is_parallel: false)
	endif
endif

if get_option('hash_crypt').enabled()

	ascon_keccak_crypt_test = executable('ascon_keccak_crypt_test',
				[ 'ascon_keccak_crypt_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	ascon_keccak_crypt_iuf_test = executable('ascon_keccak_crypt_iuf_test',
				[ 'ascon_keccak_crypt_iuf_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	ascon_keccak_crypt_large_test_512 = \
				executable('ascon_keccak_crypt_large_test_512',
				[ 'ascon_keccak_crypt_large_test_512.c',
				  internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	ascon_keccak_crypt_large_test_512_c = \
				executable('ascon_keccak_crypt_large_test_512_c',
				[ 'ascon_keccak_crypt_large_test_512_c.c',
				  internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	ascon_keccak_crypt_large_test_256 = \
				executable('ascon_keccak_crypt_large_test_256',
				[ 'ascon_keccak_crypt_large_test_256.c',
				  internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	ascon_keccak_crypt_large_test_256_c = \
				executable('ascon_keccak_crypt_large_test_256_c',
				[ 'ascon_keccak_crypt_large_test_256_c.c',
				  internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	test('AEAD Ascon Keccak', ascon_keccak_crypt_test)
	test('AEAD Ascon Keccak IUF', ascon_keccak_crypt_iuf_test)
	test('AEAD Ascon Keccak 256/512 Accel 1GB',
	     ascon_keccak_crypt_large_test_512,
	     timeout: 2500, is_parallel: false)
	test('AEAD Ascon Keccak 256/512 C 1GB',
	     ascon_keccak_crypt_large_test_512_c,
	     timeout: 2500, is_parallel: false)
	test('AEAD Ascon Keccak 256/256 Accel 1GB',
	     ascon_keccak_crypt_large_test_256,
	     timeout: 2500, is_parallel: false)
	test('AEAD Ascon Keccak 256/256 C 1GB',
	     ascon_keccak_crypt_large_test_256_c,
	     timeout: 2500, is_parallel: false)

endif

if (get_option('hash_crypt').enabled() and get_option('ascon').enabled())

	ascon_crypt_test = executable('ascon_crypt_test',
				[ 'ascon_crypt_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	ascon_crypt_iuf_test = executable('ascon_crypt_iuf_test',
				[ 'ascon_crypt_iuf_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	ascon_crypt_large_test_128 = executable('ascon_crypt_large_test_128',
				[ 'ascon_crypt_large_test_128.c',
				  internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	ascon_crypt_large_test_128a = executable('ascon_crypt_large_test_128a',
				[ 'ascon_crypt_large_test_128a.c',
				  internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	ascon_crypt_large_test_128_c = executable('ascon_crypt_large_test_128_c',
				[ 'ascon_crypt_large_test_128_c.c',
				  internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	ascon_crypt_large_test_128a_c = executable('ascon_crypt_large_test_128a_c',
				[ 'ascon_crypt_large_test_128a_c.c',
				  internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	test('AEAD Ascon C', ascon_crypt_test)
	test('AEAD Ascon IUF C', ascon_crypt_iuf_test)
	test('AEAD Ascon 128 Accel 1GB',
	     ascon_crypt_large_test_128,
	     timeout: 2500, is_parallel: false)
	test('AEAD Ascon 128a Accel 1GB',
	     ascon_crypt_large_test_128a,
	     timeout: 2500, is_parallel: false)
	test('AEAD Ascon 128 C 1GB',
	     ascon_crypt_large_test_128_c,
	     timeout: 2500, is_parallel: false)
	test('AEAD Ascon 128a C 1GB',
	     ascon_crypt_large_test_128a_c,
	     timeout: 2500, is_parallel: false)
endif
