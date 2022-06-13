if get_option('drbg_hash').enabled()
	hash_sha2_drbg_tester = executable('hash_sha2_drbg_tester',
				[ 'hash_drbg_tester.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	hash_sha2_drbg_tester_large = executable('hash_sha2_drbg_tester_large',
				[ 'hash_drbg_tester_large.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	test('Hash SHA2-512 DRBG', hash_sha2_drbg_tester)
	test('Hash SHA2-512 DRBG 1GB', hash_sha2_drbg_tester_large, timeout: 300)

#	Disabled as SHA3 DRBG is disabled in main meson.build
# 	if get_option('sha3').enabled()
# 		hash_sha3_drbg_tester = executable('hash_sha3_drbg_tester',
# 				[ 'hash_sha3_drbg_tester.c', internal_src ],
# 				include_directories: [ include_internal_dirs ],
# 				dependencies: leancrypto
# 				)
# 		test('Hash SHA3-512 DRBG', hash_sha3_drbg_tester)
# 	endif
endif

if get_option('drbg_hmac').enabled()
	hmac_sha2_drbg_tester = executable('hmac_sha2_drbg_tester',
				[ 'hmac_drbg_tester.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	hmac_sha2_drbg_tester_large = executable('hmac_sha2_drbg_tester_large',
				[ 'hmac_drbg_tester_large.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	test('HMAC SHA2-512 DRBG', hmac_sha2_drbg_tester)
	test('HMAC SHA2-512 DRBG 1GB', hmac_sha2_drbg_tester_large, timeout: 300)
endif
