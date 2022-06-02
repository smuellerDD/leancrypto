hmac_tester = executable('hmac_sha3_224_tester',
			 [ 'hmac_sha3_224_tester.c', internal_src ],
			 include_directories: [ include_internal_dirs ],
			 dependencies: leancrypto
			 )
hmac_sha2_256_tester = executable('hmac_sha2_256_tester',
				  [ 'hmac_sha2_256_tester.c', internal_src ],
				  include_directories: [ include_internal_dirs ],
				  dependencies: leancrypto
				 )

hmac_sha2_512_tester = executable('hmac_sha2_512_tester',
				  [ 'hmac_sha2_512_tester.c', internal_src ],
				  include_directories: [ include_internal_dirs ],
				  dependencies: leancrypto
				 )

test('HMAC SHA2-256', hmac_sha2_256_tester)
test('HMAC SHA2-512', hmac_sha2_512_tester)
test('HMAC SHA3-224', hmac_tester)
