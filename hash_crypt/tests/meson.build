hash_crypt_tester = executable('hash_crypt_test',
			       [ 'hash_crypt_test.c', internal_src ],
			       include_directories: [ include_internal_dirs ],
			       dependencies: leancrypto
			       )

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
hash_crypt_large_tester = executable('hash_crypt_large_test',
			       [ 'hash_crypt_large_test.c', internal_src ],
			       include_directories: [ include_internal_dirs ],
			       dependencies: leancrypto
			       )

test('Hash Crypt', hash_crypt_tester)
test('KMAC Crypt', kmac_crypt_tester)
test('KMAC Crypt 1GB', kmac_crypt_large_tester, timeout: 300)
test('Hash Crypt 1GB', hash_crypt_large_tester, timeout: 300)
