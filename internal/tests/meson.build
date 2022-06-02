conversion_be_le = executable('conversion_be_le',
			      [ 'conversion_be_le.c', internal_src ],
			      include_directories: [ include_internal_dirs ],
			      dependencies: leancrypto
			      )
memcmp_secure_test = executable('memcmp_secure_test',
				[ 'memcmp_secure_test.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)

test('Conversion LE<->BE', conversion_be_le)
test('memcmp secure', memcmp_secure_test, timeout: 300)
