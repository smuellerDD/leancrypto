conversion_be_le = executable('conversion_be_le',
			      [ 'conversion_be_le.c', internal_src ],
			      include_directories: [ include_internal_dirs ],
			      dependencies: leancrypto
			      )

test('Conversion LE<->BE', conversion_be_le)

if get_option('drbg_hash').enabled()
	memcmp_secure_test = executable('memcmp_secure_test',
					[ 'memcmp_secure_test.c', internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

	test('memcmp secure', memcmp_secure_test, timeout: 600)
endif

status_tester = executable('status_tester',
			   [ 'status_tester.c', internal_src ],
			   include_directories: [ include_internal_dirs ],
			   dependencies: leancrypto
			  )
rerun_selftests_tester = executable('rerun_selftests_tester',
			   [ 'rerun_selftests_tester.c', internal_src ],
			   include_directories: [ include_internal_dirs ],
			   dependencies: leancrypto
			  )
test('Status', status_tester)
test('Rerun selftests', rerun_selftests_tester)
