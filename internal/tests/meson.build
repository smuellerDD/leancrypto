conversion_be_le = executable('conversion_be_le',
			      [ 'conversion_be_le.c', internal_src ],
			      include_directories: [ include_internal_dirs ],
			      dependencies: leancrypto
			      )

test('Conversion LE<->BE', conversion_be_le, suite: regression)

if get_option('drbg_hash').enabled()
	memcmp_secure_test = executable('memcmp_secure_test',
					[ 'memcmp_secure_test.c', internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

	test('memcmp secure', memcmp_secure_test, timeout: 600,
	     suite: regression)
endif

status_tester = executable('status_tester',
			   [ 'status_tester.c', internal_src ],
			   include_directories: [ include_internal_dirs ],
			   dependencies: leancrypto
			  )
test('Status', status_tester, suite: regression)

if get_option('sha3').enabled() and get_option('enable_selftests').enabled()
	rerun_selftests_tester = executable('rerun_selftests_tester',
			   [ 'rerun_selftests_tester.c', internal_src ],
			   include_directories: [ include_internal_dirs ],
			   dependencies: leancrypto
			  )
	test('Rerun selftests', rerun_selftests_tester, suite: regression)
endif
