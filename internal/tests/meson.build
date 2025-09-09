conversion_be_le = executable('conversion_be_le',
			      [ 'conversion_be_le.c', internal_src ],
			      include_directories: [ include_internal_dirs ],
			      dependencies: leancrypto
			      )

test('Conversion LE<->BE', conversion_be_le, suite: regression)

if seeded_rng != 0
	memcmp_secure_test = executable('memcmp_secure_test',
					[ 'memcmp_secure_test.c', internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

	test('memcmp secure', memcmp_secure_test, timeout: 600,
		suite: regression)

	memcpy_secure_test = executable('memcpy_secure_test',
					[ 'memcpy_secure_test.c', internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

	test('memcpy secure', memcpy_secure_test, timeout: 600,
		suite: regression)
endif

status_tester = executable('status_tester',
			   [ 'status_tester.c', internal_src ],
			   include_directories: [ include_internal_dirs ],
			   dependencies: leancrypto
			  )
test('Status', status_tester, suite: regression)

if (get_option('sha3').enabled() and
    get_option('hmac').enabled() and
    get_option('enable_selftests').enabled())
	rerun_selftests_tester = executable('rerun_selftests_tester',
			   [ 'rerun_selftests_tester.c', internal_src ],
			   include_directories: [ include_internal_dirs ],
			   dependencies: leancrypto
			  )
	rerun_one_selftest_tester = executable('rerun_one_selftest_tester',
			   [ 'rerun_one_selftest_tester.c', internal_src ],
			   include_directories: [ include_internal_dirs ],
			   dependencies: leancrypto
			  )
	fips_degraded_mode = executable('fips_degraded_mode',
			   [ 'fips_degraded_mode.c', internal_src ],
			   include_directories: [ include_dirs,
						  include_internal_dirs ],
			   link_with: leancrypto_static_lib_fips
			  )
	test('Rerun selftests', rerun_selftests_tester, suite: regression)
	test('Rerun one selftest', rerun_one_selftest_tester, suite: regression)
	test('FIPS degraded mode', fips_degraded_mode, suite: regression)
endif

if ((get_option('dilithium_87').enabled() or
     get_option('dilithium_65').enabled() or
     get_option('dilithium_44').enabled()) and
    (get_option('sha2-256').enabled() and
     get_option('sha2-512').enabled()))
	tester_kat = executable('tester_kat',
			[ 'tester_kat.c', internal_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			], link_with: leancrypto_lib
			)
endif
