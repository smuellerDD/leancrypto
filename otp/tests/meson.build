if get_option('hotp').enabled()
	hotp_sha256_tester = executable('hotp_sha256_tester',
					[ 'hotp_sha256_tester.c', internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

	test('HOTP SHA-256', hotp_sha256_tester, suite: regression,
	     should_fail: fips140_negative_expect_fail)
endif
